/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>
#include <linux/cryptouser.h>
#include <linux/if_alg.h>
#include <linux/netlink.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>

#include "internal/engine.h"

#define AFALG_REQUIRE_ACCELERATED 0 /* require confirmation of acceleration */
#define AFALG_USE_SOFTWARE        1 /* allow software drivers */
#define AFALG_REJECT_SOFTWARE     2 /* only disallow confirmed software drivers */

#define STR_(S) #S
#define STR(S)  STR_(S)

static int use_softdrivers = AFALG_REJECT_SOFTWARE;

/*
 * cipher/digest status & acceleration definitions
 * Make sure the defaults are set to 0
 */

struct driver_info_st {
    enum afalg_status_t {
        AFALG_STATUS_FAILURE       = -3, /* unusable for other reason */
        AFALG_STATUS_NO_COPY       = -2, /* hash state copy not supported */
        AFALG_STATUS_NO_OPEN       = -1, /* bind call failed */
        AFALG_STATUS_UNKNOWN       =  0, /* not tested yet */
        AFALG_STATUS_USABLE        =  1  /* algo can be used */
    } status;

    enum afalg_accelerated_t {
        AFALG_NOT_ACCELERATED      = -1, /* software implemented */
        AFALG_ACCELERATION_UNKNOWN =  0, /* acceleration support unkown */
        AFALG_ACCELERATED          =  1  /* hardware accelerated */
    } accelerated;

    char *driver_name;
};

static int get_afalg_socket(const char *salg_name, const char *salg_type)
{
    int fd = -1;
    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strncpy((char *)sa.salg_type, salg_type, sizeof(sa.salg_type) - 1);
    strncpy((char *)sa.salg_name, salg_name, sizeof(sa.salg_name) - 1);
    if ((fd = socket(AF_ALG, SOCK_SEQPACKET, 0)) < 0) {
        SYSerr(SYS_F_SOCKET, errno);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
        return fd;

    SYSerr(SYS_F_BIND, errno);
    close(fd);
    return -1;
}

static int afalg_get_driver_name(const char *algo_name, char *driver_name,
                                 size_t driver_len)
{
  int ret = -EFAULT;

  /* NETLINK_CRYPTO specific */
  char buf[CMSG_SPACE(CRYPTO_REPORT_MAXSIZE)];
  struct nlmsghdr *res_n = (struct nlmsghdr *)buf;
  struct {
    struct nlmsghdr n;
    struct crypto_user_alg cru;
  } req;
  struct crypto_user_alg *cru_res = NULL;

  /* AF_NETLINK specific */
  struct sockaddr_nl nl;
  int nlfd =0;
  struct iovec iov;
  struct msghdr msg;

  if (algo_name == NULL || driver_name == NULL || driver_len < 1)
    return -EINVAL;

  memset(&req, 0, sizeof(req));
  memset(&buf, 0, sizeof(buf));
  memset(&msg, 0, sizeof(msg));

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.cru));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.n.nlmsg_type = CRYPTO_MSG_GETALG;
  strncpy(req.cru.cru_name, algo_name, sizeof(req.cru.cru_name) - 1);

  /* open netlink socket */
  nlfd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
  if (nlfd < 0) {
    perror("Netlink error: cannot open netlink socket");
    return -errno;
  }
  memset(&nl, 0, sizeof(nl));
  nl.nl_family = AF_NETLINK;
  if (bind(nlfd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
    perror("Netlink error: cannot bind netlink socket");
    ret = -errno;
    goto out;
  }

  /* sending data */
  memset(&nl, 0, sizeof(nl));
  nl.nl_family = AF_NETLINK;
  iov.iov_base = (void*) &req.n;
  iov.iov_len = req.n.nlmsg_len;
  msg.msg_name = &nl;
  msg.msg_namelen = sizeof(nl);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (sendmsg(nlfd, &msg, 0) < 0) {
    perror("Netlink error: sendmsg failed");
    ret = -errno;
    goto out;
  }

  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  while (1) {
    if ((ret = recvmsg(nlfd, &msg, 0)) <= 0) {
      if (errno == EINTR || errno == EAGAIN)
         continue;
      else if (ret == 0)
        perror("Nelink error: no data");
      else
        perror("Nelink error: netlink receive error");
      ret = -errno;
      goto out;
    }
    if ((u_int32_t)ret > sizeof(buf)) {
      perror("Netlink error: received too much data");
      ret = -errno;
      goto out;
    }
    break;
  }

  ret = -EFAULT;
  if (res_n->nlmsg_type == NLMSG_ERROR) {
    ret = 0;
    goto out;
  }

  if (res_n->nlmsg_type == CRYPTO_MSG_GETALG)
    cru_res = NLMSG_DATA(res_n);
  if (!cru_res || res_n->nlmsg_len < NLMSG_SPACE(sizeof(*cru_res)))
    goto out;

  strncpy(driver_name, cru_res->cru_driver_name, driver_len -1);
  driver_name[driver_len -1] = '\0';
  ret = 1;
out:
  close(nlfd);
  return ret;
}

static enum afalg_accelerated_t
afalg_accelerated(const char *driver_name)
{
    if (driver_name == NULL)
        return AFALG_ACCELERATION_UNKNOWN;

    /* look for known crypto engine names, like cryptodev-linux does */
    if (!strncmp(driver_name, "artpec", 6)
        || !strncmp(driver_name, "atmel-", 6)
        || strstr(driver_name, "-caam")
        || !strncmp(driver_name, "cavium-", 7)
        || strstr(driver_name, "-ccp")
        || strstr(driver_name, "-chcr")
        || strstr(driver_name, "-dcp")
        || strstr(driver_name, "geode")
        || strstr(driver_name, "hifn")
        || !strncmp(driver_name, "img-", 4)
        || strstr(driver_name, "-iproc")
        || strstr(driver_name, "-ixp4xx")
        || !strncmp(driver_name, "mtk-", 4)
        || strstr(driver_name, "-mtk")
        || !strncmp(driver_name, "mv-", 3)
        || strstr(driver_name, "-n2")
        || !strncmp(driver_name, "n5_", 3)
        || strstr(driver_name, "-nx")
        || !strncmp(driver_name, "omap-", 5)
        || strstr(driver_name, "-omap")
        || !strncmp(driver_name, "p8_", 3)
        || strstr(driver_name, "-padlock")
        || strstr(driver_name, "-picoxcell")
        || strstr(driver_name, "-ppc4xx")
        || !strncmp(driver_name, "qat", 3)
        || !strncmp(driver_name, "rk-", 3)
        || strstr(driver_name, "-rk")
        || strstr(driver_name, "-s5p")
        || !strncmp(driver_name, "safexcel-", 9)
        || !strncmp(driver_name, "sahara-", 7)
        || strstr(driver_name, "-scc")
        || !strncmp(driver_name, "stm32-", 6)
        || strstr(driver_name, "-sun4i-ss")
        || strstr(driver_name, "-talitos")
        || strstr(driver_name, "-ux500"))
        return AFALG_ACCELERATED;

    /* these are known asm/software drivers */
    if (strstr(driver_name, "-3way")
        || strstr(driver_name, "-aesni")
        || strstr(driver_name, "-arm")
        || strstr(driver_name, "-asm")
        || strstr(driver_name, "-avx")
        || strstr(driver_name, "-ce")
        || strstr(driver_name, "-fixed-time")
        || strstr(driver_name, "-generic")
        || strstr(driver_name, "-neon")
        || strstr(driver_name, "-ni")
        || !strncmp(driver_name, "octeon-", 7)
        || strstr(driver_name, "-pclmul")
        || strstr(driver_name, "-ppc-spe")
        || strstr(driver_name, "-s390")
        || strstr(driver_name, "-simd")
        || strstr(driver_name, "-sparc64")
        || strstr(driver_name, "-sse2")
        || strstr(driver_name, "-ssse3"))
        return AFALG_NOT_ACCELERATED;

    return AFALG_ACCELERATION_UNKNOWN;
}

/******************************************************************************
 *
 * Ciphers
 *
 * Because they all do the same basic operation, we have only one set of
 * method functions for them all to share, and a mapping table between
 * NIDs and cryptodev IDs, with all the necessary size data.
 *
 *****/

struct cipher_ctx {
    int bfd, sfd;
    unsigned int op, blocksize, num;
    unsigned char partial[EVP_MAX_BLOCK_LENGTH];
};

static const struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    const char *name;
} cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, "cbc(des)" },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, "cbc(des3_ede)" },
#endif
#ifndef OPENSSL_NO_BF
    { NID_bf_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(blowfish)" },
#endif
#ifndef OPENSSL_NO_CAST
    { NID_cast5_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, "cbc(cast5)" },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)" },
#ifndef OPENSSL_NO_RC4
    { NID_rc4, 1, 16, 0, EVP_CIPH_STREAM_CIPHER, "arc4" },
#endif
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)" },
#if 0                            /* Not yet supported */
    { NID_aes_128_xts, 16, 128 / 8 * 2, 16, EVP_CIPH_XTS_MODE, "xts(aes)" },
    { NID_aes_256_xts, 16, 256 / 8 * 2, 16, EVP_CIPH_XTS_MODE, "xts(aes)" },
#endif
    { NID_aes_128_ecb, 16, 128 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
    { NID_aes_192_ecb, 16, 192 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
    { NID_aes_256_ecb, 16, 256 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)" },
#if 0                            /* Not yet supported */
    { NID_aes_128_gcm, 16, 128 / 8, 16, EVP_CIPH_GCM_MODE, "gcm(aes)" },
    { NID_aes_192_gcm, 16, 192 / 8, 16, EVP_CIPH_GCM_MODE, "gcm(aes)" },
    { NID_aes_256_gcm, 16, 256 / 8, 16, EVP_CIPH_GCM_MODE, "gcm(aes)" },
#endif
#ifndef OPENSSL_NO_CAMELLIA
    { NID_camellia_128_cbc, 16, 128 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
    { NID_camellia_192_cbc, 16, 192 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
    { NID_camellia_256_cbc, 16, 256 / 8, 8, EVP_CIPH_CBC_MODE,
      "cbc(camellia)" },
#endif
};

static size_t find_cipher_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        if (nid == cipher_data[i].nid)
            return i;
    return (size_t)-1;
}

static size_t get_cipher_data_index(int nid)
{
    size_t i = find_cipher_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static const struct cipher_data_st *get_cipher_data(int nid)
{
    return &cipher_data[get_cipher_data_index(nid)];
}

/*
 * Following are the three necessary functions to map OpenSSL functionality
 * with cryptodev.
 */

static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    const struct cipher_data_st *cipher_d =
        get_cipher_data(EVP_CIPHER_CTX_nid(ctx));

    cipher_ctx->sfd = -1;
    if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CTR_MODE)
        cipher_ctx->blocksize = cipher_d->blocksize;
    if ((cipher_ctx->bfd = get_afalg_socket(cipher_d->name, "skcipher")) < 0)
        return 0;

    cipher_ctx->op = enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    if ((key == NULL
         || setsockopt(cipher_ctx->bfd, SOL_ALG, ALG_SET_KEY, key,
                       EVP_CIPHER_CTX_key_length(ctx)) >= 0)
        && (cipher_ctx->sfd = accept(cipher_ctx->bfd, NULL, 0)) != -1) {
        return 1;
    }

    close(cipher_ctx->bfd);
    if (cipher_ctx->sfd > -1)
        close(cipher_ctx->sfd);
    cipher_ctx->sfd = -1;
    return 0;
}

static int afalg_do_cipher(struct cipher_ctx *cipher_ctx, unsigned char *out,
                           const unsigned char *in, size_t inl, int enc,
                           const unsigned char *iv, size_t ivlen)
{
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    struct af_alg_iv *aiv;
    struct iovec iov;
    char buf[CMSG_SPACE(sizeof(cipher_ctx->op))
             + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + EVP_MAX_IV_LENGTH)];
    ssize_t nbytes;

    memset(&buf, 0, sizeof(buf));
    msg.msg_control = buf;
    msg.msg_controllen = CMSG_SPACE(sizeof(cipher_ctx->op));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(cipher_ctx->op));
    memcpy(CMSG_DATA(cmsg), &cipher_ctx->op, sizeof(cipher_ctx->op));

    if (ivlen > 0) {
        msg.msg_controllen += CMSG_SPACE(offsetof(struct af_alg_iv, iv) + ivlen);
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
        aiv = (void *)CMSG_DATA(cmsg);
        aiv->ivlen = ivlen;
        memcpy(aiv->iv, iv, ivlen);
    }

    iov.iov_base = (void *)in;
    iov.iov_len = inl;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if ((nbytes = sendmsg(cipher_ctx->sfd, &msg, 0)) < 0) {
        perror ("cipher_do_cipher: sendmsg");
        return -1;
    } else if (nbytes != (ssize_t) inl) {
        fprintf(stderr, "cipher_do_cipher: sent %zd bytes != inlen %zd\n",
                nbytes, inl);
        return -1;
    }
    if ((nbytes = read(cipher_ctx->sfd, out, inl)) != (ssize_t) inl) {
        fprintf(stderr, "cipher_do_cipher: read %zd bytes != inlen %zd\n",
                nbytes, inl);
        return -1;
    }

    return nbytes;
}

static int cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    size_t ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned char saved_iv[EVP_MAX_IV_LENGTH];
    int outl;

    assert(inl >= ivlen);
    if (!enc)
        memcpy(saved_iv, in + inl - ivlen, ivlen);
    if ((outl = afalg_do_cipher(cipher_ctx, out, in, inl, enc, iv, ivlen)) < 1)
        return outl;
    memcpy(iv, enc ? out + inl - ivlen : saved_iv, ivlen);

    return outl;
}

static void ctr_updateiv(unsigned char* iv, size_t ivlen, size_t nblocks)
{
    do {
        ivlen--;
        nblocks += iv[ivlen];
        iv[ivlen] = (uint8_t) nblocks;
        nblocks >>= 8;
    } while (ivlen);
}

static int ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    size_t ivlen = EVP_CIPHER_CTX_iv_length(ctx), nblocks, len;
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);

    /* handle initial partial block */
    while (cipher_ctx->num && inl) {
        (*out++) = *(in++) ^ cipher_ctx->partial[cipher_ctx->num];
        --inl;
        cipher_ctx->num = (cipher_ctx->num + 1) % cipher_ctx->blocksize;
    }

    /* process full blocks */
    if (inl > (unsigned int) cipher_ctx->blocksize) {
      nblocks = inl/cipher_ctx->blocksize;
      len = nblocks * cipher_ctx->blocksize;
      if (afalg_do_cipher(cipher_ctx, out, in, len, enc, iv, ivlen) < 1)
          return 0;
      ctr_updateiv(iv, ivlen, nblocks);
      inl -= len;
      out += len;
      in += len;
    }

    /* process final partial block */
    if (inl) {
        memset(cipher_ctx->partial, 0, cipher_ctx->blocksize);
        if (afalg_do_cipher(cipher_ctx, cipher_ctx->partial,
                            cipher_ctx->partial, cipher_ctx->blocksize, enc,
			    iv, ivlen) < 1)
            return 0;
        ctr_updateiv(iv, ivlen, 1);
        while (inl--) {
            out[cipher_ctx->num] = in[cipher_ctx->num]
                ^ cipher_ctx->partial[cipher_ctx->num];
	    cipher_ctx->num++;
	}
    }

    return 1;
}

static int ecb_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int enc = EVP_CIPHER_CTX_encrypting(ctx);

    return afalg_do_cipher(cipher_ctx, out, in, inl, enc, NULL, 0);
}

static int cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void* p2)
{
    struct cipher_ctx *to, *from;

    if (type != EVP_CTRL_COPY)
        return -1;

    from = (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    to = (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(
            (EVP_CIPHER_CTX *)p2);

    to->sfd = -1;
    if ((to->sfd = accept(from->sfd, NULL, 0)) != -1)
        return 1;

    SYSerr(SYS_F_ACCEPT, errno);
    to->sfd = -1;

    return 0;
}

static int cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret = 1;

    if (cipher_ctx == NULL)
        return 1;

    if (cipher_ctx->sfd >= 0 && close(cipher_ctx->sfd) != 0) {
        SYSerr(SYS_F_CLOSE, errno);
        ret = 0;
    }
    if (cipher_ctx->bfd >= 0 && close(cipher_ctx->bfd) != 0) {
        SYSerr(SYS_F_CLOSE, errno);
        ret = 0;
    }

    cipher_ctx->bfd = cipher_ctx->sfd = -1;
    return ret;
}

/*
 * Keep tables of known nids, associated methods, selected ciphers, and driver
 * info.
 * Note that known_cipher_nids[] isn't necessarily indexed the same way as
 * cipher_data[] above, which the other tables are.
 */
static int known_cipher_nids[OSSL_NELEM(cipher_data)];
static int known_cipher_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_CIPHER *known_cipher_methods[OSSL_NELEM(cipher_data)] = { NULL, };
static int selected_ciphers[OSSL_NELEM(cipher_data)];
static struct driver_info_st cipher_driver_info[OSSL_NELEM(cipher_data)];


static int afalg_test_cipher(size_t cipher_data_index)
{
    return (cipher_driver_info[cipher_data_index].status == AFALG_STATUS_USABLE
            && selected_ciphers[cipher_data_index] == 1
            && (cipher_driver_info[cipher_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (cipher_driver_info[cipher_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void prepare_cipher_methods(void)
{
    size_t i;
    int fd, blocksize;
    int (*do_cipher) (EVP_CIPHER_CTX *, unsigned char *, const unsigned char *,
                      size_t);

    for (i = 0, known_cipher_nids_amount = 0;
         i < OSSL_NELEM(cipher_data); i++) {

        selected_ciphers[i] = 1;
        /*
         * Check that the cipher is usable
         */
        if ((fd = get_afalg_socket(cipher_data[i].name, "skcipher")) < 0) {
            cipher_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* gather hardware driver information */
        cipher_driver_info[i].driver_name = OPENSSL_zalloc(CRYPTO_MAX_NAME);
        if (cipher_driver_info[i].driver_name != NULL
            && afalg_get_driver_name(cipher_data[i].name,
                                     cipher_driver_info[i].driver_name,
                                     CRYPTO_MAX_NAME) > 0)
            cipher_driver_info[i].accelerated =
                afalg_accelerated(cipher_driver_info[i].driver_name);

        blocksize = cipher_data[i].blocksize;
        switch (cipher_data[i].flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CBC_MODE:
            do_cipher = cbc_do_cipher;
            break;
        case EVP_CIPH_CTR_MODE:
            do_cipher = ctr_do_cipher;
            blocksize = 1;
            break;
        case EVP_CIPH_ECB_MODE:
            do_cipher = ecb_do_cipher;
            break;
        default:
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            known_cipher_methods[i] = NULL;
            continue;
        }

        if ((known_cipher_methods[i] =
                 EVP_CIPHER_meth_new(cipher_data[i].nid, blocksize,
                                     cipher_data[i].keylen)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(known_cipher_methods[i],
                                              cipher_data[i].ivlen)
            || !EVP_CIPHER_meth_set_flags(known_cipher_methods[i],
                                          cipher_data[i].flags
                                          | EVP_CIPH_CUSTOM_COPY
                                          | EVP_CIPH_FLAG_DEFAULT_ASN1)
            || !EVP_CIPHER_meth_set_init(known_cipher_methods[i], cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(known_cipher_methods[i], do_cipher)
            || !EVP_CIPHER_meth_set_ctrl(known_cipher_methods[i], cipher_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(known_cipher_methods[i],
                                            cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(known_cipher_methods[i],
                                                  sizeof(struct cipher_ctx))) {
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_CIPHER_meth_free(known_cipher_methods[i]);
            known_cipher_methods[i] = NULL;
        } else {
            cipher_driver_info[i].status = AFALG_STATUS_USABLE;
            if (afalg_test_cipher(i))
                known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
        }
    }
}

static void rebuild_known_cipher_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_cipher_nids_amount = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (afalg_test_cipher(i))
            known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
    }
    ENGINE_unregister_ciphers(e);
    ENGINE_register_ciphers(e);
}

static const EVP_CIPHER *get_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_cipher_methods[i];
}

static int get_cipher_nids(const int **nids)
{
    *nids = known_cipher_nids;
    return known_cipher_nids_amount;
}

static void destroy_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    EVP_CIPHER_meth_free(known_cipher_methods[i]);
    known_cipher_methods[i] = NULL;
}

static void destroy_all_cipher_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        destroy_cipher_method(cipher_data[i].nid);
        OPENSSL_free(cipher_driver_info[i].driver_name);
        cipher_driver_info[i].driver_name = NULL;
    }
}

static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                             const int **nids, int nid)
{
    if (cipher == NULL)
        return get_cipher_nids(nids);

    *cipher = get_cipher_method(nid);

    return *cipher != NULL;
}

static void afalg_select_all_ciphers(int *cipher_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        cipher_list[i] = 1;
}

static int afalg_select_cipher_cb(const char *str, int len, void *usr)
{
    int *cipher_list = (int *)usr;
    char *name;
    const EVP_CIPHER *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    EVP = EVP_get_cipherbyname(name);
    if (EVP == NULL)
        fprintf(stderr, "afalg: unknown cipher %s\n", name);
    else if ((i = find_cipher_data_index(EVP_CIPHER_nid(EVP))) != (size_t)-1)
        cipher_list[i] = 1;
    else
        fprintf(stderr, "afalg: cipher %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_cipher_info(void)
{
    size_t i;
    const char *evp_name;

    fprintf (stderr, "Information about ciphers supported by the AF_ALG"
             " engine:\n");
    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        evp_name = OBJ_nid2sn(cipher_data[i].nid);
        fprintf (stderr, "Cipher %s, NID=%d, AF_ALG info: name=%s, ",
                 evp_name ? evp_name : "unknown", cipher_data[i].nid,
                 cipher_data[i].name);
        if (cipher_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, "AF_ALG socket bind failed.\n");
            continue;
        }
        fprintf(stderr, " driver=%s ", cipher_driver_info[i].driver_name ?
                 cipher_driver_info[i].driver_name : "unknown");
        if (cipher_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, "(hw accelerated)");
        else if (cipher_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, "(software)");
        else
            fprintf(stderr, "(acceleration status unknown)");
        if (cipher_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed.");
        fprintf (stderr, "\n");
    }
    fprintf(stderr, "\n");
}

/******************************************************************************
 *
 * Digests
 *
 * Because they all do the same basic operation, we have only one set of
 * method functions for them all to share, and a mapping table between
 * NIDs and AF_ALG names, with all the necessary size data.
 *
 *****/

struct digest_ctx {
    /* This signals that the init function was called, not that it succeeded. */
    int init_called;
    int bfd, sfd;
};

static const struct digest_data_st {
    int nid;
    int digestlen;
    char *name;
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, 16, "md5" },
#endif
    { NID_sha1, 20, "sha1" },
#ifndef OPENSSL_NO_RMD160
    { NID_ripemd160, 20, "rmd160" },
#endif
    { NID_sha224, 224 / 8, "sha224" },
    { NID_sha256, 256 / 8, "sha256" },
    { NID_sha384, 384 / 8, "sha384" },
    { NID_sha512, 512 / 8, "sha512" },
};

static size_t find_digest_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        if (nid == digest_data[i].nid)
            return i;
    return (size_t)-1;
}

static size_t get_digest_data_index(int nid)
{
    size_t i = find_digest_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static const struct digest_data_st *get_digest_data(int nid)
{
    return &digest_data[get_digest_data_index(nid)];
}

/*
 * Following are the five necessary functions to map OpenSSL functionality
 * with cryptodev: init, update, final, cleanup, and copy.
 */

static int digest_init(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    const struct digest_data_st *digest_d =
        get_digest_data(EVP_MD_CTX_type(ctx));

    digest_ctx->init_called = 1;

    digest_ctx->sfd = -1;
    if ((digest_ctx->bfd =
        get_afalg_socket(digest_d->name, "hash")) < 0)
        return 0;
    if ((digest_ctx->sfd = accept(digest_ctx->bfd, NULL, 0)) >= 0)
        return 1;
    close(digest_ctx->bfd);
    digest_ctx->bfd = -1;
    return 0;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int flags = 0;

    if (count == 0)
        return 1;

    if (digest_ctx == NULL)
        return 0;

    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT))
        flags = MSG_MORE;

    if (send(digest_ctx->sfd, data, count, flags) == (ssize_t)count)
        return 1;

    return 0;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int len = EVP_MD_CTX_size(ctx);

    if (md == NULL || digest_ctx == NULL)
        return 0;

    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT) &&
        (send(digest_ctx->sfd, NULL, 0, 0) < 0))
        return 0;
    if (recv(digest_ctx->sfd, md, len, 0) != len)
        return 0;

    return 1;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);

    if (digest_from == NULL || digest_from->init_called != 1)
        return 1;

    digest_to->sfd = digest_to->bfd = -1;
    if((digest_to->bfd = accept(digest_from->bfd, NULL, 0)) != -1
       && (digest_to->sfd = accept(digest_from->sfd, NULL, 0)) != -1)
        return 1;

    SYSerr(SYS_F_ACCEPT, errno);
    if (digest_to->bfd != -1)
        close(digest_to->bfd);
    digest_to->sfd = digest_to->bfd = -1;
    return 0;
}

static int digest_cleanup(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int ret=1;

    if (digest_ctx == NULL || digest_ctx->init_called != 1)
        return 1;

    if (digest_ctx->bfd >= 0 && close(digest_ctx->bfd) != 0) {
        ret = 0;
    }

    if (digest_ctx->sfd >= 0 && close(digest_ctx->sfd) != 0) {
        ret = 0;
    }

    return ret;
}

/*
 * Keep tables of known nids, associated methods, selected digests, and
 * driver info.
 * Note that known_digest_nids[] isn't necessarily indexed the same way as
 * digest_data[] above, which the other tables are.
 */
static int known_digest_nids[OSSL_NELEM(digest_data)];
static int known_digest_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_MD *known_digest_methods[OSSL_NELEM(digest_data)] = { NULL, };
static int selected_digests[OSSL_NELEM(digest_data)];
static struct driver_info_st digest_driver_info[OSSL_NELEM(digest_data)];

static int afalg_test_digest(size_t digest_data_index)
{
    return (digest_driver_info[digest_data_index].status == AFALG_STATUS_USABLE
            && selected_digests[digest_data_index] == 1
            && (digest_driver_info[digest_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (digest_driver_info[digest_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void rebuild_known_digest_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data); i++) {
        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
    ENGINE_unregister_digests(e);
    ENGINE_register_digests(e);
}

static void prepare_digest_methods(void)
{
    size_t i;
    int fd;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data);
         i++) {

        selected_digests[i] = 1;
        /*
         * Check that the digest is usable
         */
        if ((fd = get_afalg_socket(digest_data[i].name, "hash")) < 0) {
            digest_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* gather hardware driver information */
        digest_driver_info[i].driver_name = OPENSSL_zalloc(CRYPTO_MAX_NAME);
        if (digest_driver_info[i].driver_name != NULL
            && afalg_get_driver_name(digest_data[i].name,
                                     digest_driver_info[i].driver_name,
                                     CRYPTO_MAX_NAME) > 0)
            digest_driver_info[i].accelerated =
                afalg_accelerated(digest_driver_info[i].driver_name);

        if ((known_digest_methods[i] = EVP_MD_meth_new(digest_data[i].nid,
                                                       NID_undef)) == NULL
            || !EVP_MD_meth_set_result_size(known_digest_methods[i],
                                            digest_data[i].digestlen)
            || !EVP_MD_meth_set_init(known_digest_methods[i], digest_init)
            || !EVP_MD_meth_set_update(known_digest_methods[i], digest_update)
            || !EVP_MD_meth_set_final(known_digest_methods[i], digest_final)
            || !EVP_MD_meth_set_copy(known_digest_methods[i], digest_copy)
            || !EVP_MD_meth_set_cleanup(known_digest_methods[i], digest_cleanup)
            || !EVP_MD_meth_set_app_datasize(known_digest_methods[i],
                                             sizeof(struct digest_ctx))) {
            digest_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_MD_meth_free(known_digest_methods[i]);
            known_digest_methods[i] = NULL;
        } else {
            digest_driver_info[i].status = AFALG_STATUS_USABLE;
        }
        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
}

static const EVP_MD *get_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_digest_methods[i];
}

static void destroy_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    EVP_MD_meth_free(known_digest_methods[i]);
    known_digest_methods[i] = NULL;
}

static void destroy_all_digest_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        destroy_digest_method(digest_data[i].nid);
        OPENSSL_free(digest_driver_info[i].driver_name);
        digest_driver_info[i].driver_name = NULL;
    }
}

static int afalg_digests(ENGINE *e, const EVP_MD **digest,
                             const int **nids, int nid)
{
    if (digest == NULL) {
        *nids = known_digest_nids;
        return known_digest_nids_amount;
    }
    *digest = get_digest_method(nid);

    return *digest != NULL;
}

static void afalg_select_all_digests(int *digest_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        digest_list[i] = 1;
}

static int afalg_select_digest_cb(const char *str, int len, void *usr)
{
    int *digest_list = (int *)usr;
    char *name;
    const EVP_MD *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    EVP = EVP_get_digestbyname(name);
    if (EVP == NULL)
        fprintf(stderr, "afalg: unknown digest %s\n", name);
    else if ((i = find_digest_data_index(EVP_MD_type(EVP))) != (size_t)-1)
        digest_list[i] = 1;
    else
        fprintf(stderr, "afalg: digest %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_digest_info(void)
{
    size_t i;
    const char *evp_name;

    fprintf (stderr, "Information about digests supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        evp_name = OBJ_nid2sn(digest_data[i].nid);
        fprintf (stderr, "Digest %s, NID=%d, AF_ALG info: name=%s, ",
                 evp_name ? evp_name : "unknown", digest_data[i].nid,
                 digest_data[i].name);
        if (digest_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, "AF_ALG socket bind failed.\n");
            continue;
        }
        fprintf(stderr, " driver=%s ", digest_driver_info[i].driver_name ?
                 digest_driver_info[i].driver_name : "unknown");
        if (digest_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, "(hw accelerated)");
        else if (digest_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            fprintf(stderr, "(software)");
        else
            fprintf(stderr, "(acceleration status unknown)");
        if (digest_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Digest setup failed.");
        fprintf (stderr, "\n");
    }
}

/******************************************************************************
 *
 * CONTROL COMMANDS
 *
 *****/

#define AFALG_CMD_USE_SOFTDRIVERS  ENGINE_CMD_BASE
#define AFALG_CMD_CIPHERS         (ENGINE_CMD_BASE + 1)
#define AFALG_CMD_DIGESTS         (ENGINE_CMD_BASE + 2)
#define AFALG_CMD_DUMP_INFO       (ENGINE_CMD_BASE + 3)

static const ENGINE_CMD_DEFN afalg_cmds[] = {
    {AFALG_CMD_USE_SOFTDRIVERS,
    "USE_SOFTDRIVERS",
    "specifies whether to use software (not accelerated) drivers (" STR(AFALG_REQUIRE_ACCELERATED)
        "=use only accelerated drivers, " STR(AFALG_USE_SOFTWARE) "=allow all drivers, "
        STR(AFALG_REJECT_SOFTWARE) "=use if acceleration can't be determined [default=2])",
    ENGINE_CMD_FLAG_NUMERIC},

    {AFALG_CMD_CIPHERS,
     "CIPHERS",
     "either ALL, NONE, or a comma-separated list of ciphers to enable [default=ALL]",
     ENGINE_CMD_FLAG_STRING},

   {AFALG_CMD_DIGESTS,
     "DIGESTS",
     "either ALL, NONE, or a comma-separated list of digests to enable [default=ALL]",
     ENGINE_CMD_FLAG_STRING},

   {AFALG_CMD_DUMP_INFO,
     "DUMP_INFO",
     "dump info about each algorithm to stderr; use 'openssl engine -pre DUMP_INFO afalg'",
     ENGINE_CMD_FLAG_NO_INPUT},

    {0, NULL, NULL, 0}
};

static int afalg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int *new_list;

    switch(cmd) {
    case AFALG_CMD_USE_SOFTDRIVERS:
        switch(i) {
        case AFALG_REQUIRE_ACCELERATED:
        case AFALG_USE_SOFTWARE:
        case AFALG_REJECT_SOFTWARE:
            break;
        default:
            fprintf(stderr, "devcrypto: invalid value (%ld) for USE_SOFTDRIVERS\n", i);
            return 0;
        }
        if (use_softdrivers == i)
            return 1;
        use_softdrivers = i;
        rebuild_known_digest_nids(e);
        rebuild_known_cipher_nids(e);
        return 1;

    case AFALG_CMD_CIPHERS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_ciphers(selected_ciphers);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_ciphers, 0, sizeof(selected_ciphers));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_ciphers));
            if (!CONF_parse_list(p, ',', 1, afalg_select_cipher_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_ciphers, new_list, sizeof(selected_ciphers));
            OPENSSL_free(new_list);
        }
        rebuild_known_cipher_nids(e);
        return 1;

    case AFALG_CMD_DIGESTS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_digests(selected_digests);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_digests, 0, sizeof(selected_digests));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_digests));
            if (!CONF_parse_list(p, ',', 1, afalg_select_digest_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_digests, new_list, sizeof(selected_digests));
            OPENSSL_free(new_list);
        }
        rebuild_known_digest_nids(e);
        return 1;

    case AFALG_CMD_DUMP_INFO:
        dump_cipher_info();
        dump_digest_info();
        return 1;

    default:
        break;
    }
    return 0;
}

/******************************************************************************
 *
 * LOAD / UNLOAD
 *
 *****/

static int afalg_unload(ENGINE *e)
{
    destroy_all_cipher_methods();
    destroy_all_digest_methods();

    return 1;
}


/*
 * This engine is always built into libcrypto, so it doesn't offer any
 * ability to be dynamically loadable.
 */
void engine_load_devcrypto_int()
{
    ENGINE *e = NULL;
    int sock;

    /* Test if we can actually create an AF_ALG socket */
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        fprintf(stderr, "Could not create AF_ALG socket: %s\n", strerror(errno));
        return;
    }
    close(sock);

    if ((e = ENGINE_new()) == NULL
        || !ENGINE_set_destroy_function(e, afalg_unload)) {
        ENGINE_free(e);
        return;
    }

    prepare_cipher_methods();
    prepare_digest_methods();

    if (!ENGINE_set_id(e, "devcrypto")
        || !ENGINE_set_name(e, "AF_ALG engine")
        || !ENGINE_set_cmd_defns(e, afalg_cmds)
        || !ENGINE_set_ctrl_function(e, afalg_ctrl)

/*
 * Asymmetric ciphers aren't well supported with /dev/crypto.  Among the BSD
 * implementations, it seems to only exist in FreeBSD, and regarding the
 * parameters in its crypt_kop, the manual crypto(4) has this to say:
 *
 *    The semantics of these arguments are currently undocumented.
 *
 * Reading through the FreeBSD source code doesn't give much more than
 * their CRK_MOD_EXP implementation for ubsec.
 *
 * It doesn't look much better with cryptodev-linux.  They have the crypt_kop
 * structure as well as the command (CRK_*) in cryptodev.h, but no support
 * seems to be implemented at all for the moment.
 *
 * At the time of writing, it seems impossible to write proper support for
 * FreeBSD's asym features without some very deep knowledge and access to
 * specific kernel modules.
 *
 * /Richard Levitte, 2017-05-11
 */
#if 0
# ifndef OPENSSL_NO_RSA
        || !ENGINE_set_RSA(e, afalg_rsa)
# endif
# ifndef OPENSSL_NO_DSA
        || !ENGINE_set_DSA(e, afalg_dsa)
# endif
# ifndef OPENSSL_NO_DH
        || !ENGINE_set_DH(e, afalg_dh)
# endif
# ifndef OPENSSL_NO_EC
        || !ENGINE_set_EC(e, afalg_ec)
# endif
#endif
        || !ENGINE_set_ciphers(e, afalg_ciphers)
        || !ENGINE_set_digests(e, afalg_digests)
        ) {
        ENGINE_free(e);
        return;
    }

    ENGINE_add(e);
    ENGINE_free(e);          /* Loose our local reference */
    ERR_clear_error();
}
