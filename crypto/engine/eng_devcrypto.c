/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <crypto/cryptodev.h>

#include "internal/engine.h"

#ifdef CRYPTO_ALGORITHM_MIN
# define CHECK_BSD_STYLE_MACROS
#endif

#define engine_devcrypto_id "devcrypto"

/*
 * ONE global file descriptor for all sessions.  This allows operations
 * such as digest session data copying (see digest_copy()), but is also
 * saner...  why re-open /dev/crypto for every session?
 */
static int cfd = -1;
#define DEVCRYPTO_REQUIRE_ACCELERATED 0 /* require confirmation of acceleration */
#define DEVCRYPTO_USE_SOFTWARE        1 /* allow software drivers */
#define DEVCRYPTO_REJECT_SOFTWARE     2  /* only disallow confirmed software drivers */

#define STR_(S) #S
#define STR(S)  STR_(S)

static int use_softdrivers = DEVCRYPTO_REJECT_SOFTWARE;

/*
 * cipher/digest status & acceleration definitions
 * Make sure the defaults are set to 0
 */
struct driver_info_st {
    enum devcrypto_status_t {
        DEVCRYPTO_STATUS_FAILURE         = -3, /* unusable for other reason */
        DEVCRYPTO_STATUS_NO_CIOCCPHASH   = -2, /* hash state copy not supported */
        DEVCRYPTO_STATUS_NO_CIOCGSESSION = -1, /* session open failed */
        DEVCRYPTO_STATUS_UNKNOWN         =  0, /* not tested yet */
        DEVCRYPTO_STATUS_USABLE          =  1  /* algo can be used */
    } status;

    enum devcrypto_accelerated_t {
        DEVCRYPTO_NOT_ACCELERATED        = -1, /* software implemented */
        DEVCRYPTO_ACCELERATION_UNKNOWN   =  0, /* acceleration support unkown */
        DEVCRYPTO_ACCELERATED            =  1  /* hardware accelerated */
    } accelerated;

    char *driver_name;
};

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
    struct session_op sess;

    /* to pass from init to do_cipher */
    const unsigned char *iv;
    int op;                      /* COP_ENCRYPT or COP_DECRYPT */
};

static const struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    int devcryptoid;
} cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, CRYPTO_DES_CBC },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, CRYPTO_3DES_CBC },
#endif
#ifndef OPENSSL_NO_BF
    { NID_bf_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, CRYPTO_BLF_CBC },
#endif
#ifndef OPENSSL_NO_CAST
    { NID_cast5_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, CRYPTO_CAST_CBC },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
#ifndef OPENSSL_NO_RC4
    { NID_rc4, 1, 16, 0, EVP_CIPH_STREAM_CIPHER, CRYPTO_ARC4 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_AES_CTR)
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
#endif
#if 0                            /* Not yet supported */
    { NID_aes_128_xts, 16, 128 / 8 * 2, 16, EVP_CIPH_XTS_MODE, CRYPTO_AES_XTS },
    { NID_aes_256_xts, 16, 256 / 8 * 2, 16, EVP_CIPH_XTS_MODE, CRYPTO_AES_XTS },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_AES_ECB)
    { NID_aes_128_ecb, 16, 128 / 8, 16, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
    { NID_aes_192_ecb, 16, 192 / 8, 16, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
    { NID_aes_256_ecb, 16, 256 / 8, 16, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
#endif
#if 0                            /* Not yet supported */
    { NID_aes_128_gcm, 16, 128 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
    { NID_aes_192_gcm, 16, 192 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
    { NID_aes_256_gcm, 16, 256 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
#endif
#ifndef OPENSSL_NO_CAMELLIA
    { NID_camellia_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
    { NID_camellia_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
    { NID_camellia_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
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

    memset(&cipher_ctx->sess, 0, sizeof(cipher_ctx->sess));
    cipher_ctx->sess.cipher = cipher_d->devcryptoid;
    cipher_ctx->sess.keylen = cipher_d->keylen;
    cipher_ctx->sess.key = (void *)key;
    cipher_ctx->op = enc ? COP_ENCRYPT : COP_DECRYPT;
    if (ioctl(cfd, CIOCGSESSION, &cipher_ctx->sess) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct crypt_op cryp;
#if !defined(COP_FLAG_WRITE_IV)
    unsigned char saved_iv[EVP_MAX_IV_LENGTH];
#endif

    memset(&cryp, 0, sizeof(cryp));
    cryp.ses = cipher_ctx->sess.ses;
    cryp.len = inl;
    cryp.src = (void *)in;
    cryp.dst = (void *)out;
    cryp.iv = (void *)EVP_CIPHER_CTX_iv_noconst(ctx);
    cryp.op = cipher_ctx->op;
#if !defined(COP_FLAG_WRITE_IV)
    cryp.flags = 0;

    if (EVP_CIPHER_CTX_iv_length(ctx) > 0) {
        assert(inl >= EVP_CIPHER_CTX_iv_length(ctx));
        if (!EVP_CIPHER_CTX_encrypting(ctx)) {
            unsigned char *ivptr = in + inl - EVP_CIPHER_CTX_iv_length(ctx);

            memcpy(saved_iv, ivptr, EVP_CIPHER_CTX_iv_length(ctx));
        }
    }
#else
    cryp.flags = COP_FLAG_WRITE_IV;
#endif

    if (ioctl(cfd, CIOCCRYPT, &cryp) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

#if !defined(COP_FLAG_WRITE_IV)
    if (EVP_CIPHER_CTX_iv_length(ctx) > 0) {
        unsigned char *ivptr = saved_iv;

        assert(inl >= EVP_CIPHER_CTX_iv_length(ctx));
        if (!EVP_CIPHER_CTX_encrypting(ctx))
            ivptr = out + inl - EVP_CIPHER_CTX_iv_length(ctx);

        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), ivptr,
               EVP_CIPHER_CTX_iv_length(ctx));
    }
#endif

    return 1;
}

static int cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void* p2)
{
    EVP_CIPHER_CTX *to_ctx = (EVP_CIPHER_CTX *)p2;
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
# ifdef HAVE_SYSLOG_R
    struct syslog_data sd = SYSLOG_DATA_INIT;
# endif

# ifdef HAVE_SYSLOG_R
    syslog_r(LOG_ERR, &sd, "cipher_ctrl: CTX=%08lx, type=%d, p1=%d, p2=%08lx, "
             "cipher_ctx=%08lx", (long)ctx, type, p1, (long)p2, (long)cipher_ctx);
# else
    syslog(LOG_ERR, "cipher_ctrl: CTX=%08lx, type=%d, p1=%d, p2=%08lx, "
           "cipher_ctx=%08lx", (long)ctx, type, p1, (long)p2, (long)cipher_ctx);
# endif
    if (type == EVP_CTRL_COPY) {
        /* when copying the context, a new session needs to be initialized */
        return (cipher_ctx == NULL)
            || cipher_init(to_ctx, cipher_ctx->sess.key, EVP_CIPHER_CTX_iv(ctx),
                           (cipher_ctx->op == COP_ENCRYPT));
    }

    return -1;
}

static int cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (ioctl(cfd, CIOCFSESSION, &cipher_ctx->sess.ses) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
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


static int devcrypto_test_cipher(size_t cipher_data_index)
{
    return (cipher_driver_info[cipher_data_index].status == DEVCRYPTO_STATUS_USABLE
            && selected_ciphers[cipher_data_index] == 1
            && (cipher_driver_info[cipher_data_index].accelerated
                    == DEVCRYPTO_ACCELERATED
                || use_softdrivers == DEVCRYPTO_USE_SOFTWARE
                || (cipher_driver_info[cipher_data_index].accelerated
                        != DEVCRYPTO_NOT_ACCELERATED
                    && use_softdrivers == DEVCRYPTO_REJECT_SOFTWARE)));
}

static void prepare_cipher_methods(void)
{
    size_t i;
    struct session_op sess;
#ifdef CIOCGSESSINFO
    struct session_info_op siop;
#endif

    memset(&cipher_driver_info, 0, sizeof(cipher_driver_info));

    memset(&sess, 0, sizeof(sess));
    sess.key = (void *)"01234567890123456789012345678901234567890123456789";

    for (i = 0, known_cipher_nids_amount = 0;
         i < OSSL_NELEM(cipher_data); i++) {

        selected_ciphers[i] = 1;
        /*
         * Check that the cipher is usable
         */
        sess.cipher = cipher_data[i].devcryptoid;
        sess.keylen = cipher_data[i].keylen;
        if (ioctl(cfd, CIOCGSESSION, &sess) < 0) {
            cipher_driver_info[i].status = DEVCRYPTO_STATUS_NO_CIOCGSESSION;
            continue;
        }

        if ((known_cipher_methods[i] =
                 EVP_CIPHER_meth_new(cipher_data[i].nid,
                                     cipher_data[i].blocksize,
                                     cipher_data[i].keylen)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(known_cipher_methods[i],
                                              cipher_data[i].ivlen)
            || !EVP_CIPHER_meth_set_flags(known_cipher_methods[i],
                                          cipher_data[i].flags
                                          | EVP_CIPH_CUSTOM_COPY
                                          | EVP_CIPH_FLAG_DEFAULT_ASN1)
            || !EVP_CIPHER_meth_set_init(known_cipher_methods[i], cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(known_cipher_methods[i],
                                              cipher_do_cipher)
            || !EVP_CIPHER_meth_set_ctrl(known_cipher_methods[i], cipher_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(known_cipher_methods[i],
                                            cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(known_cipher_methods[i],
                                                  sizeof(struct cipher_ctx))) {
            cipher_driver_info[i].status = DEVCRYPTO_STATUS_FAILURE;
            EVP_CIPHER_meth_free(known_cipher_methods[i]);
            known_cipher_methods[i] = NULL;
        } else {
            cipher_driver_info[i].status = DEVCRYPTO_STATUS_USABLE;
#ifdef CIOCGSESSINFO
            siop.ses = sess.ses;
            if (ioctl(cfd, CIOCGSESSINFO, &siop) < 0) {
                cipher_driver_info[i].accelerated = DEVCRYPTO_ACCELERATION_UNKNOWN;
            } else {
                cipher_driver_info[i].driver_name =
                    OPENSSL_strndup(siop.cipher_info.cra_driver_name,
                                    CRYPTODEV_MAX_ALG_NAME);
                if (!(siop.flags & SIOP_FLAG_KERNEL_DRIVER_ONLY))
                    cipher_driver_info[i].accelerated = DEVCRYPTO_NOT_ACCELERATED;
                else
                    cipher_driver_info[i].accelerated = DEVCRYPTO_ACCELERATED;
            }
#endif /* CIOCGSESSINFO */
        }
        ioctl(cfd, CIOCFSESSION, &sess.ses);
        if (devcrypto_test_cipher(i)) {
            known_cipher_nids[known_cipher_nids_amount++] =
                cipher_data[i].nid;
        }
    }
}

static void rebuild_known_cipher_nids(void)
{
    size_t i;

    for (i = 0, known_cipher_nids_amount = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (devcrypto_test_cipher(i))
            known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
    }
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

static int devcrypto_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                             const int **nids, int nid)
{
    if (cipher == NULL)
        return get_cipher_nids(nids);

    *cipher = get_cipher_method(nid);

    return *cipher != NULL;
}

static void devcrypto_select_all_ciphers(int *cipher_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        cipher_list[i] = 1;
}

static int cryptodev_select_cipher_cb(const char *str, int len, void *usr)
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
        fprintf(stderr, "devcrypto: unknown cipher %s\n", name);
    else if ((i = find_cipher_data_index(EVP_CIPHER_nid(EVP))) != (size_t)-1)
        cipher_list[i] = 1;
    else
        fprintf(stderr, "devcrypto: cipher %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_cipher_info(void)
{
    size_t i;
    const char *name;

    fprintf (stderr, "Information about ciphers supported by the /dev/crypto"
             " engine:\n");
#ifndef CIOCGSESSINFO
    fprintf(stderr, "CIOCGSESSINFO (session info call) unavailable\n");
#endif
    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        name = OBJ_nid2sn(cipher_data[i].nid);
        fprintf (stderr, "Cipher %s, NID=%d, /dev/crypto info: id=%d, ",
                 name ? name : "unknown", cipher_data[i].nid,
                 cipher_data[i].devcryptoid);
        if (cipher_driver_info[i].status == DEVCRYPTO_STATUS_NO_CIOCGSESSION ) {
            fprintf (stderr, "CIOCGSESSION (session open call) failed\n");
            continue;
        }
        fprintf (stderr, "driver=%s ", cipher_driver_info[i].driver_name ?
                 cipher_driver_info[i].driver_name : "unknown");
        if (cipher_driver_info[i].accelerated == DEVCRYPTO_ACCELERATED)
            fprintf(stderr, "(hw accelerated)");
        else if (cipher_driver_info[i].accelerated == DEVCRYPTO_NOT_ACCELERATED)
            fprintf(stderr, "(software)");
        else
            fprintf(stderr, "(acceleration status unknown)");
        if (cipher_driver_info[i].status == DEVCRYPTO_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed");
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

/*
 * We only support digests if the cryptodev implementation supports multiple
 * data updates and session copying.  Otherwise, we would be forced to maintain
 * a cache, which is perilous if there's a lot of data coming in (if someone
 * wants to checksum an OpenSSL tarball, for example).
 */
#if defined(CIOCCPHASH) && defined(COP_FLAG_UPDATE) && defined(COP_FLAG_FINAL)
#define IMPLEMENT_DIGEST

/******************************************************************************
 *
 * Digests
 *
 * Because they all do the same basic operation, we have only one set of
 * method functions for them all to share, and a mapping table between
 * NIDs and cryptodev IDs, with all the necessary size data.
 *
 *****/

struct digest_ctx {
    struct session_op sess;
    /* This signals that the init function was called, not that it succeeded. */
    int init_called;
    unsigned char digest_res[HASH_MAX_LEN];
};

static const struct digest_data_st {
    int nid;
    int digestlen;
    int devcryptoid;
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, 16, CRYPTO_MD5 },
#endif
    { NID_sha1, 20, CRYPTO_SHA1 },
#ifndef OPENSSL_NO_RMD160
# if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_RIPEMD160)
    { NID_ripemd160, 20, CRYPTO_RIPEMD160 },
# endif
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_224)
    { NID_sha224, 224 / 8, CRYPTO_SHA2_224 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_256)
    { NID_sha256, 256 / 8, CRYPTO_SHA2_256 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_384)
    { NID_sha384, 384 / 8, CRYPTO_SHA2_384 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_512)
    { NID_sha512, 512 / 8, CRYPTO_SHA2_512 },
#endif
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

    memset(&digest_ctx->sess, 0, sizeof(digest_ctx->sess));
    digest_ctx->sess.mac = digest_d->devcryptoid;
    if (ioctl(cfd, CIOCGSESSION, &digest_ctx->sess) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int digest_op(struct digest_ctx *ctx, const void *src, size_t srclen,
                     void *res, unsigned int flags)
{
    struct crypt_op cryp;

    memset(&cryp, 0, sizeof(cryp));
    cryp.ses = ctx->sess.ses;
    cryp.len = srclen;
    cryp.src = (void *)src;
    cryp.dst = NULL;
    cryp.mac = res;
    cryp.flags = flags;
    return ioctl(cfd, CIOCCRYPT, &cryp);
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (count == 0)
        return 1;

    if (digest_ctx == NULL)
        return 0;

    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT)) {
        if (digest_op(digest_ctx, data, count, digest_ctx->digest_res, 0) >= 0)
            return 1;
    } else if (digest_op(digest_ctx, data, count, NULL, COP_FLAG_UPDATE) >= 0) {
        return 1;
    }

    SYSerr(SYS_F_IOCTL, errno);
    return 0;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (md == NULL || digest_ctx == NULL)
        return 0;

    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT)) {
        memcpy(md, digest_ctx->digest_res, EVP_MD_CTX_size(ctx));
    } else if (digest_op(digest_ctx, NULL, 0, md, COP_FLAG_FINAL) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);
    struct cphash_op cphash;

    if (digest_from == NULL || digest_from->init_called != 1)
        return 1;

    if (!digest_init(to)) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    cphash.src_ses = digest_from->sess.ses;
    cphash.dst_ses = digest_to->sess.ses;
    if (ioctl(cfd, CIOCCPHASH, &cphash) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }
    return 1;
}

static int digest_cleanup(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (digest_ctx == NULL)
        return 1;
    if (ioctl(cfd, CIOCFSESSION, &digest_ctx->sess.ses) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }
    return 1;
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

static int devcrypto_test_digest(size_t digest_data_index)
{
    return (digest_driver_info[digest_data_index].status == DEVCRYPTO_STATUS_USABLE
            && selected_digests[digest_data_index] == 1
            && (digest_driver_info[digest_data_index].accelerated
                    == DEVCRYPTO_ACCELERATED
                || use_softdrivers == DEVCRYPTO_USE_SOFTWARE
                || (digest_driver_info[digest_data_index].accelerated
                        != DEVCRYPTO_NOT_ACCELERATED
                    && use_softdrivers == DEVCRYPTO_REJECT_SOFTWARE)));
}

static void rebuild_known_digest_nids(void)
{
    size_t i;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data); i++) {
        if (devcrypto_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
}

static void prepare_digest_methods(void)
{
    size_t i;
    struct session_op sess1, sess2;
#ifdef CIOCGSESSINFO
    struct session_info_op siop;
#endif
    struct cphash_op cphash;

    memset(&digest_driver_info, 0, sizeof(digest_driver_info));

    memset(&sess1, 0, sizeof(sess1));
    memset(&sess2, 0, sizeof(sess2));

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data);
         i++) {

        selected_digests[i] = 1;

        /*
         * Check that the digest is usable
         */
        sess1.mac = digest_data[i].devcryptoid;
        sess2.ses = 0;
        if (ioctl(cfd, CIOCGSESSION, &sess1) < 0) {
            digest_driver_info[i].status = DEVCRYPTO_STATUS_NO_CIOCGSESSION;
            goto finish;
        }

#ifdef CIOCGSESSINFO
        /* gather hardware acceleration info from the driver */
        siop.ses = sess1.ses;
        if (ioctl(cfd, CIOCGSESSINFO, &siop) < 0) {
            digest_driver_info[i].accelerated = DEVCRYPTO_ACCELERATION_UNKNOWN;
        } else {
            digest_driver_info[i].driver_name =
                OPENSSL_strndup(siop.hash_info.cra_driver_name,
                                CRYPTODEV_MAX_ALG_NAME);
            if (siop.flags & SIOP_FLAG_KERNEL_DRIVER_ONLY)
                digest_driver_info[i].accelerated = DEVCRYPTO_ACCELERATED;
            else
                digest_driver_info[i].accelerated = DEVCRYPTO_NOT_ACCELERATED;
        }
#endif

        /* digest must be capable of hash state copy */
        sess2.mac = sess1.mac;
        if (ioctl(cfd, CIOCGSESSION, &sess2) < 0) {
            digest_driver_info[i].status = DEVCRYPTO_STATUS_FAILURE;
            goto finish;
        }
        cphash.src_ses = sess1.ses;
        cphash.dst_ses = sess2.ses;
        if (ioctl(cfd, CIOCCPHASH, &cphash) < 0) {
            digest_driver_info[i].status = DEVCRYPTO_STATUS_NO_CIOCCPHASH;
            goto finish;
        }
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
            digest_driver_info[i].status = DEVCRYPTO_STATUS_FAILURE;
            EVP_MD_meth_free(known_digest_methods[i]);
            known_digest_methods[i] = NULL;
            goto finish;
        }
        digest_driver_info[i].status = DEVCRYPTO_STATUS_USABLE;
finish:
        ioctl(cfd, CIOCFSESSION, &sess1.ses);
        if (sess2.ses != 0)
            ioctl(cfd, CIOCFSESSION, &sess2.ses);
        if (devcrypto_test_digest(i))
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

static int get_digest_nids(const int **nids)
{
    *nids = known_digest_nids;
    return known_digest_nids_amount;
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

static int devcrypto_digests(ENGINE *e, const EVP_MD **digest,
                             const int **nids, int nid)
{
    if (digest == NULL)
        return get_digest_nids(nids);

    *digest = get_digest_method(nid);

    return *digest != NULL;
}

static void devcrypto_select_all_digests(int *digest_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        digest_list[i] = 1;
}

static int cryptodev_select_digest_cb(const char *str, int len, void *usr)
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
        fprintf(stderr, "devcrypto: unknown digest %s\n", name);
    else if ((i = find_digest_data_index(EVP_MD_type(EVP))) != (size_t)-1)
        digest_list[i] = 1;
    else
        fprintf(stderr, "devcrypto: digest %s not available\n", name);
    OPENSSL_free(name);
    return 1;
}

static void dump_digest_info(void)
{
    size_t i;
    const char *name;

    fprintf (stderr, "Information about digests supported by the /dev/crypto"
             " engine:\n");
#ifndef CIOCGSESSINFO
    fprintf(stderr, "CIOCGSESSINFO (session info call) unavailable\n");
#endif

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        name = OBJ_nid2sn(digest_data[i].nid);
        fprintf (stderr, "Digest %s, NID=%d, /dev/crypto info: id=%d, driver=%s",
                 name ? name : "unknown", digest_data[i].nid,
                 digest_data[i].devcryptoid,
                 digest_driver_info[i].driver_name ? digest_driver_info[i].driver_name : "unknown");
        if (digest_driver_info[i].status == DEVCRYPTO_STATUS_NO_CIOCGSESSION) {
            fprintf (stderr, ". CIOCGSESSION (session open) failed\n");
            continue;
        }
        if (digest_driver_info[i].accelerated == DEVCRYPTO_ACCELERATED)
            fprintf(stderr, " (hw accelerated)");
        else if (digest_driver_info[i].accelerated == DEVCRYPTO_NOT_ACCELERATED)
            fprintf(stderr, " (software)");
        else
            fprintf(stderr, " (acceleration status unknown)");
        if (cipher_driver_info[i].status == DEVCRYPTO_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed\n");
        else if (digest_driver_info[i].status == DEVCRYPTO_STATUS_NO_CIOCCPHASH)
            fprintf(stderr, ", CIOCCPHASH failed\n");
        else
            fprintf(stderr, ", CIOCCPHASH capable\n");
    }
    fprintf(stderr, "\n");
}

#endif

/******************************************************************************
 *
 * CONTROL COMMANDS
 *
 *****/

#define DEVCRYPTO_CMD_USE_SOFTDRIVERS ENGINE_CMD_BASE
#define DEVCRYPTO_CMD_CIPHERS (ENGINE_CMD_BASE + 1)
#define DEVCRYPTO_CMD_DIGESTS (ENGINE_CMD_BASE + 2)
#define DEVCRYPTO_CMD_DUMP_INFO (ENGINE_CMD_BASE + 3)

static const ENGINE_CMD_DEFN devcrypto_cmds[] = {
#ifdef CIOCGSESSINFO
   {DEVCRYPTO_CMD_USE_SOFTDRIVERS,
    "USE_SOFTDRIVERS",
    "specifies whether to use software (not accelerated) drivers (" STR(DEVCRYPTO_REQUIRE_ACCELERATED)
        "=use only accelerated drivers, " STR(DEVCRYPTO_USE_SOFTWARE) "=allow all drivers, "
        STR(DEVCRYPTO_REJECT_SOFTWARE) "=use if acceleration can't be determined [default=2])",
    ENGINE_CMD_FLAG_NUMERIC},
#endif

   {DEVCRYPTO_CMD_CIPHERS,
    "CIPHERS",
    "either ALL, NONE, or a comma-separated list of ciphers to enable [default=ALL]",
    ENGINE_CMD_FLAG_STRING},

#ifdef IMPLEMENT_DIGEST
   {DEVCRYPTO_CMD_DIGESTS,
    "DIGESTS",
    "either ALL, NONE, or a comma-separated list of digests to enable [default=ALL]",
    ENGINE_CMD_FLAG_STRING},
#endif

   {DEVCRYPTO_CMD_DUMP_INFO,
    "DUMP_INFO",
    "dump info about each algorithm to stderr; use 'openssl engine -pre DUMP_INFO devcrypto'",
    ENGINE_CMD_FLAG_NO_INPUT},

   {0, NULL, NULL, 0}
};

static int devcrypto_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int *new_list;
    switch(cmd) {
#ifdef CIOCGSESSINFO
    case DEVCRYPTO_CMD_USE_SOFTDRIVERS:
        switch(i) {
        case DEVCRYPTO_REQUIRE_ACCELERATED:
        case DEVCRYPTO_USE_SOFTWARE:
        case DEVCRYPTO_REJECT_SOFTWARE:
            break;
        default:
            fprintf(stderr, "devcrypto: invalid value (%ld) for USE_SOFTDRIVERS\n", i);
            return 0;
        }
        if (use_softdrivers == i)
            return 1;
        use_softdrivers = i;
#ifdef IMPLEMENT_DIGEST
        rebuild_known_digest_nids();
#endif
        rebuild_known_cipher_nids();
        return 1;
#endif /* CIOCGSESSINFO */

    case DEVCRYPTO_CMD_CIPHERS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "ALL") == 0) {
            devcrypto_select_all_ciphers(selected_ciphers);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_ciphers, 0, sizeof(selected_ciphers));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_ciphers));
            if (!CONF_parse_list(p, ',', 1, cryptodev_select_cipher_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_ciphers, new_list, sizeof(selected_ciphers));
            OPENSSL_free(new_list);
        }
        rebuild_known_cipher_nids();
        return 1;

#ifdef IMPLEMENT_DIGEST
    case DEVCRYPTO_CMD_DIGESTS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "ALL") == 0) {
            devcrypto_select_all_digests(selected_digests);
        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_digests, 0, sizeof(selected_digests));
        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_digests));
            if (!CONF_parse_list(p, ',', 1, cryptodev_select_digest_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }
            memcpy(selected_digests, new_list, sizeof(selected_digests));
            OPENSSL_free(new_list);
        }
        rebuild_known_digest_nids();
        return 1;
#endif /* IMPLEMENT_DIGEST */

    case DEVCRYPTO_CMD_DUMP_INFO:
        dump_cipher_info();
#ifdef IMPLEMENT_DIGEST
        dump_digest_info();
#endif
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

/*
 * Opens /dev/crypto
 */
static int open_devcrypto(void)
{
    if (cfd >= 0)
        return 1;

    if ((cfd = open("/dev/crypto", O_RDWR, 0)) < 0) {
        fprintf(stderr, "Could not open /dev/crypto: %s\n", strerror(errno));
        return 0;
    }

    return 1;
}

static int close_devcrypto(void)
{
    if (cfd < 0)
        return 1;
    cfd = -1;
    if (close(cfd) == 0) {
        fprintf(stderr, "Error closing /dev/crypto: %s\n", strerror(errno));
        return 0;
    }
    return 1;
}

static int devcrypto_unload(ENGINE *e)
{
    destroy_all_cipher_methods();
#ifdef IMPLEMENT_DIGEST
    destroy_all_digest_methods();
#endif

    close_devcrypto();

    return 1;
}

static int bind_devcrypto(ENGINE *e) {

    if (!ENGINE_set_id(e, engine_devcrypto_id)
        || !ENGINE_set_name(e, "/dev/crypto engine")
        || !ENGINE_set_destroy_function(e, devcrypto_unload)
        || !ENGINE_set_cmd_defns(e, devcrypto_cmds)
        || !ENGINE_set_ctrl_function(e, devcrypto_ctrl))
        return 0;

    prepare_cipher_methods();
#ifdef IMPLEMENT_DIGEST
    prepare_digest_methods();
#endif

    return (ENGINE_set_ciphers(e, devcrypto_ciphers)
#ifdef IMPLEMENT_DIGEST
        && ENGINE_set_digests(e, devcrypto_digests)
#endif
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
        && ENGINE_set_RSA(e, devcrypto_rsa)
# endif
# ifndef OPENSSL_NO_DSA
        && ENGINE_set_DSA(e, devcrypto_dsa)
# endif
# ifndef OPENSSL_NO_DH
        && ENGINE_set_DH(e, devcrypto_dh)
# endif
# ifndef OPENSSL_NO_EC
        && ENGINE_set_EC(e, devcrypto_ec)
# endif
#endif
        );
}

#ifndef OPENSSL_DEVCRYPTO_DYNAMIC
/*
 * In case this engine is built into libcrypto, then it doesn't offer any
 * ability to be dynamically loadable.
 */
void engine_load_devcrypto_int()
{
    ENGINE *e = NULL;

    if (!open_devcrypto())
        return;

    if ((e = ENGINE_new()) == NULL
        || !bind_devcrypto(e)) {
        close_devcrypto();
        ENGINE_free(e);
        return;
    }

    ENGINE_add(e);
    ENGINE_free(e);          /* Loose our local reference */
    ERR_clear_error();
}

#else

static int bind_helper(ENGINE *e, const char *id)
{
    if ((id && (strcmp(id, engine_devcrypto_id) != 0))
        || !open_devcrypto())
        return 0;
    if (!bind_devcrypto(e)) {
        close_devcrypto();
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#endif
