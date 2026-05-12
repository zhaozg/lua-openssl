/***
 * pkey sign/verify module
 * Sign and verify operations
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/***
 * sign message with private key
 * @function sign
 * @tparam string data data be signed
 * @tparam[opt] string|env_digest md_alg default use sha256 or sm3 when pkey is SM2 type
 * @tparam[opt='1234567812345678'] string userId used when pkey is SM2 type
 * @treturn string signed message
 */
int
openssl_sign(lua_State *L)
{
  int           ret = 0;
  size_t        data_len;
  const char   *data;
  const char   *md_alg;
  EVP_PKEY     *pkey;
  const EVP_MD *md;
  EVP_MD_CTX   *ctx;

#if defined(OPENSSL_SUPPORT_SM2)
  int           is_SM2 = 0;
  EVP_PKEY_CTX *pctx = NULL;
#endif

  pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  data = luaL_checklstring(L, 2, &data_len);

  md_alg = "sha256";
#if defined(OPENSSL_SUPPORT_SM2)
  is_SM2 = openssl_pkey_is_sm2(pkey);
  if (is_SM2) md_alg = "sm3";
#endif

  /* For EdDSA keys (Ed25519, Ed448) and PQC signature algorithms (ML-DSA, etc.),
   * allow NULL digest as they use internal hash functions.
   * Detect these and allow omitting or explicitly passing nil.
   *
   * NOTE: For PQC algorithms (ML-DSA, SLH-DSA), EVP_PKEY_type(EVP_PKEY_id(pkey))
   * returns 0 because these NIDs are not registered in the legacy type table.
   * So we must compare EVP_PKEY_id(pkey) directly for PQC algorithms. */
  {
    int pkey_id = EVP_PKEY_id(pkey);
    int pkey_type = EVP_PKEY_type(pkey_id);
    int needs_null_digest = 0;
#ifdef EVP_PKEY_ED25519
    if (pkey_type == EVP_PKEY_ED25519
#ifdef EVP_PKEY_ED448
        || pkey_type == EVP_PKEY_ED448
#endif
    ) {
      needs_null_digest = 1;
    }
#endif
    /* PQC signature algorithms (ML-DSA/Dilithium, Falcon, SLH-DSA/SPHINCS+) use
     * internal hashing and don't need an external digest.
     * Detect these and allow omitting or explicitly passing nil.
     * Use EVP_PKEY_id() directly since EVP_PKEY_type() returns 0 for these. */
    if (!needs_null_digest) {
      /* Old OQS provider names (DILITHIUM, KYBER, SPHINCS) */
#ifdef EVP_PKEY_DILITHIUM
      if (pkey_id == EVP_PKEY_DILITHIUM) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM2
      if (pkey_id == EVP_PKEY_DILITHIUM2) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM3
      if (pkey_id == EVP_PKEY_DILITHIUM3) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM5
      if (pkey_id == EVP_PKEY_DILITHIUM5) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON
      if (pkey_id == EVP_PKEY_FALCON) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON512
      if (pkey_id == EVP_PKEY_FALCON512) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON1024
      if (pkey_id == EVP_PKEY_FALCON1024) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCS
      if (pkey_id == EVP_PKEY_SPHINCS) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCSSHA256
      if (pkey_id == EVP_PKEY_SPHINCSSHA256) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCSSHAKE256
      if (pkey_id == EVP_PKEY_SPHINCSSHAKE256) needs_null_digest = 1;
#endif
      /* Standardized NIST names (OpenSSL 3.5+) */
#ifdef EVP_PKEY_ML_DSA_44
      if (pkey_id == EVP_PKEY_ML_DSA_44) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_ML_DSA_65
      if (pkey_id == EVP_PKEY_ML_DSA_65) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_ML_DSA_87
      if (pkey_id == EVP_PKEY_ML_DSA_87) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_128S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_128F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_192S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_192F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_256S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_256F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_128S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_128F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_192S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_192F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_256S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_256F) needs_null_digest = 1;
#endif
    }
    /* Fallback: for keymgmt-based keys (EVP_PKEY_id == -1), such as
     * PQC public keys obtained via EVP_PKEY_dup, try NULL digest.
     * These algorithms (ML-DSA, SLH-DSA) use internal hashing. */
    if (!needs_null_digest && pkey_id == -1) {
      needs_null_digest = 1;
    }
    if (needs_null_digest) {
      md = NULL;
    } else {
      md = get_digest(L, 3, md_alg);
    }
  }
#if defined(OPENSSL_SUPPORT_SM2)
  if (is_SM2 && md) is_SM2 = EVP_MD_type(md) == NID_sm3;
#endif

  ctx = EVP_MD_CTX_new();
#if defined(OPENSSL_SUPPORT_SM2)
  if (is_SM2) {
    size_t idlen = 0;

    const char *userId = luaL_optlstring(L, 4, SM2_DEFAULT_USERID, &idlen);
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, userId, idlen);
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
  }
#endif

  ret = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
  if (ret == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* For EdDSA (and other algorithms), use one-shot API if available (OpenSSL >= 1.1.1) */
    if (md == NULL) {
      size_t siglen = 0;
      ret = EVP_DigestSign(ctx, NULL, &siglen, (const unsigned char *)data, data_len);
      if (ret == 1) {
        unsigned char *sigbuf = OPENSSL_malloc(siglen);
        ret = EVP_DigestSign(ctx, sigbuf, &siglen, (const unsigned char *)data, data_len);
        if (ret == 1) {
          lua_pushlstring(L, (char *)sigbuf, siglen);
        }
        OPENSSL_free(sigbuf);
      }
    } else
#endif
    {
      /* Traditional three-step approach for algorithms with digest */
      ret = EVP_DigestSignUpdate(ctx, data, data_len);
      if (ret == 1) {
        size_t         siglen = 0;
        unsigned char *sigbuf = NULL;
        ret = EVP_DigestSignFinal(ctx, NULL, &siglen);
        if (ret == 1) {
          siglen += 2;
          sigbuf = OPENSSL_malloc(siglen);
          ret = EVP_DigestSignFinal(ctx, sigbuf, &siglen);
          if (ret == 1) {
            lua_pushlstring(L, (char *)sigbuf, siglen);
          }
          OPENSSL_free(sigbuf);
        }
      }
    }
  }

  EVP_MD_CTX_free(ctx);
#if defined(OPENSSL_SUPPORT_SM2)
  if (pctx) EVP_PKEY_CTX_free(pctx);
#endif

  return ret == 1 ? 1 : openssl_pushresult(L, ret);
}

/***
 * verify signed message with public key
 * @function verify
 * @tparam string data data be signed
 * @tparam string signature signed result
 * @tparam[opt] string|env_digest md_alg default use sha256 or sm3 when pkey is SM2 type
 * @tparam[opt='1234567812345678'] string userId used when pkey is SM2 type
 * @treturn boolean true for pass verify
 */
int
openssl_verify(lua_State *L)
{
  int           ret = 0;
  size_t        data_len, signature_len;
  const char   *data, *signature;
  const char   *md_alg;
  EVP_PKEY     *pkey;
  const EVP_MD *md;
  EVP_MD_CTX   *ctx;

#if defined(OPENSSL_SUPPORT_SM2)
  int           is_SM2 = 0;
  EVP_PKEY_CTX *pctx = NULL;
#endif

  pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  data = luaL_checklstring(L, 2, &data_len);
  signature = luaL_checklstring(L, 3, &signature_len);

  md_alg = "sha256";
#if defined(OPENSSL_SUPPORT_SM2)
  is_SM2 = openssl_pkey_is_sm2(pkey);
  if (is_SM2) md_alg = "sm3";
#endif

  /* For EdDSA keys (Ed25519, Ed448) and PQC signature algorithms (ML-DSA, etc.),
   * allow NULL digest as they use internal hash functions.
   * Detect these and allow omitting or explicitly passing nil.
   *
   * NOTE: For PQC algorithms (ML-DSA, SLH-DSA), EVP_PKEY_type(EVP_PKEY_id(pkey))
   * returns 0 because these NIDs are not registered in the legacy type table.
   * So we must compare EVP_PKEY_id(pkey) directly for PQC algorithms. */
  {
    int pkey_id = EVP_PKEY_id(pkey);
    int pkey_type = EVP_PKEY_type(pkey_id);
    int needs_null_digest = 0;
#ifdef EVP_PKEY_ED25519
    if (pkey_type == EVP_PKEY_ED25519
#ifdef EVP_PKEY_ED448
        || pkey_type == EVP_PKEY_ED448
#endif
    ) {
      needs_null_digest = 1;
    }
#endif
    /* PQC signature algorithms (ML-DSA/Dilithium, Falcon, SLH-DSA/SPHINCS+) use
     * internal hashing and don't need an external digest.
     * Detect these and allow omitting or explicitly passing nil.
     * Use EVP_PKEY_id() directly since EVP_PKEY_type() returns 0 for these. */
    if (!needs_null_digest) {
      /* Old OQS provider names (DILITHIUM, KYBER, SPHINCS) */
#ifdef EVP_PKEY_DILITHIUM
      if (pkey_id == EVP_PKEY_DILITHIUM) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM2
      if (pkey_id == EVP_PKEY_DILITHIUM2) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM3
      if (pkey_id == EVP_PKEY_DILITHIUM3) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_DILITHIUM5
      if (pkey_id == EVP_PKEY_DILITHIUM5) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON
      if (pkey_id == EVP_PKEY_FALCON) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON512
      if (pkey_id == EVP_PKEY_FALCON512) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_FALCON1024
      if (pkey_id == EVP_PKEY_FALCON1024) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCS
      if (pkey_id == EVP_PKEY_SPHINCS) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCSSHA256
      if (pkey_id == EVP_PKEY_SPHINCSSHA256) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SPHINCSSHAKE256
      if (pkey_id == EVP_PKEY_SPHINCSSHAKE256) needs_null_digest = 1;
#endif
      /* Standardized NIST names (OpenSSL 3.5+) */
#ifdef EVP_PKEY_ML_DSA_44
      if (pkey_id == EVP_PKEY_ML_DSA_44) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_ML_DSA_65
      if (pkey_id == EVP_PKEY_ML_DSA_65) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_ML_DSA_87
      if (pkey_id == EVP_PKEY_ML_DSA_87) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_128S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_128F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_192S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_192F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_256S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHA2_256F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_128S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_128F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_192S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_192F) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256S
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_256S) needs_null_digest = 1;
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256F
      if (pkey_id == EVP_PKEY_SLH_DSA_SHAKE_256F) needs_null_digest = 1;
#endif
    }
    /* Fallback: for keymgmt-based keys (EVP_PKEY_id == -1), such as
     * PQC public keys obtained via EVP_PKEY_dup, try NULL digest.
     * These algorithms (ML-DSA, SLH-DSA) use internal hashing. */
    if (!needs_null_digest && pkey_id == -1) {
      needs_null_digest = 1;
    }
    if (needs_null_digest) {
      md = NULL;
    } else {
      md = get_digest(L, 4, md_alg);
    }
  }

  ctx = EVP_MD_CTX_new();
#if defined(OPENSSL_SUPPORT_SM2)
  if (is_SM2) {
    size_t idlen = 0;

    const char *userId = luaL_optlstring(L, 5, SM2_DEFAULT_USERID, &idlen);

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, userId, idlen);
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
  }
#endif

  ret = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
  if (ret == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* For EdDSA (and other algorithms), use one-shot API if available (OpenSSL >= 1.1.1) */
    if (md == NULL) {
      ret = EVP_DigestVerify(ctx, (const unsigned char *)signature, signature_len,
                              (const unsigned char *)data, data_len);
      if (ret == 1) {
        lua_pushboolean(L, 1);
      } else {
        lua_pushboolean(L, 0);
      }
    } else
#endif
    {
      /* Traditional three-step approach for algorithms with digest */
      ret = EVP_DigestVerifyUpdate(ctx, data, data_len);
      if (ret == 1) {
        ret = EVP_DigestVerifyFinal(ctx, (unsigned char *)signature, signature_len);
        if (ret == 1) {
          lua_pushboolean(L, ret == 1);
        } else {
          lua_pushboolean(L, 0);
        }
      } else {
        lua_pushboolean(L, 0);
      }
    }
    /* Return 1 to indicate we pushed a result (true or false) */
    EVP_MD_CTX_free(ctx);
#if defined(OPENSSL_SUPPORT_SM2)
    if (pctx) EVP_PKEY_CTX_free(pctx);
#endif
    return 1;
  }

  EVP_MD_CTX_free(ctx);
#if defined(OPENSSL_SUPPORT_SM2)
  if (pctx) EVP_PKEY_CTX_free(pctx);
#endif

  return ret == 1 ? 1 : openssl_pushresult(L, ret);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
