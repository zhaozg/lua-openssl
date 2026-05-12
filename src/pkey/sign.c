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

/* ========================================================================
 * Shared helper: prepare EVP_MD_CTX for sign/verify
 *
 * Sets up the digest (NULL for EdDSA/PQC), SM2 context if applicable,
 * and calls the appropriate Init function.
 *
 * @param L Lua state
 * @param pkey EVP_PKEY to sign/verify with
 * @param md_alg_idx Lua stack index for optional digest parameter
 * @param userid_idx Lua stack index for optional SM2 userid parameter
 * @param[out] out_ctx The initialized EVP_MD_CTX (caller must free)
 * @param[out] out_md The selected EVP_MD (NULL for EdDSA/PQC)
 * @param is_sign 1 for sign, 0 for verify
 * @return 1 on success, 0 on failure (error already pushed on Lua stack)
 * ======================================================================== */
static int
sign_verify_init_ctx(lua_State *L, EVP_PKEY *pkey,
                     int md_alg_idx, int userid_idx,
                     EVP_MD_CTX **out_ctx, const EVP_MD **out_md,
                     int is_sign)
{
  const char   *md_alg;
  const EVP_MD *md;
  EVP_MD_CTX   *ctx;
  int           ret;

#if defined(OPENSSL_SUPPORT_SM2)
  int           is_SM2 = 0;
  EVP_PKEY_CTX *pctx = NULL;
#endif

  md_alg = "sha256";
#if defined(OPENSSL_SUPPORT_SM2)
  is_SM2 = openssl_pkey_is_sm2(pkey);
  if (is_SM2) md_alg = "sm3";
#endif

  /* For EdDSA keys (Ed25519, Ed448) and PQC signature algorithms (ML-DSA, etc.),
   * allow NULL digest as they use internal hash functions.
   * Uses shared helper evp_pkey_needs_null_digest() defined in core.c. */
  if (evp_pkey_needs_null_digest(pkey)) {
    md = NULL;
  } else {
    md = get_digest(L, md_alg_idx, md_alg);
  }

#if defined(OPENSSL_SUPPORT_SM2)
  if (is_SM2 && md) is_SM2 = EVP_MD_type(md) == NID_sm3;
#endif

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "EVP_MD_CTX_new failed");
    return 0;
  }

#if defined(OPENSSL_SUPPORT_SM2)
  if (is_SM2) {
    size_t idlen = 0;
    const char *userId = luaL_optlstring(L, userid_idx, SM2_DEFAULT_USERID, &idlen);
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx) {
      EVP_PKEY_CTX_set1_id(pctx, userId, idlen);
      EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
    }
  }
#endif

  if (is_sign) {
    ret = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
  } else {
    ret = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
  }

  if (ret != 1) {
    EVP_MD_CTX_free(ctx);
#if defined(OPENSSL_SUPPORT_SM2)
    if (pctx) EVP_PKEY_CTX_free(pctx);
#endif
    openssl_pushresult(L, ret);
    return 0;
  }

  *out_ctx = ctx;
  *out_md = md;
  return 1;
}

/***
 * sign message with private key
 * @function sign
 * @tparam string data data be signed
 * @tparam[opt] string|env_digest md_alg digest algorithm name, default "sha256" (or "sm3" for SM2).
 *  For EdDSA (Ed25519, Ed448) and PQC signature algorithms (ML-DSA, Falcon, SLH-DSA),
 *  the digest is ignored as these algorithms use internal hashing.
 * @tparam[opt='1234567812345678'] string userId used when pkey is SM2 type
 * @treturn string signed message
 * @treturn[2] nil
 * @treturn[2] string error message
 * @see evp_pkey_needs_null_digest
 */
int
openssl_sign(lua_State *L)
{
  int           ret = 0;
  size_t        data_len;
  const char   *data;
  EVP_PKEY     *pkey;
  const EVP_MD *md;
  EVP_MD_CTX   *ctx;

  pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  data = luaL_checklstring(L, 2, &data_len);

  /* Use shared helper to initialize context with proper digest detection */
  if (!sign_verify_init_ctx(L, pkey, 3, 4, &ctx, &md, 1)) {
    return 2; /* nil, error already pushed */
  }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
  /* For EdDSA and PQC algorithms, use one-shot API if available (OpenSSL >= 1.1.1) */
  if (md == NULL) {
    size_t siglen = 0;
    ret = EVP_DigestSign(ctx, NULL, &siglen, (const unsigned char *)data, data_len);
    if (ret == 1) {
      unsigned char *sigbuf = OPENSSL_malloc(siglen);
      if (sigbuf) {
        ret = EVP_DigestSign(ctx, sigbuf, &siglen, (const unsigned char *)data, data_len);
        if (ret == 1) {
          lua_pushlstring(L, (char *)sigbuf, siglen);
        }
        OPENSSL_free(sigbuf);
      } else {
        ret = 0;
      }
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
        if (sigbuf) {
          ret = EVP_DigestSignFinal(ctx, sigbuf, &siglen);
          if (ret == 1) {
            lua_pushlstring(L, (char *)sigbuf, siglen);
          }
          OPENSSL_free(sigbuf);
        } else {
          ret = 0;
        }
      }
    }
  }

  EVP_MD_CTX_free(ctx);

  return ret == 1 ? 1 : openssl_pushresult(L, ret);
}

/***
 * verify signed message with public key
 * @function verify
 * @tparam string data data be signed
 * @tparam string signature signed result
 * @tparam[opt] string|env_digest md_alg digest algorithm name, default "sha256" (or "sm3" for SM2).
 *  For EdDSA (Ed25519, Ed448) and PQC signature algorithms (ML-DSA, Falcon, SLH-DSA),
 *  the digest is ignored as these algorithms use internal hashing.
 * @tparam[opt='1234567812345678'] string userId used when pkey is SM2 type
 * @treturn boolean true for pass verify
 * @treturn[2] nil
 * @treturn[2] string error message
 * @see evp_pkey_needs_null_digest
 */
int
openssl_verify(lua_State *L)
{
  int           ret = 0;
  size_t        data_len, signature_len;
  const char   *data, *signature;
  EVP_PKEY     *pkey;
  const EVP_MD *md;
  EVP_MD_CTX   *ctx;

  pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  data = luaL_checklstring(L, 2, &data_len);
  signature = luaL_checklstring(L, 3, &signature_len);

  /* Use shared helper to initialize context with proper digest detection */
  if (!sign_verify_init_ctx(L, pkey, 4, 5, &ctx, &md, 0)) {
    return 2; /* nil, error already pushed */
  }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
  /* For EdDSA and PQC algorithms, use one-shot API if available (OpenSSL >= 1.1.1) */
  if (md == NULL) {
    ret = EVP_DigestVerify(ctx, (const unsigned char *)signature, signature_len,
                            (const unsigned char *)data, data_len);
    lua_pushboolean(L, ret == 1);
  } else
#endif
  {
    /* Traditional three-step approach for algorithms with digest */
    ret = EVP_DigestVerifyUpdate(ctx, data, data_len);
    if (ret == 1) {
      ret = EVP_DigestVerifyFinal(ctx, (unsigned char *)signature, signature_len);
    }
    lua_pushboolean(L, ret == 1);
  }

  EVP_MD_CTX_free(ctx);
  return 1;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
