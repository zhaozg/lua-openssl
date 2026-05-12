/***
 * pkey derive module
 * Key derivation (DH, ECDH, X25519, X448)
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/***
 * derive shared secret
 * @function derive
 * @tparam openssl.evp_pkey peer peer's public key
 * @tparam[opt] openssl.engine eng engine for hardware acceleration
 * @treturn string shared secret
 */
int
openssl_derive(lua_State *L)
{
  int ret = 0;

  EVP_PKEY     *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  EVP_PKEY     *peer = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  ENGINE       *eng = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");
  EVP_PKEY_CTX *ctx;
  int           ptype = EVP_PKEY_type(EVP_PKEY_id(pkey));

#if !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_EC)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
  /* OpenSSL 3.0+ way: use PARAM API compatible check */
  {
    int valid_pkey = (ptype == EVP_PKEY_DH && pkey_is_type(pkey, EVP_PKEY_DH))
                  || (ptype == EVP_PKEY_EC && pkey_is_type(pkey, EVP_PKEY_EC))
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support DH, EC, X25519 or X448 private key");
  }
#else
  /* OpenSSL 1.x way */
  {
    int valid_pkey = (ptype == EVP_PKEY_DH && EVP_PKEY_get0_DH(pkey) != NULL)
                  || (ptype == EVP_PKEY_EC && EVP_PKEY_get0_EC_KEY(pkey) != NULL)
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support DH, EC, X25519 or X448 private key");
  }
#endif
#elif !defined(OPENSSL_NO_DH)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
  /* OpenSSL 3.0+ way: use PARAM API compatible check */
  {
    int valid_pkey = (ptype == EVP_PKEY_DH && pkey_is_type(pkey, EVP_PKEY_DH))
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support DH, X25519 or X448 private key");
  }
#else
  /* OpenSSL 1.x way */
  {
    int valid_pkey = (ptype == EVP_PKEY_DH && EVP_PKEY_get0_DH(pkey) != NULL)
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support DH, X25519 or X448 private key");
  }
#endif
#elif !defined(OPENSSL_NO_EC)
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
  /* OpenSSL 3.0+ way: use PARAM API compatible check */
  {
    int valid_pkey = (ptype == EVP_PKEY_EC && pkey_is_type(pkey, EVP_PKEY_EC))
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support EC, X25519 or X448 private key");
  }
#else
  /* OpenSSL 1.x way */
  {
    int valid_pkey = (ptype == EVP_PKEY_EC && EVP_PKEY_get0_EC_KEY(pkey) != NULL)
#ifdef EVP_PKEY_X25519
                  || ptype == EVP_PKEY_X25519
#ifdef EVP_PKEY_X448
                  || ptype == EVP_PKEY_X448
#endif
#endif
                  ;
    luaL_argcheck(L, valid_pkey, 1, "only support EC, X25519 or X448 private key");
  }
#endif
#endif

  luaL_argcheck(L, ptype == EVP_PKEY_type(EVP_PKEY_id(peer)), 2, "mismatch key type");

  ctx = EVP_PKEY_CTX_new(pkey, eng);
  if (ctx) {
    ret = EVP_PKEY_derive_init(ctx);
    if (ret == 1) {
      ret = EVP_PKEY_derive_set_peer(ctx, peer);
      if (ret == 1) {
        size_t skeylen;
        ret = EVP_PKEY_derive(ctx, NULL, &skeylen);
        if (ret == 1) {
          unsigned char *skey = OPENSSL_malloc(skeylen);
          if (skey) {
            ret = EVP_PKEY_derive(ctx, skey, &skeylen);
            if (ret == 1) {
              lua_pushlstring(L, (const char *)skey, skeylen);
            }
            OPENSSL_free(skey);
          }
        }
      }
    }
    EVP_PKEY_CTX_free(ctx);
  }

  return ret == 1 ? 1 : openssl_pushresult(L, ret);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
