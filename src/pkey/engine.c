/***
 * pkey engine module
 * Engine support for hardware acceleration
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef OPENSSL_NO_ENGINE

/***
 * set engine for the key
 * @function set_engine
 * @tparam openssl.engine eng engine object to use for this key
 * @treturn boolean result true for success
 */
int
openssl_pkey_set_engine(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  ENGINE   *eng = CHECK_OBJECT(2, ENGINE, "openssl.engine");

  int ret = 0;

  int typ = EVP_PKEY_type(EVP_PKEY_id(pkey));
  switch (typ) {
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA: {
    RSA              *rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
    const RSA_METHOD *m = ENGINE_get_RSA(eng);
    if (m != NULL) ret = RSA_set_method(rsa, m);
    break;
  }
#endif
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA: {
    DSA              *dsa = (DSA *)EVP_PKEY_get0_DSA(pkey);
    const DSA_METHOD *m = ENGINE_get_DSA(eng);
    if (m != NULL) ret = DSA_set_method(dsa, m);
    break;
  }
#endif
#ifndef OPENSSL_NO_DH
  case EVP_PKEY_DH: {
    DH              *dh = (DH *)EVP_PKEY_get0_DH(pkey);
    const DH_METHOD *m = ENGINE_get_DH(eng);
    if (m != NULL) ret = DH_set_method(dh, m);
    break;
  }
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC: {
    EC_KEY *ec = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    const ECDSA_METHOD *m = ENGINE_get_ECDSA(eng);
    if (m != NULL) ret = ECDSA_set_method(ec, m);
#else
    const EC_KEY_METHOD *m = ENGINE_get_EC(eng);
    if (m != NULL) ret = EC_KEY_set_method(ec, m);
#endif
    break;
  }
#endif
  default:
    break;
  }

  lua_pushboolean(L, ret == 1);
  return 1;
}
#endif /* OPENSSL_NO_ENGINE */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
