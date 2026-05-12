/***
 * pkey SM2 module
 * SM2 (Chinese national standard) key support
 *
 * Note: SM2 as_sm2 is only available on OpenSSL < 3.0.0
 * On OpenSSL 3.0+, SM2 keys are handled natively via EVP_PKEY.
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#if defined(OPENSSL_SUPPORT_SM2) && OPENSSL_VERSION_NUMBER < 0x30000000

/***
 * convert EC key to SM2 key type
 * @function as_sm2
 * @treturn boolean result true if successfully converted to SM2
 */
int
openssl_pkey_as_sm2(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int       type = EVP_PKEY_type(EVP_PKEY_id(pkey));
  int       ret = 0;

  luaL_argcheck(L, type == EVP_PKEY_EC, 1, "must be EC key with SM2 curve");

  if (type == EVP_PKEY_EC) {
    const EC_KEY   *ec = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    int             curve = EC_GROUP_get_curve_name(grp);
    if (curve == NID_sm2) {
      EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
      lua_pushboolean(L, 1);
      ret = 1;
    }
  }

  return ret;
}
#endif /* OPENSSL_SUPPORT_SM2 && OPENSSL_VERSION_NUMBER < 0x30000000 */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
