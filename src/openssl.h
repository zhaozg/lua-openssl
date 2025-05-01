/* vim: set filetype=c : */

/*=========================================================================*\
* x509 routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#ifndef LUA_EAY_H
#define LUA_EAY_H
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <assert.h>
#include <string.h>
/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#if !defined(OPENSSL_NO_COMP)
#include <openssl/comp.h>
#endif
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/ts.h>
#include <openssl/ocsp.h>

/*-
* Numeric release version identifier:
* MNNFFPPS: major minor fix patch status
* The status nibble has one of the values 0 for development, 1 to e for betas
* 1 to 14, and f for release.  The patch level is exactly that.
* For example:
* 0.9.3-dev      0x00903000
* 0.9.3-beta1    0x00903001
* 0.9.3-beta2-dev 0x00903002
* 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
* 0.9.3          0x0090300f
* 0.9.3a         0x0090301f
* 0.9.4          0x0090400f
* 1.2.3z         0x102031af
*/

/*History
  2017-04-18  update to 0.7.1
  2017-08-04  update to 0.7.3
  2019-03-24  update to 0.7.5-1
  2019-05-19  update to 0.7.5-2
  2019-08-20  update to 0.7.6
*/

/*                              MNNFFPPS  */
#define LOPENSSL_VERSION_NUM  0x0090200f
#ifndef LOPENSSL_VERSION
#define LOPENSSL_VERSION  "0.9.2"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/lhash.h>
#define OPENSSL_HAVE_TS
#define LHASH LHASH_OF(CONF_VALUE)
#endif

#define LUA_FUNCTION(X) int X(lua_State *L)

int openssl_s2i_revoke_reason(const char*s);

LUALIB_API LUA_FUNCTION(luaopen_openssl);
LUA_FUNCTION(luaopen_digest);
LUA_FUNCTION(luaopen_hmac);
LUA_FUNCTION(luaopen_cipher);
LUA_FUNCTION(luaopen_bn);
LUA_FUNCTION(luaopen_pkey);
LUA_FUNCTION(luaopen_x509);
LUA_FUNCTION(luaopen_pkcs7);
LUA_FUNCTION(luaopen_pkcs12);
LUA_FUNCTION(luaopen_bio);
LUA_FUNCTION(luaopen_asn1);

LUA_FUNCTION(luaopen_ts);
LUA_FUNCTION(luaopen_x509_req);
LUA_FUNCTION(luaopen_x509_crl);
LUA_FUNCTION(luaopen_ocsp);
LUA_FUNCTION(luaopen_cms);
LUA_FUNCTION(luaopen_ssl);
LUA_FUNCTION(luaopen_ec);
LUA_FUNCTION(luaopen_rsa);
LUA_FUNCTION(luaopen_dsa);
LUA_FUNCTION(luaopen_dh);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
LUA_FUNCTION(luaopen_mac);
LUA_FUNCTION(luaopen_param);
#endif
LUA_FUNCTION(luaopen_kdf);
LUA_FUNCTION(luaopen_srp);

#endif
