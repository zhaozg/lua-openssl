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
#include "auxiliar.h"

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
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>

#define LOPENSSL_VERSION_STR  "0.4.0"

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/lhash.h>
#define OPENSSL_HAVE_TS
#define LHASH LHASH_OF(CONF_VALUE)
#endif
typedef unsigned char byte;

#define MULTI_LINE_MACRO_BEGIN do {
#ifdef _MSC_VER
#define MULTI_LINE_MACRO_END  \
__pragma(warning(push))   \
__pragma(warning(disable:4127)) \
} while(0)      \
__pragma(warning(pop))
#else
#define MULTI_LINE_MACRO_END \
} while(0)
#endif

/* Common */
#include <time.h>
#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

#ifdef NETWARE
#define timezone _timezone  /* timezone is called _timezone in LibC */
#endif


#ifdef WIN32
#define snprintf _snprintf
#ifndef strcasecmp
#define strcasecmp stricmp
#endif
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

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) ;
void openssl_add_method(const OBJ_NAME *name, void *arg);

#define CHECK_OBJECT(n,type,name) *(type**)auxiliar_checkclass(L,name,n)

#define PUSH_OBJECT(o, tname)                                   \
  MULTI_LINE_MACRO_BEGIN                                        \
  if(o) {                                                       \
  *(void **)(lua_newuserdata(L, sizeof(void *))) = (void*)(o);  \
  auxiliar_setclass(L,tname,-1);                                \
  }else lua_pushnil(L);                                         \
  MULTI_LINE_MACRO_END

int openssl_register_lhash(lua_State* L);
int openssl_register_engine(lua_State* L);

#endif

