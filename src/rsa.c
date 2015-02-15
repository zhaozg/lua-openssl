/*=========================================================================*\
* ec.c
* RSA routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/rsa.h>

#define MYNAME    "rsa"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

#define lua_boxpointer(L,u) \
  (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define PUSH_BN(x)                  \
lua_boxpointer(L,x);                \
luaL_getmetatable(L,"openssl.bn");  \
lua_setmetatable(L,-2)

static LUA_FUNCTION(openssl_rsa_free)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  RSA_free(rsa);
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  return 0;
};

static LUA_FUNCTION(openssl_rsa_parse)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  lua_newtable(L);
  OPENSSL_PKEY_GET_BN(rsa->n, n);
  OPENSSL_PKEY_GET_BN(rsa->e, e);
  OPENSSL_PKEY_GET_BN(rsa->d, d);
  OPENSSL_PKEY_GET_BN(rsa->p, p);
  OPENSSL_PKEY_GET_BN(rsa->q, q);
  OPENSSL_PKEY_GET_BN(rsa->dmp1, dmp1);
  OPENSSL_PKEY_GET_BN(rsa->dmq1, dmq1);
  OPENSSL_PKEY_GET_BN(rsa->iqmp, iqmp);
  return 1;
}

static luaL_Reg rsa_funs[] =
{
  {"parse",       openssl_rsa_parse},

  {"__gc",        openssl_rsa_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

int luaopen_rsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.rsa",     rsa_funs);
  return 0;
  /*
    lua_newtable(L);
    luaL_setfuncs(L, R, 0);
    lua_pushliteral(L, "version");
    lua_pushliteral(L, MYVERSION);
    lua_settable(L, -3);

    return 1;
  */
}
