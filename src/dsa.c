/*=========================================================================*\
* dsa.c
* DSA routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/dsa.h>

#define MYNAME    "dsa"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

#define lua_boxpointer(L,u) \
  (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define PUSH_BN(x)                  \
lua_boxpointer(L,x);                \
luaL_getmetatable(L,"openssl.bn");  \
lua_setmetatable(L,-2)

static LUA_FUNCTION(openssl_dsa_free)
{
  DSA* dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
  DSA_free(dsa);
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  return 0;
};

static LUA_FUNCTION(openssl_dsa_parse)
{
  DSA* dsa = CHECK_OBJECT(1, DSA, "openssl.rsa");
  lua_newtable(L);
  OPENSSL_PKEY_GET_BN(dsa->p, p);
  OPENSSL_PKEY_GET_BN(dsa->q, q);
  OPENSSL_PKEY_GET_BN(dsa->g, g);
  OPENSSL_PKEY_GET_BN(dsa->priv_key, priv_key);
  OPENSSL_PKEY_GET_BN(dsa->pub_key, pub_key);
  return 1;
}

static luaL_Reg dsa_funs[] =
{
  {"parse",       openssl_dsa_parse},

  {"__gc",        openssl_dsa_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

int luaopen_dsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.dsa",     dsa_funs);
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
