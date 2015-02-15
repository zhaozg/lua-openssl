/*=========================================================================*\
* dh.c
* DH routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/dh.h>

#define MYNAME    "dh"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

#define lua_boxpointer(L,u) \
  (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define PUSH_BN(x)                  \
lua_boxpointer(L,x);                \
luaL_getmetatable(L,"openssl.bn");  \
lua_setmetatable(L,-2)

static LUA_FUNCTION(openssl_dh_free)
{
  DH* dh = CHECK_OBJECT(1, DH, "openssl.dh");
  DH_free(dh);
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  return 0;
};

static LUA_FUNCTION(openssl_dh_parse)
{
  DH* dh = CHECK_OBJECT(1, DH, "openssl.dh");
  lua_newtable(L);
  OPENSSL_PKEY_GET_BN(dh->p, p);
  OPENSSL_PKEY_GET_BN(dh->g, g);
  OPENSSL_PKEY_GET_BN(dh->priv_key, priv_key);
  OPENSSL_PKEY_GET_BN(dh->pub_key, pub_key);

  return 1;
}

static luaL_Reg dh_funs[] =
{
  {"parse",       openssl_dh_parse},

  {"__gc",        openssl_dh_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

int luaopen_dh(lua_State *L)
{
  auxiliar_newclass(L, "openssl.dh",     dh_funs);
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
