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
  return 0;
};

static LUA_FUNCTION(openssl_dsa_parse)
{
  const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *pri = NULL;
  DSA* dsa = CHECK_OBJECT(1, DSA, "openssl.rsa");
  lua_newtable(L);

  lua_pushinteger(L, DSA_size(dsa));
  lua_setfield(L, -2, "size");

  lua_pushinteger(L, DSA_bits(dsa));
  lua_setfield(L, -2, "bits");

  DSA_get0_pqg(dsa, &p, &q, &g);
  DSA_get0_key(dsa, &pub, &pri);

  OPENSSL_PKEY_GET_BN(p, p);
  OPENSSL_PKEY_GET_BN(q, q);
  OPENSSL_PKEY_GET_BN(g, g);
  OPENSSL_PKEY_GET_BN(pri, priv_key);
  OPENSSL_PKEY_GET_BN(pub, pub_key);
  return 1;
}

static luaL_Reg dsa_funs[] =
{
  {"parse",       openssl_dsa_parse},

  {"__gc",        openssl_dsa_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

static luaL_Reg R[] =
{
  {NULL, NULL}
};

int luaopen_dsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.dsa",     dsa_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  return 1;
}
