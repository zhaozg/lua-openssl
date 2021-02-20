/*=========================================================================*\
* dsa.c
* DSA routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/dsa.h>
#include <openssl/engine.h>

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

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  lua_pushinteger(L, DSA_size(dsa));
  lua_setfield(L, -2, "size");
#endif

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

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
static int openssl_dsa_set_method(lua_State *L)
{
#ifndef OPENSSL_NO_ENGINE
  DSA* dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
  ENGINE *e = CHECK_OBJECT(2, ENGINE, "openssl.engine");
  const DSA_METHOD *m = ENGINE_get_DSA(e);
  if (m)
  {
    int r = DSA_set_method(dsa, m);
    return openssl_pushresult(L, r);
  }
#endif
  return 0;
}
#endif

static luaL_Reg dsa_funs[] =
{
  {"parse",       openssl_dsa_parse},
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  {"set_method",  openssl_dsa_set_method},
#endif

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

  return 1;
}
