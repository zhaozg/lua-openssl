/*=========================================================================*\
* dh.c
* DH routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/dh.h>
#include <openssl/engine.h>

static LUA_FUNCTION(openssl_dh_free)
{
  DH* dh = CHECK_OBJECT(1, DH, "openssl.dh");
  DH_free(dh);
  return 0;
};

static LUA_FUNCTION(openssl_dh_parse)
{
  const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *pri = NULL;
  DH* dh = CHECK_OBJECT(1, DH, "openssl.dh");
  lua_newtable(L);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  lua_pushinteger(L, DH_bits(dh)/8);
#else
  lua_pushinteger(L, DH_size(dh));
#endif
  lua_setfield(L, -2, "size");

  lua_pushinteger(L, DH_bits(dh));
  lua_setfield(L, -2, "bits");

  DH_get0_pqg(dh, &p, &q, &g);
  DH_get0_key(dh, &pub, &pri);

  OPENSSL_PKEY_GET_BN(p, p);
  OPENSSL_PKEY_GET_BN(q, q);
  OPENSSL_PKEY_GET_BN(g, g);
  OPENSSL_PKEY_GET_BN(pub, pub_key);
  OPENSSL_PKEY_GET_BN(pri, priv_key);

  return 1;
}

static int openssl_dh_set_method(lua_State *L)
{
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_VERSION_NUMBER < 0x30000000L
  DH* dh = CHECK_OBJECT(1, DH, "openssl.dh");
  ENGINE *e = CHECK_OBJECT(2, ENGINE, "openssl.engine");
  const DH_METHOD *m = ENGINE_get_DH(e);
  if (m)
  {
    int r = DH_set_method(dh, m);
    return openssl_pushresult(L, r);
  }
#endif
  return 0;
}

static luaL_Reg dh_funs[] =
{
  {"parse",       openssl_dh_parse},
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_VERSION_NUMBER < 0x30000000L
  {"set_method",  openssl_dh_set_method},
#endif

  {"__gc",        openssl_dh_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

static luaL_Reg R[] =
{
  {NULL, NULL}
};

int luaopen_dh(lua_State *L)
{
  auxiliar_newclass(L, "openssl.dh",     dh_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  return 1;
}
