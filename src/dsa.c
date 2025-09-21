/*=========================================================================*\
* dsa.c
* DSA routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

/***
dsa module for lua-openssl binding

Digital Signature Algorithm (DSA) is a Federal Information Processing
Standard for digital signatures. DSA is used for digital signing and
signature verification. The module provides functionality for DSA key
generation, signature creation and verification.

@module dsa
@usage
  dsa = require('openssl').dsa
*/
#include <openssl/dsa.h>
#include <openssl/engine.h>

#include "openssl.h"
#include "private.h"

#if !defined(OPENSSL_NO_DSA)
static int openssl_dsa_free(lua_State *L)
{
  DSA *dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
  DSA_free(dsa);
  return 0;
};

/***
parse DSA key parameters and components
@function parse
@treturn table DSA parameters including bits, p, q, g, public key, and private key (if present)
*/
static int openssl_dsa_parse(lua_State *L)
{
  const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *pri = NULL;
  DSA          *dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
  lua_newtable(L);

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

/***
set engine for DSA operations
@function set_engine
@tparam engine engine the engine to use for DSA operations
@treturn boolean true on success, false on failure
*/
static int
openssl_dsa_set_engine(lua_State *L)
{
#ifndef OPENSSL_NO_ENGINE
  DSA              *dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
  ENGINE           *e = CHECK_OBJECT(2, ENGINE, "openssl.engine");
  const DSA_METHOD *m = ENGINE_get_DSA(e);
  if (m) {
    int r = DSA_set_method(dsa, m);
    return openssl_pushresult(L, r);
  }
#endif
  return 0;
}

/***
generate DSA key pair with specified parameters
@function generate_key
@tparam[opt=1024] number bits key size in bits
@tparam[opt] string seed random seed for parameter generation
@tparam[opt] engine eng engine to use for key generation
@treturn dsa|nil generated DSA key pair or nil on error
*/
static int
openssl_dsa_generate_key(lua_State *L)
{
  int         bits = luaL_optint(L, 1, 1024);
  size_t      seed_len = 0;
  const char *seed = luaL_optlstring(L, 2, NULL, &seed_len);
  ENGINE     *eng = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");

  DSA *dsa = eng ? DSA_new_method(eng) : DSA_new();
  int  ret = DSA_generate_parameters_ex(dsa, bits, (byte *)seed, seed_len, NULL, NULL, NULL);
  if (ret == 1) ret = DSA_generate_key(dsa);
  if (ret == 1) {
    PUSH_OBJECT(dsa, "openssl.dsa");
    return 1;
  }
  DSA_free(dsa);
  return openssl_pushresult(L, ret);
}

static luaL_Reg dsa_funs[] = {
  { "parse",      openssl_dsa_parse      },
  { "set_engine", openssl_dsa_set_engine },

  { "__gc",       openssl_dsa_free       },
  { "__tostring", auxiliar_tostring      },

  { NULL,         NULL                   }
};

static luaL_Reg R[] = {
  { "generate_key", openssl_dsa_generate_key },

  { NULL,           NULL                     }
};

int
luaopen_dsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.dsa", dsa_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  return 1;
}
#endif
