/*=========================================================================*\
* ec.c
* RSA routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/rsa.h>
#include <openssl/engine.h>

static LUA_FUNCTION(openssl_rsa_free)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  RSA_free(rsa);
  return 0;
};

static int is_private(const RSA* rsa)
{
  const BIGNUM* d = NULL;
  RSA_get0_key(rsa, NULL, NULL, &d);
  return d != NULL && !BN_is_zero(d);
};

static LUA_FUNCTION(openssl_rsa_isprivate)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  lua_pushboolean(L, is_private(rsa));
  return 1;
};

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
static LUA_FUNCTION(openssl_rsa_size)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  lua_pushinteger(L, RSA_size(rsa));
  return 1;
};

static LUA_FUNCTION(openssl_rsa_encrypt)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  size_t l;
  const unsigned char* from = (const unsigned char *)luaL_checklstring(L, 2, &l);
  int padding = openssl_get_padding(L, 3, "pkcs1");
  int ispriv = lua_isnone(L, 4) ? is_private(rsa) : lua_toboolean(L, 4);
  unsigned char* to = OPENSSL_malloc(RSA_size(rsa));
  int flen = l;

  flen = ispriv
         ? RSA_private_encrypt(flen, from, to, rsa, padding)
         : RSA_public_encrypt(flen, from, to, rsa, padding);
  if (flen > 0)
  {
    lua_pushlstring(L, (const char*)to, flen);
    OPENSSL_free(to);
    return 1;
  }
  OPENSSL_free(to);
  return openssl_pushresult(L, flen);
};

static LUA_FUNCTION(openssl_rsa_decrypt)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  size_t l;
  const unsigned char* from = (const unsigned char *) luaL_checklstring(L, 2, &l);
  int padding = openssl_get_padding(L, 3, "pkcs1");
  int ispriv = lua_isnone(L, 4) ? is_private(rsa) : lua_toboolean(L, 4);
  unsigned char* to = OPENSSL_malloc(RSA_size(rsa));
  int flen = l;

  flen = ispriv
         ? RSA_private_decrypt(flen, from, to, rsa, padding)
         : RSA_public_decrypt(flen, from, to, rsa, padding);
  if (flen > 0)
  {
    lua_pushlstring(L, (const char*)to, flen);
    OPENSSL_free(to);
    return 1;
  }
  OPENSSL_free(to);
  return openssl_pushresult(L, flen);
};

static LUA_FUNCTION(openssl_rsa_sign)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  size_t l;
  const unsigned char* msg = (const unsigned char *)luaL_checklstring(L, 2, &l);
  int type = luaL_optint(L, 3, NID_md5_sha1);
  unsigned char* sig = OPENSSL_malloc(RSA_size(rsa));
  int flen = l;
  unsigned int slen = RSA_size(rsa);

  int ret = RSA_sign(type, msg, flen, sig, &slen, rsa);
  if (ret == 1)
  {
    lua_pushlstring(L, (const char*)sig, slen);
    OPENSSL_free(sig);
    return 1;
  }
  OPENSSL_free(sig);
  return openssl_pushresult(L, ret);
};

static LUA_FUNCTION(openssl_rsa_verify)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  size_t l;
  const unsigned char* from = (const unsigned char *)luaL_checklstring(L, 2, &l);
  size_t s;
  const unsigned char* sig = (const unsigned char *)luaL_checklstring(L, 3, &s);
  int type = luaL_optint(L, 4, NID_md5_sha1);
  int flen = l;
  int slen = s;

  int ret = RSA_verify(type, from, flen, sig, slen, rsa);
  return openssl_pushresult(L, ret);
};
#endif

static LUA_FUNCTION(openssl_rsa_parse)
{
  const BIGNUM *n = NULL, *e = NULL, *d = NULL;
  const BIGNUM *p = NULL, *q = NULL;
  const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  RSA_get0_key(rsa, &n, &e, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);


  lua_newtable(L);
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  lua_pushinteger(L, RSA_size(rsa));
  lua_setfield(L, -2, "size");
#endif
  lua_pushinteger(L, RSA_bits(rsa));
  lua_setfield(L, -2, "bits");
  OPENSSL_PKEY_GET_BN(n, n);
  OPENSSL_PKEY_GET_BN(e, e);
  OPENSSL_PKEY_GET_BN(d, d);
  OPENSSL_PKEY_GET_BN(p, p);
  OPENSSL_PKEY_GET_BN(q, q);
  OPENSSL_PKEY_GET_BN(dmp1, dmp1);
  OPENSSL_PKEY_GET_BN(dmq1, dmq1);
  OPENSSL_PKEY_GET_BN(iqmp, iqmp);
  return 1;
}

static LUA_FUNCTION(openssl_rsa_read)
{
  size_t l;
  const char* data = luaL_checklstring(L, 1, &l);
  const unsigned char* in = (const unsigned char*)data;
  RSA *rsa = d2i_RSAPrivateKey(NULL, &in, l);
  if (rsa == NULL)
  {
    in = (const unsigned char*)data;
    rsa = d2i_RSA_PUBKEY(NULL, &in, l);
  }
  if (rsa)
    PUSH_OBJECT(rsa, "openssl.rsa");
  else
    lua_pushnil(L);
  return 1;
}

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
static int openssl_rsa_set_method(lua_State *L)
{
#ifndef OPENSSL_NO_ENGINE
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  ENGINE *e = CHECK_OBJECT(2, ENGINE, "openssl.engine");
  const RSA_METHOD *m = ENGINE_get_RSA(e);
  if (m)
  {
    int r = RSA_set_method(rsa, m);
    return openssl_pushresult(L, r);
  }
#endif
  return 0;
}
#endif

static luaL_Reg rsa_funs[] =
{
  {"parse",       openssl_rsa_parse},
  {"isprivate",   openssl_rsa_isprivate},
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  {"encrypt",     openssl_rsa_encrypt},
  {"decrypt",     openssl_rsa_decrypt},
  {"sign",        openssl_rsa_sign},
  {"verify",      openssl_rsa_verify},
  {"size",        openssl_rsa_size},
  {"set_method",  openssl_rsa_set_method},
#endif

  {"__gc",        openssl_rsa_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

static luaL_Reg R[] =
{
  {"parse",       openssl_rsa_parse},
  {"isprivate",   openssl_rsa_isprivate},
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
  {"encrypt",     openssl_rsa_encrypt},
  {"decrypt",     openssl_rsa_decrypt},
  {"sign",        openssl_rsa_sign},
  {"verify",      openssl_rsa_verify},
  {"size",        openssl_rsa_size},
#endif
  {"read",        openssl_rsa_read},

  {NULL, NULL}
};

int luaopen_rsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.rsa",     rsa_funs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  return 1;
}
