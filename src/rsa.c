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
  return 0;
};

static int is_private(const RSA* rsa)
{
  if (NULL == rsa->p || NULL == rsa->q)
  {
    return 0;
  }
  return 1;
};

static LUA_FUNCTION(openssl_rsa_isprivate)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  lua_pushboolean(L, is_private(rsa));
  return 1;
};

static LUA_FUNCTION(openssl_rsa_encrypt)
{
  RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
  size_t l;
  const unsigned char* from = (const unsigned char *)luaL_checklstring(L, 2, &l);
  int padding = openssl_get_padding(L, 3, "pkcs1");
  unsigned char* to = OPENSSL_malloc(RSA_size(rsa));
  int flen = l;

  flen = is_private(rsa)
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
  unsigned char* to = OPENSSL_malloc(RSA_size(rsa));
  int flen = l;

  flen = is_private(rsa)
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
  {"isprivate",   openssl_rsa_isprivate},
  {"encrypt",     openssl_rsa_encrypt},
  {"decrypt",     openssl_rsa_decrypt},

  {"__gc",        openssl_rsa_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

static luaL_Reg R[] =
{
  {"parse",       openssl_rsa_parse},
  {"isprivate",   openssl_rsa_isprivate},
  {"encrypt",     openssl_rsa_encrypt},
  {"decrypt",     openssl_rsa_decrypt},

  {NULL, NULL}
};

int luaopen_rsa(lua_State *L)
{
  auxiliar_newclass(L, "openssl.rsa",     rsa_funs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
