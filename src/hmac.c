/*=========================================================================*\
* hamc.c
* hamc module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include <openssl/hmac.h>

#define MYNAME    "hmac"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE      "hmac"

static int openssl_hmac_new(lua_State *L)
{
  const EVP_MD *type = get_digest(L, 1);
  size_t l;
  const char *k = luaL_checklstring(L, 2, &l);
  ENGINE* e = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");

  HMAC_CTX *c = OPENSSL_malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(c);
  HMAC_Init_ex(c, k, (int)l, type, e);
  PUSH_OBJECT(c, "openssl.hmac_ctx");

  return 1;
}

static int openssl_hmac_update(lua_State *L)
{
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  size_t l;
  const char *s = luaL_checklstring(L, 2, &l);

  HMAC_Update(c, (unsigned char *)s, l);
  return 0;
}

static int openssl_hmac_final(lua_State *L)
{
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len = 0;

  if (lua_isstring(L, 2))
  {
    size_t l;
    const char *s = luaL_checklstring(L, 2, &l);
    HMAC_Update(c, (unsigned char *)s, l);
  }

  HMAC_Final(c, digest, &len);
  lua_pushlstring(L, (char *)digest, len);
  return 1;
}

static int openssl_hmac_free(lua_State *L)
{
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  HMAC_CTX_cleanup(c);
  OPENSSL_free(c);
  return 0;
}

static int openssl_hmac(lua_State *L)
{
  if (lua_istable(L, 1))
  {
    if (lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
    {
      lua_pop(L, 1);
      lua_remove(L, 1);
    }
    else
      luaL_error(L, "call function with invalid state");
  }
  {

    const EVP_MD *type = get_digest(L, 1);
    size_t l;
    const char *k = luaL_checklstring(L, 2, &l);
    size_t len;
    const char *dat = luaL_checklstring(L, 3, &len);
    ENGINE* e = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");

    unsigned char digest[EVP_MAX_MD_SIZE];
    HMAC_CTX ctx;
    HMAC_CTX *c = &ctx;
    HMAC_CTX_init(c);
    HMAC_Init_ex(c, k, (int)l, type, e);

    HMAC_Update(c, (unsigned char *)dat, len);
    len = EVP_MAX_MD_SIZE;
    HMAC_Final(c, digest, &len);

    HMAC_CTX_cleanup(c);

    lua_pushlstring(L, (char *)digest, len);

  }
  return 1;
}

static luaL_Reg hmac_ctx_funs[] =
{
  {"update",    openssl_hmac_update},
  {"final",   openssl_hmac_final},

  {"__tostring",  auxiliar_tostring},
  {"__gc",    openssl_hmac_free},
  {NULL, NULL}
};

static const luaL_Reg R[] =
{
  { "__call",  openssl_hmac},
  { "new",   openssl_hmac_new},
  { "hmac",  openssl_hmac},

  {NULL,  NULL}
};

LUALIB_API int luaopen_hmac(lua_State *L)
{
  ERR_load_crypto_strings();

  auxiliar_newclass(L, "openssl.hmac_ctx", hmac_ctx_funs);

  luaL_newmetatable(L, MYTYPE);
  lua_setglobal(L, MYNAME);
  luaL_register(L, MYNAME, R);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  return 1;
}

