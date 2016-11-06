/*=========================================================================*\
* hamc.c
* hamc module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME    "hmac"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static int openssl_hmac_new(lua_State *L)
{
  const EVP_MD *type = get_digest(L, 1);
  size_t l;
  const char *k = luaL_checklstring(L, 2, &l);
  ENGINE* e = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");

  HMAC_CTX *c = HMAC_CTX_new();
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
  int raw = 0;

  if (lua_isstring(L, 2))
  {
    size_t l;
    const char *s = luaL_checklstring(L, 2, &l);
    HMAC_Update(c, (unsigned char *)s, l);
    raw = (lua_isnoneornil(L, 3)) ? 0 : lua_toboolean(L, 3);
  }
  else
    raw = (lua_isnoneornil(L, 2)) ? 0 : lua_toboolean(L, 2);

  HMAC_Final(c, digest, &len);

  if (raw)
  {
    lua_pushlstring(L, (char *)digest, len);
  }
  else
  {
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    to_hex((const char*) digest, len, hex);
    lua_pushstring(L, hex);
  }
  return 1;
}

static int openssl_hmac_reset(lua_State *L)
{
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  int ret = HMAC_Init_ex(c, NULL, 0, NULL, NULL);
  return openssl_pushresult(L, ret);
}

static int openssl_hmac_free(lua_State *L)
{
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  HMAC_CTX_free(c);
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
    size_t len;
    const char *dat = luaL_checklstring(L, 2, &len);
    size_t l;
    const char *k = luaL_checklstring(L, 3, &l);
    int raw = (lua_isnoneornil(L, 4)) ? 0 : lua_toboolean(L, 4);
    ENGINE* e = lua_isnoneornil(L, 5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");

    unsigned char digest[EVP_MAX_MD_SIZE];

    HMAC_CTX *c = HMAC_CTX_new();
    HMAC_Init_ex(c, k, (int)l, type, e);

    HMAC_Update(c, (unsigned char *)dat, len);
    len = EVP_MAX_MD_SIZE;
    HMAC_Final(c, digest, (unsigned int*)&len);

    HMAC_CTX_free(c);

    if (raw)
      lua_pushlstring(L, (char *)digest, len);
    else
    {
      char hex[2 * EVP_MAX_MD_SIZE + 1];
      to_hex((const char*)digest, len, hex);
      lua_pushstring(L, hex);
    }
  }
  return 1;
}

static luaL_Reg hmac_ctx_funs[] =
{
  {"update",  openssl_hmac_update},
  {"final",   openssl_hmac_final},
  {"close",   openssl_hmac_free},
  {"reset",   openssl_hmac_reset},

  {"__tostring",  auxiliar_tostring},
  {"__gc",    openssl_hmac_free},
  {NULL, NULL}
};

static const luaL_Reg R[] =
{
  { "__call",   openssl_hmac},
  { "new",      openssl_hmac_new},
  { "hmac",     openssl_hmac},
  { "digest",   openssl_hmac},

  {NULL,  NULL}
};

int luaopen_hmac(lua_State *L)
{
  auxiliar_newclass(L, "openssl.hmac_ctx", hmac_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
