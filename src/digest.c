/*=========================================================================*\
* digest.c
* digest module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME    "digest"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static LUA_FUNCTION(openssl_digest_list)
{
  int aliases = lua_isnoneornil(L, 1) ? 1 : lua_toboolean(L, 1);
  lua_newtable(L);
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, aliases ? openssl_add_method_or_alias : openssl_add_method, L);
  return 1;
};

static LUA_FUNCTION(openssl_digest_get)
{
  const EVP_MD* md = get_digest(L, 1);

  if (md)
    PUSH_OBJECT((void*)md, "openssl.evp_digest");
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_digest_new)
{
  const EVP_MD* md = get_digest(L, 1);
  if (md)
  {
    int ret;
    ENGINE* e =  (!lua_isnoneornil(L, 2)) ? CHECK_OBJECT(2, ENGINE, "openssl.engine") : NULL;
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    ret = EVP_DigestInit_ex(ctx, md, e);
    if (ret == 1)
    {
      PUSH_OBJECT(ctx, "openssl.evp_digest_ctx");
    }
    else
    {
      EVP_MD_CTX_destroy(ctx);
      return openssl_pushresult(L, ret);
    }
  }
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_digest)
{
  const EVP_MD *md = NULL;
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
  if (lua_isstring(L, 1))
  {
    md = EVP_get_digestbyname(lua_tostring(L, 1));
  }
  else if (auxiliar_isclass(L, "openssl.evp_digest", 1))
  {
    md = CHECK_OBJECT(1, EVP_MD, "openssl.evp_digest");
  }
  else
    luaL_error(L, "argument #1 must be a string identity digest method or an openssl.evp_digest object");

  if (md)
  {
    size_t inl;
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int  blen = sizeof(buf);
    const char* in = luaL_checklstring(L, 2, &inl);
    int raw = (lua_isnoneornil(L, 3)) ? 0 : lua_toboolean(L, 3);
    int status = EVP_Digest(in, inl, buf, &blen, md, NULL);
    if (status)
    {
      if (raw)
        lua_pushlstring(L, (const char*)buf, blen);
      else
      {
        char hex[2 * EVP_MAX_MD_SIZE + 1];
        to_hex(buf, blen, hex);
        lua_pushstring(L, hex);
      }
    }
    else
      luaL_error(L, "EVP_Digest method fail");
  }
  else
    luaL_error(L, "argument #1 is not a valid digest algorithm or openssl.evp_digest object");
  return 1;
};

/*** evp_digest method ***/
static LUA_FUNCTION(openssl_digest_digest)
{
  size_t inl;
  EVP_MD *md = CHECK_OBJECT(1, EVP_MD, "openssl.evp_digest");
  const char* in = luaL_checklstring(L, 2, &inl);
  ENGINE*     e = (!lua_isnoneornil(L, 3)) ? CHECK_OBJECT(3, ENGINE, "openssl.engine") : NULL;

  char buf[EVP_MAX_MD_SIZE];
  unsigned int  blen = EVP_MAX_MD_SIZE;

  int status = EVP_Digest(in, inl, (unsigned char*)buf, &blen, md, e);
  if (status)
  {
    lua_pushlstring(L, buf, blen);
  }
  else
    luaL_error(L, "EVP_Digest method fail");
  return 1;
}

static LUA_FUNCTION(openssl_digest_info)
{
  EVP_MD *md = CHECK_OBJECT(1, EVP_MD, "openssl.evp_digest");
  lua_newtable(L);
  AUXILIAR_SET(L, -1, "nid", EVP_MD_nid(md), integer);
  AUXILIAR_SET(L, -1, "name", EVP_MD_name(md), string);
  AUXILIAR_SET(L, -1, "size", EVP_MD_size(md), integer);
  AUXILIAR_SET(L, -1, "block_size", EVP_MD_block_size(md), integer);

  AUXILIAR_SET(L, -1, "pkey_type", EVP_MD_pkey_type(md), integer);
  AUXILIAR_SET(L, -1, "flags", EVP_MD_type(md), integer);
  return 1;
}

static LUA_FUNCTION(openssl_evp_digest_init)
{
  EVP_MD* md = CHECK_OBJECT(1, EVP_MD, "openssl.evp_digest");
  ENGINE*     e = lua_gettop(L) > 1 ? CHECK_OBJECT(2, ENGINE, "openssl.engine") : NULL;

  EVP_MD_CTX* ctx = EVP_MD_CTX_create();
  if (ctx)
  {
    int ret;
    EVP_MD_CTX_init(ctx);
    ret = EVP_DigestInit_ex(ctx, md, e);
    if (ret == 1)
    {
      PUSH_OBJECT(ctx, "openssl.evp_digest_ctx");
    }
    else
    {
      EVP_MD_CTX_destroy(ctx);
      return openssl_pushresult(L, ret);
    }
  }
  else
    lua_pushnil(L);
  return 1;
}

/** openssl.evp_digest_ctx method */

static LUA_FUNCTION(openssl_digest_ctx_info)
{
  EVP_MD_CTX *ctx = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  lua_newtable(L);
  AUXILIAR_SET(L, -1, "block_size", EVP_MD_CTX_block_size(ctx), integer);
  AUXILIAR_SET(L, -1, "size", EVP_MD_CTX_size(ctx), integer);
  AUXILIAR_SET(L, -1, "type", EVP_MD_CTX_type(ctx), integer);

  AUXILIAR_SETOBJECT(L, EVP_MD_CTX_md(ctx), "openssl.evp_digest", -1, "digest");
  return 1;
}


static LUA_FUNCTION(openssl_evp_digest_update)
{
  size_t inl;
  EVP_MD_CTX* c = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  const char* in = luaL_checklstring(L, 2, &inl);

  int ret = EVP_DigestUpdate(c, in, inl);

  lua_pushboolean(L, ret);
  return 1;
}

static LUA_FUNCTION(openssl_evp_digest_final)
{
  EVP_MD_CTX* c = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  EVP_MD_CTX* d = EVP_MD_CTX_create();

  int ret;
  int raw = 0;

  if (lua_isstring(L, 2))
  {
    size_t inl;
    const char* in = luaL_checklstring(L, 2, &inl);
    ret = EVP_DigestUpdate(c, in, inl);
    if (!ret)
    {
      EVP_MD_CTX_destroy(d);
      return openssl_pushresult(L, ret);
    }
    raw = (lua_isnoneornil(L, 3)) ? 0 : lua_toboolean(L, 3);
  }
  else
    raw = (lua_isnoneornil(L, 2)) ? 0 : lua_toboolean(L, 2);

  EVP_MD_CTX_init(d);
  ret = EVP_MD_CTX_copy_ex(d, c);
  if (ret == 1)
  {
    byte out[EVP_MAX_MD_SIZE];
    unsigned int outl = sizeof(out);
    ret = EVP_DigestFinal_ex(d, (byte*)out, &outl);
    if (ret == 1)
    {
      if (raw)
      {
        lua_pushlstring(L, (const char*)out, outl);
      }
      else
      {
        char hex[2 * EVP_MAX_MD_SIZE + 1];
        to_hex(out, outl, hex);
        lua_pushstring(L, hex);
      }
      EVP_MD_CTX_destroy(d);
      return 1;
    }
  }
  EVP_MD_CTX_destroy(d);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_digest_ctx_free)
{
  EVP_MD_CTX *ctx = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  EVP_MD_CTX_destroy(ctx);
  return 0;
}

static LUA_FUNCTION(openssl_digest_ctx_reset)
{
  EVP_MD_CTX *ctx = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  const EVP_MD *md = EVP_MD_CTX_md(ctx);
  ENGINE* e = ctx->engine;
  int ret = EVP_MD_CTX_cleanup(ctx);
  if (ret)
  {
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, e);
  }
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_digest_ctx_clone)
{
  EVP_MD_CTX *ctx = CHECK_OBJECT(1, EVP_MD_CTX, "openssl.evp_digest_ctx");
  EVP_MD_CTX *d = EVP_MD_CTX_create();
  if (d)
  {
    int ret;
    EVP_MD_CTX_init(d);
    ret = EVP_MD_CTX_copy_ex(d, ctx);
    if (ret == 1)
    {
      PUSH_OBJECT(d, "openssl.evp_digest_ctx");
      return 1;
    }
    EVP_MD_CTX_destroy(d);
    return openssl_pushresult(L, ret);
  }
  else
    lua_pushnil(L);

  return 1;
}


static luaL_Reg digest_funs[] =
{
  {"new",       openssl_evp_digest_init},
  {"info",      openssl_digest_info},
  {"digest",      openssl_digest_digest},
  {"__tostring",    auxiliar_tostring},

  {NULL, NULL}
};

static luaL_Reg digest_ctx_funs[] =
{
  {"update",      openssl_evp_digest_update},
  {"final",       openssl_evp_digest_final},
  {"info",        openssl_digest_ctx_info},
  {"clone",       openssl_digest_ctx_clone},
  {"reset",       openssl_digest_ctx_reset},
  {"close",       openssl_digest_ctx_free},

  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_digest_ctx_free},
  {NULL, NULL}
};

static const luaL_Reg R[] =
{
  { "__call",  openssl_digest},
  { "list",    openssl_digest_list},
  { "get",   openssl_digest_get},
  { "new",   openssl_digest_new},
  { "digest",  openssl_digest},

  {NULL,  NULL}
};

int luaopen_digest(lua_State *L)
{
  auxiliar_newclass(L, "openssl.evp_digest",   digest_funs);
  auxiliar_newclass(L, "openssl.evp_digest_ctx", digest_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
