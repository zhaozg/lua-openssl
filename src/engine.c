/*=========================================================================*\
* engine.c
* engine object for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include <openssl/engine.h>
#include "openssl.h"

enum
{
  TYPE_RSA,
  TYPE_DSA,
  TYPE_ECDH,
  TYPE_ECDSA,
  TYPE_DH,
  TYPE_RAND,
  TYPE_STORE,
  TYPE_CIPHERS,
  TYPE_DIGESTS,
  TYPE_COMPLETE
};

static const char* const list[] =
{
  "RSA",      /* 0 */
  "DSA",
  "ECDH",     /* 2 */
  "ECDSA",
  "DH",       /* 4 */
  "RAND",
  "STORE",    /* 6 */
  "ciphers",
  "digests",  /* 8 */
  "complete", /* 9 */

  NULL
};

int openssl_engine(lua_State *L)
{
  const ENGINE* eng = NULL;
  if (lua_isnoneornil(L, 1))
  {
    eng = ENGINE_new();
  }
  else if (lua_isstring(L, 1))
  {
    const char* id = luaL_checkstring(L, 1);
    eng = ENGINE_by_id(id);
  }
  else if (lua_isboolean(L, 1))
  {
    int first = lua_toboolean(L, 1);
    if (first)
      eng = ENGINE_get_first();
    else
      eng = ENGINE_get_last();
  }
  else
    luaL_error(L,
               "#1 may be string, boolean, nil, userdata for engine or none\n"
               "\tstring for an engine id to load\n"
               "\ttrue for first engine, false or last engine\n"
               "\tnil or none will create a new engine\n"
               "\tbut we get %s:%s", lua_typename(L, lua_type(L,  1)), lua_tostring(L, 1));
  if (eng)
  {
    PUSH_OBJECT((void*)eng, "openssl.engine");
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_engine_next(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  eng = ENGINE_get_next(eng);
  if (eng)
  {
    PUSH_OBJECT(eng, "openssl.engine");
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_engine_prev(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  eng = ENGINE_get_prev(eng);
  if (eng)
  {
    PUSH_OBJECT(eng, "openssl.engine");
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_engine_add(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = ENGINE_add(eng);
  lua_pushboolean(L, ret);
  return 1;
}

static int openssl_engine_remove(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = ENGINE_remove(eng);
  lua_pushboolean(L, ret);
  return 1;
}

static int openssl_engine_register(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int unregister = 0;
  int first = 2;
  int top = lua_gettop(L);
  if (lua_isboolean(L, 2))
  {
    unregister = lua_toboolean(L, 2);
    first = 3;
  };
  while (first <= top)
  {
    int c = luaL_checkoption(L, first, "RSA", list);
    switch (c)
    {
    case TYPE_RSA:
      if (unregister)
        ENGINE_unregister_RSA(eng);
      else
        ENGINE_register_RSA(eng);
      break;
    case TYPE_DSA:
      if (unregister)
        ENGINE_unregister_DSA(eng);
      else
        ENGINE_register_DSA(eng);
      break;
    case TYPE_ECDH:
      if (unregister)
        ENGINE_unregister_ECDH(eng);
      else
        ENGINE_register_ECDH(eng);
      break;
    case TYPE_ECDSA:
      if (unregister)
        ENGINE_unregister_ECDSA(eng);
      else
        ENGINE_register_ECDSA(eng);
      break;
    case TYPE_DH:
      if (unregister)
        ENGINE_unregister_DH(eng);
      else
        ENGINE_register_DH(eng);
      break;
    case TYPE_RAND:
      if (unregister)
        ENGINE_unregister_RAND(eng);
      else
        ENGINE_register_RAND(eng);
      break;
    case TYPE_STORE:
      if (unregister)
        ENGINE_unregister_STORE(eng);
      else
        ENGINE_register_STORE(eng);
      break;
    case TYPE_CIPHERS:
      if (unregister)
        ENGINE_unregister_ciphers(eng);
      else
        ENGINE_register_ciphers(eng);
      break;
    case TYPE_DIGESTS:
      if (unregister)
        ENGINE_unregister_digests(eng);
      else
        ENGINE_register_digests(eng);
      break;
    case TYPE_COMPLETE:
    {
      int ret = ENGINE_register_complete(eng);
      lua_pushboolean(L, ret);
      return 1;
      break;
    }
    default:
      luaL_error(L, "not support %d for %s", c, list[c]);
      break;
    }
    first++;
  }
  return 0;
};

static int openssl_engine_ctrl(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");

  if (lua_isnumber(L, 2))
  {
    int cmd = luaL_checkinteger(L, 2);
    if (lua_isnoneornil(L, 3))
    {
      int ret = ENGINE_cmd_is_executable(eng, cmd);
      lua_pushboolean(L, ret);
    }
    else
    {
      long i = (long)luaL_checknumber(L, 3);
      void* p = lua_touserdata(L, 4);
      int ret = ENGINE_ctrl(eng, cmd, i, p, NULL);
      lua_pushboolean(L, ret);
    }
  }
  else
  {
    const char* cmd = luaL_checkstring(L, 2);
    if (lua_isnumber(L, 3))
    {
      long i = (long)luaL_checknumber(L, 3);
      void* p = lua_touserdata(L, 4);
      int opt = luaL_optinteger(L, 5, 0);
      int ret = ENGINE_ctrl_cmd(eng, cmd, i, p, NULL, opt);
      lua_pushboolean(L, ret);
    }
    else
    {
      const char* arg  = luaL_optstring(L, 3, NULL);
      int opt = luaL_optinteger(L, 4, 0);
      int ret = ENGINE_ctrl_cmd_string(eng, cmd, arg, opt);
      lua_pushboolean(L, ret);
    }
  }
  return 1;
}

static int openssl_engine_gc(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  ENGINE_free(eng);
  return 0;
}


static int openssl_engine_id(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  const char*id = NULL;
  int ret = 0;
  if (lua_isstring(L, 2))
  {
    id = luaL_checkstring(L, 2);
    ret = ENGINE_set_id(eng, id);
    lua_pushboolean(L, ret);
    return 1;
  }
  lua_pushstring(L, ENGINE_get_id(eng));
  return 1;
}


static int openssl_engine_name(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  const char*id = NULL;
  int ret = 0;
  if (lua_isstring(L, 2))
  {
    id = luaL_checkstring(L, 2);
    ret = ENGINE_set_name(eng, id);
    lua_pushboolean(L, ret);
    return 1;
  }
  lua_pushstring(L, ENGINE_get_name(eng));
  return 1;
}


static int openssl_engine_flags(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = 0;
  if (lua_isstring(L, 2))
  {
    int flags = luaL_checkinteger(L, 2);
    ret = ENGINE_set_flags(eng, flags);
    lua_pushboolean(L, ret);
    return 1;
  }
  lua_pushinteger(L, ENGINE_get_flags(eng));
  return 1;
}
/*
int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg);
void *ENGINE_get_ex_data(const ENGINE *e, int idx);
*/

static int openssl_engine_init(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = ENGINE_init(eng);
  lua_pushboolean(L, ret);
  return 1;
}


static int openssl_engine_finish(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = ENGINE_finish(eng);
  lua_pushboolean(L, ret);
  return 1;
}


static int openssl_engine_set_default(lua_State*L)
{
  ENGINE* eng = CHECK_OBJECT(1, ENGINE, "openssl.engine");
  int ret = 0;
  int first = 3;
  int top = lua_gettop(L);
  if (top == 2)
  {
    if (lua_isnumber(L, 2))
    {
      int methods = luaL_checkinteger(L, 2);
      ret = ENGINE_set_default(eng, methods);
    }
    else if (lua_isstring(L, 2))
    {
      const char* s = luaL_checkstring(L, 2);
      ret = ENGINE_set_default_string(eng, s);
    }
    else
      luaL_error(L, "#2 must be a number or string");
    lua_pushboolean(L, ret);
    return 1;
  }

  while (first <= top)
  {
    int c = luaL_checkoption(L, first, "RSA", list);
    switch (c)
    {
    case TYPE_RSA:
      ret = ENGINE_set_default_RSA(eng);
      break;
    case TYPE_DSA:
      ret = ENGINE_set_default_DSA(eng);
      break;
    case TYPE_ECDH:
      ret = ENGINE_set_default_ECDH(eng);
      break;
    case TYPE_ECDSA:
      ret = ENGINE_set_default_ECDSA(eng);
      break;
    case TYPE_DH:
      ret = ENGINE_set_default_DH(eng);
      break;
    case TYPE_RAND:
      ret = ENGINE_set_default_RAND(eng);
      break;
    case TYPE_CIPHERS:
      ret = ENGINE_set_default_ciphers(eng);
      break;
    case TYPE_DIGESTS:
      ret = ENGINE_set_default_digests(eng);
      break;
    default:
      luaL_error(L, "not support '%s' to set default", c, list[c]);
      break;
    }
    first++;
    if (ret != 1)
    {
      lua_pushboolean(L, 0);
      return 1;
    }
  }
  lua_pushboolean(L, ret);
  return 1;
};

static luaL_Reg eng_funcs[] =
{
  {"next",      openssl_engine_next},
  {"prev",      openssl_engine_prev},
  {"add",       openssl_engine_add},
  {"remove",      openssl_engine_remove},
  {"register",    openssl_engine_register},
  {"ctrl",      openssl_engine_ctrl},
  {"id",        openssl_engine_id},
  {"name",      openssl_engine_name},
  {"flags",     openssl_engine_flags},

  {"init",      openssl_engine_init},
  {"finish",      openssl_engine_finish},
  {"set_default",   openssl_engine_set_default},

  {"__gc",      openssl_engine_gc},
  {"__tostring",    auxiliar_tostring},

  {NULL,      NULL},
};


int openssl_register_engine(lua_State* L)
{
  auxiliar_newclass(L, "openssl.engine", eng_funcs);
  return 0;
}

