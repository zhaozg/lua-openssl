#include "private.h"

int openssl_newvalue(lua_State*L, void*p)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (lua_isnil(L, -1))
  {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_rawsetp(L, LUA_REGISTRYINDEX, p);
  }
  else
    lua_pop(L, 1);
  return 0;
}

int openssl_freevalue(lua_State*L, void*p)
{
  lua_pushnil(L);
  lua_rawsetp(L, LUA_REGISTRYINDEX, p);
  return 0;
}

int openssl_setvalue(lua_State*L, void*p, const char*field)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  lua_pushvalue(L, -2);
  lua_remove(L, -3);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
  return 0;
}

int openssl_getvalue(lua_State*L, void*p, const char*field)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (!lua_isnil(L, -1))
  {
    lua_getfield(L, -1, field);
    lua_remove(L, -2);
  }
  return 0;
}

int openssl_refrence(lua_State*L, void*p, int op)
{
  int ref;
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  lua_getfield(L, -1, "refrence");
  ref = lua_isnil(L, -1) ? 0 : luaL_checkint(L, -1);
  lua_pop(L, 1);
  if (ref >= 0 && op == 1)
  {
    ref = ref + 1;
    lua_pushinteger(L, ref);
    lua_setfield(L, -2, "refrence");
  }
  else if (ref > 0 && op == -1)
  {
    ref = ref - 1;
    lua_pushinteger(L, ref);
    lua_setfield(L, -2, "refrence");
  }
  else if (op != 0)
    luaL_error(L, "lua-openssl internal error");
  lua_pop(L, 1);
  return ref;
}
