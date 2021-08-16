#include "private.h"

int openssl_newvalue(lua_State*L,const void*p)
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

int openssl_freevalue(lua_State*L, const void*p)
{
  lua_pushnil(L);
  lua_rawsetp(L, LUA_REGISTRYINDEX, p);
  return 0;
}

int openssl_valueset(lua_State*L, const void*p, const char*field)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  lua_pushvalue(L, -2);
  lua_remove(L, -3);
  lua_setfield(L, -2, field);
  lua_pop(L, 1);
  return 0;
}

int openssl_valueget(lua_State*L, const void*p, const char*field)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (!lua_isnil(L, -1))
  {
    lua_getfield(L, -1, field);
    lua_remove(L, -2);
  }
  return lua_type(L, -1);
}

int openssl_valueseti(lua_State*L, const void*p, int i)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  lua_pushvalue(L, -2);
  lua_remove(L, -3);
  lua_rawseti(L, -2, i);
  lua_pop(L, 1);
  return 0;
}

int openssl_valuegeti(lua_State*L, const void*p, int i)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (!lua_isnil(L, -1))
  {
    lua_rawgeti(L, -1, i);
    lua_remove(L, -2);
  }
  return lua_type(L, -1);
}

int openssl_valuesetp(lua_State*L, const void*p, const void *d)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  lua_pushvalue(L, -2);
  lua_remove(L, -3);
  lua_rawsetp(L, -2, d);
  lua_pop(L, 1);
  return 0;
}

int openssl_valuegetp(lua_State*L, const void*p, const void *d)
{
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (!lua_isnil(L, -1))
  {
    lua_rawgetp(L, -1, p);
    lua_remove(L, -2);
  }
  return lua_type(L, -1);
}

int openssl_refrence(lua_State*L, const void*p, int op)
{
  int ref;
  lua_rawgetp(L, LUA_REGISTRYINDEX, p);
  if (lua_isnil(L, -1))
  {
    lua_pop(L, 1);
    return -1;
  }
  lua_getfield(L, -1, "refrence");
  ref = lua_isnil(L, -1) ? 0 : luaL_checkint(L, -1);
  lua_pop(L, 1);

  ref = ref + op;
  lua_pushinteger(L, ref);
  lua_setfield(L, -2, "refrence");
  lua_pop(L, 1);
  return ref;
}
