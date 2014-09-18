#include "private.h"

int openssl_newvalue(lua_State*L, void*p) {
  lua_newtable(L);
  lua_rawseti(L,LUA_REGISTRYINDEX, (int)p);
  return 0;
}

int openssl_freevalue(lua_State*L, void*p) {
  lua_pushnil(L);
  lua_rawseti(L,LUA_REGISTRYINDEX, (int)p);
  return 0;
}

int openssl_setvalue(lua_State*L, void*p, const char*field){
  lua_rawgeti(L, LUA_REGISTRYINDEX, (int)p);
  lua_pushvalue(L, -2);
  lua_remove(L, -3);
  lua_setfield(L, -2, field);
  lua_pop(L,1);
  return 0;
}

int openssl_getvalue(lua_State*L, void*p, const char*field) {
  lua_rawgeti(L, LUA_REGISTRYINDEX, (int)p);
  if (!lua_isnil(L, -1)){
    lua_getfield(L, -1, field);
    lua_remove(L, -2);
  }
  return 0;
}
