/*
 * ###############################################################################################
 * ######################################### Lua 5.1/5.2 #########################################
 * ###############################################################################################
 */
#include "compat.h"

#if LUA_VERSION_NUM >= 502 

int luaL_typerror (lua_State *L, int narg, const char *tname) {
  const char *msg = lua_pushfstring(L, "%s expected, got %s", tname,
      luaL_typename(L, narg));
  return luaL_argerror(L, narg, msg);
}

#ifndef luaL_register

void luaL_register (lua_State *L, const char *libname, const luaL_Reg *l){
  if(libname) lua_newtable(L);
  luaL_setfuncs(L, l, 0);
}

#endif

#else 

static int luaL_getsubtable (lua_State *L, int idx, const char *fname)
{
  lua_getfield(L, idx, fname);
  if (lua_istable(L, -1))
    return 1;  /* table already there */
  else
  {
    lua_pop(L, 1);  /* remove previous result */
    idx = lua_absindex(L, idx);
    lua_newtable(L);
    lua_pushvalue(L, -1);  /* copy to be left at top */
    lua_setfield(L, idx, fname);  /* assign new table to field */
    return 0;  /* false, because did not find table there */
  }
}

void luaL_requiref (lua_State *L, const char *modname, lua_CFunction openf, int glb)
{
  lua_pushcfunction(L, openf);
  lua_pushstring(L, modname);  /* argument to open function */
  lua_call(L, 1, 1);  /* open module */
  luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED");
  lua_pushvalue(L, -2);  /* make copy of module (call result) */
  lua_setfield(L, -2, modname);  /* _LOADED[modname] = module */
  lua_pop(L, 1);  /* remove _LOADED table */
  if (glb)
  {
    lua_pushvalue(L, -1);  /* copy of 'mod' */
    lua_setglobal(L, modname);  /* _G[modname] = module */
  }
}

void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup){
  luaL_checkstack(L, nup, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -nup);
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_setfield(L, -(nup + 2), l->name);
  }
  lua_pop(L, nup);  /* remove upvalues */
}

void lua_rawgetp(lua_State *L, int index, const void *p){
  index = lua_absindex(L, index);
  lua_pushlightuserdata(L, (void *)p);
  lua_rawget(L, index);
}

void lua_rawsetp (lua_State *L, int index, const void *p){
  index = lua_absindex(L, index);
  lua_pushlightuserdata(L, (void *)p);
  lua_insert(L, -2);
  lua_rawset(L, index);
}

int luaL_getmetafield (lua_State *L, int obj, const char *event) {
  if (!lua_getmetatable(L, obj))  /* no metatable? */
    return 0;
  lua_pushstring(L, event);
  lua_rawget(L, -2);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 2);  /* remove metatable and metafield */
    return 0;
  }
  else {
    lua_remove(L, -2);  /* remove only metatable */
    return 1;
  }
}

int luaL_callmeta (lua_State *L, int obj, const char *event) {
  obj = lua_absindex(L, obj);
  if (!luaL_getmetafield(L, obj, event))  /* no metafield? */
    return 0;
  lua_pushvalue(L, obj);
  lua_call(L, 1, 1);
  return 1;
}

#endif
