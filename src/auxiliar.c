#include "../deps/auxiliar/auxiliar.c"

#if LUA_VERSION_NUM==501
#define lua_rawlen lua_strlen
#define luaL_typeerror luaL_typerror
#endif
/*=========================================================================*\
* Exported functions
\*=========================================================================*/

int auxiliar_isclass(lua_State *L, const char *classname, int objidx)
{
  void *p = lua_touserdata(L, objidx);
  if (p != NULL)    /* value is a userdata? */
  {
    if (lua_getmetatable(L, objidx))    /* does it have a metatable? */
    {
      lua_getfield(L, LUA_REGISTRYINDEX, classname);  /* get correct metatable */
      if (lua_rawequal(L, -1, -2))    /* does it have the correct mt? */
      {
        lua_pop(L, 2);  /* remove both metatables */
        return 1;
      }
      else
        lua_pop(L, 2);
    }
  }
  return 0;
}

int auxiliar_isgroup(lua_State *L, const char *groupname, int objidx)
{
  void *data = auxiliar_getgroupudata(L, groupname, objidx);
  return data != NULL;
}

int auxiliar_checkoption(lua_State*L, int objidx, const char* def, const char* const slist[], const int ival[])
{
  int at = luaL_checkoption(L, objidx, def, slist);
  return ival[at];
}
