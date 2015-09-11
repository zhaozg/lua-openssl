#ifndef AUXILIAR_H_EXT
#define AUXILIAR_H_EXT
#include "../deps/auxiliar/auxiliar.h"

#define AUXILIAR_SET(L,tidx, lvar, cval, ltype) \
  do {                  \
  int n = tidx < 0 ? tidx-1 : tidx;   \
  lua_push##ltype(L, (cval));       \
  lua_setfield(L, n, lvar);       \
  } while(0)

#define AUXILIAR_SETLSTR(L,tidx, lvar, cval,len)  \
  do {                  \
  int n = tidx < 0 ? tidx-1 : tidx;   \
  lua_pushlstring(L, (const char*)(cval),len);        \
  lua_setfield(L, n, lvar);       \
  } while(0)

#define AUXLIAR_GET(L,tidx, lvar, cvar, ltype)  \
  do {                  \
  lua_getfield(L, tidx, lvar);      \
  cvar = lua_to##ltype(L, -1);      \
  lua_pop(L, 1);              \
  } while(0)

typedef struct
{
  const char* name;
  int val;
} LuaL_Enum;

int auxiliar_isclass(lua_State *L, const char *classname, int objidx);
int auxiliar_isgroup(lua_State *L, const char *groupname, int objidx);

int auxiliar_checkoption(lua_State*L, int objidx, const char* def, const char* const slist[], const int ival[]);

#endif /* AUXILIAR_H_EXT */
