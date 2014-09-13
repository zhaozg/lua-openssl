#if !defined( __COMPAT_H__)
#define __COMPAT_H__ 1

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#if LUA_VERSION_NUM >= 502 // lua 5.2

// lua_rawgetp
// lua_rawsetp
// luaL_setfuncs
// lua_absindex
#ifndef lua_objlen
#define lua_objlen      lua_rawlen
#endif

int   luaL_typerror (lua_State *L, int narg, const char *tname);
#ifndef luaL_register
void luaL_register (lua_State *L, const char *libname, const luaL_Reg *l);
#endif

#else                      // lua 5.1

// functions form lua 5.2
void  lua_rawgetp   (lua_State *L, int index, const void *p);
void  lua_rawsetp   (lua_State *L, int index, const void *p);
void  luaL_setfuncs  (lua_State *L, const luaL_Reg *l, int nup);

# define lua_absindex(L, i) (((i)>0)?(i):((i)<=LUA_REGISTRYINDEX?(i):(lua_gettop(L)+(i)+1)))
# define lua_rawlen  lua_objlen

#define lua_pushglobaltable(L) lua_pushvalue( L, LUA_GLOBALSINDEX)
#define lua_setuservalue lua_setfenv
#define lua_getuservalue lua_getfenv
#define luaG_registerlibfuncs( L, _funcs) luaL_register( L, NULL, _funcs)

#define LUA_OK 0
#define LUA_ERRGCMM 666 // doesn't exist in Lua 5.1, we don't care about the actual value

void luaL_requiref (lua_State* L, const char* modname, lua_CFunction openf, int glb); // implementation copied from Lua 5.2 sources
int luaL_getmetafield (lua_State *L, int obj, const char *event);
int luaL_callmeta (lua_State *L, int obj, const char *event);

#endif

// wrap Lua 5.2 calls under Lua 5.1 API when it is simpler that way
#if LUA_VERSION_NUM == 502
#ifndef lua_equal // already defined when compatibility is active in luaconf.h
#define lua_equal( L, a, b) lua_compare( L, a, b, LUA_OPEQ)
#endif // lua_equal
#ifndef lua_lessthan // already defined when compatibility is active in luaconf.h
#define lua_lessthan( L, a, b) lua_compare( L, a, b, LUA_OPLT)
#endif // lua_lessthan
#define luaG_registerlibfuncs( L, _funcs) luaL_setfuncs( L, _funcs, 0)
#endif // LUA_VERSION_NUM == 502

#define luaL_checktable(L, n) luaL_checktype(L, n, LUA_TTABLE)

#endif // __COMPAT_H__
