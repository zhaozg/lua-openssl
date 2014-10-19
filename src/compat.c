
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#ifdef LUA_JITLIBNAME
#define LUAI_UINT32 unsigned int
#define LUAI_INT32  int
#endif

#include "lua-compat/c-api/compat-5.2.c"
