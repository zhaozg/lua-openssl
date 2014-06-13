/*=========================================================================*\
* misc.h
* misc routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg)
{
    lua_State *L = (lua_State *)arg;
    int i = lua_objlen(L,-1);
    lua_pushstring(L,name->name);
    lua_rawseti(L,-2,i+1);
}

void openssl_add_method(const OBJ_NAME *name, void *arg)
{
    if (name->alias == 0) {
        openssl_add_method_or_alias(name,arg);
    }
}
