/*=========================================================================*\
* misc.h
* misc routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"


const char* format[] = {
	"auto",
	"der",
	"pem",
	"smime",
	NULL
};

BIO* load_bio_object(lua_State* L, int idx) {
	BIO* bio = NULL;
	if(lua_isstring(L, idx))
	{
		size_t l = 0;
		const char* ctx = lua_tolstring(L, idx, &l);
		bio = BIO_new_mem_buf((void*)ctx, l);
	}else if(auxiliar_isclass(L,"openssl.bio", idx))
	{
		bio = CHECK_OBJECT(idx,BIO, "openssl.bio");
		bio->references++;
	}else
		luaL_argerror(L, idx, "only support string or openssl.bio");
	return bio;
}

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
