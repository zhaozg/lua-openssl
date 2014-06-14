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

const EVP_MD* get_digest(lua_State* L, int idx){
	const EVP_MD* md = NULL;
	if (lua_isstring(L,idx))
		md = EVP_get_digestbyname(lua_tostring(L,idx));
	else if(lua_isnumber(L,idx))
		md = EVP_get_digestbynid(lua_tointeger(L,idx));
	else if(auxiliar_isclass(L,"openssl.asn1_object",idx))
		md = EVP_get_digestbyobj(CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object"));
	else if(auxiliar_isclass(L,"openssl.evp_digest",idx))
		md = CHECK_OBJECT(idx, EVP_MD, "openssl.evp_digest");
	else
	{
		luaL_error(L, "argument #1 must be a string, NID number or ans1_object identify digest method");
	}

	return md;
}

BIGNUM *BN_get(lua_State *L, int i)
{
	BIGNUM *x=BN_new();
	switch (lua_type(L,i))
	{
	case LUA_TNUMBER:
		BN_set_word(x,lua_tointeger(L,i));
		break;
	case LUA_TSTRING:
		{
			const char *s=lua_tostring(L,i);
			if (s[0]=='X' || s[0]=='x') BN_hex2bn(&x,s+1); else BN_dec2bn(&x,s);
			break;
		}
	case LUA_TUSERDATA:
		BN_copy(x,CHECK_OBJECT(i, BIGNUM, "openssl.bn"));
	}
	if(BN_is_zero(x))
	{
		BN_free(x);
		x = NULL;
	}else
		luaL_argerror(L, i, "fail convert to openssl.bn");

	return x;
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
