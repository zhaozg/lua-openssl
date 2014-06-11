/*=========================================================================*\
* digest.c
* digest module for lua-openssl binding
* lua-openssl toolkit
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"

#define MYNAME		"digest"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"openssl.digest"

static LUA_FUNCTION(openssl_digest_list) {
	int aliases = lua_isnoneornil(L,1)?1:lua_toboolean(L,1);
	lua_newtable(L);
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, aliases ? openssl_add_method_or_alias: openssl_add_method, L);
	return 1;
};

static LUA_FUNCTION(openssl_digest_get) {
    const EVP_MD* md = NULL;

	if (lua_isstring(L,1))
        md = EVP_get_digestbyname(lua_tostring(L,1));
    else if(lua_isnumber(L,1))
        md = EVP_get_digestbynid(lua_tointeger(L,1));
    else if(auxiliar_isclass(L,"openssl.asn1_object",1))
        md = EVP_get_digestbyobj(CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object"));
    else
    {
		luaL_error(L, "argument #1 must be a string, NID number or ans1_object identify digest method");
    }

	if(md)
		PUSH_OBJECT((void*)md,"openssl.evp_digest");
	else
		lua_pushnil(L);
	return 1;
}

static LUA_FUNCTION(openssl_digest_new)
{
	const EVP_MD* md = NULL;

	if (lua_isstring(L,1))
		md = EVP_get_digestbyname(lua_tostring(L,1));
	else if(lua_isnumber(L,1))
		md = EVP_get_digestbynid(lua_tointeger(L,1));
	else if(auxiliar_isclass(L,"openssl.asn1_object",1))
		md = EVP_get_digestbyobj(CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object"));
	else
	{
		luaL_error(L, "argument #1 must be a string, NID number or ans1_object identify digest method");
	}

	if(md){
		ENGINE* e =  (!lua_isnoneornil(L,2)) ? CHECK_OBJECT(2,ENGINE,"openssl.engine") : NULL;
		EVP_MD_CTX* ctx = EVP_MD_CTX_create();
		EVP_MD_CTX_init(ctx);
		if (!EVP_DigestInit_ex(ctx,md,e)) {
			luaL_error(L,"EVP_DigestInit_ex failed");
		}
		PUSH_OBJECT(ctx,"openssl.evp_digest_ctx");
	}else
		lua_pushnil(L);
	return 1;
}

static LUA_FUNCTION(openssl_digest)
{
	const EVP_MD *md = NULL;
	if(lua_istable(L, 1)){
		if(lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
		{
			lua_pop(L, 1);
			lua_remove(L, 1);
		}else
			luaL_error(L,"call function with invalid state");
	}
	if(lua_isstring(L,1)){
		md = EVP_get_digestbyname(lua_tostring(L,1));
	}else if(auxiliar_isclass(L,"openssl.evp_digest",1))
	{
		md = CHECK_OBJECT(1, EVP_MD, "openssl.evp_digest");
	}else
		luaL_error(L, "argument #1 must be a string identify digest method or an openssl.evp_digest object");

	if(md)
	{
		size_t inl;
		char buf[MAX_PATH];
		unsigned int  blen = MAX_PATH;
		const char* in = luaL_checklstring(L,2,&inl);
		int raw = (lua_isnoneornil(L,3)) ? 0 : lua_toboolean(L,3);
		int status = EVP_Digest(in, inl, (unsigned char*)buf, &blen, md, NULL);
		if (status) {
			if(raw)
				lua_pushlstring(L,buf,blen);
			else{
				BIGNUM *B = BN_new();
				BN_bin2bn(buf,blen,B);
				in = BN_bn2hex(B);
				lua_pushstring(L,in);
				OPENSSL_free((void*)in);
				BN_free(B);
			}
		} else
			luaL_error(L,"EVP_Digest method fail");
	}else
		luaL_error(L,"argument #1 is not a valid digest algorithm or openssl.evp_digest object");
	return 1;
};

/*** evp_digest method ***/
static LUA_FUNCTION(openssl_digest_digest)
{
	size_t inl;
    EVP_MD *md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
    const char* in = luaL_checklstring(L,2,&inl);
    ENGINE*     e = (!lua_isnoneornil(L, 3)) ? CHECK_OBJECT(3,ENGINE,"openssl.engine") : NULL;

    char buf[EVP_MAX_MD_SIZE];
    unsigned int  blen = EVP_MAX_MD_SIZE;

    int status = EVP_Digest(in, inl, (unsigned char*)buf, &blen, md, e);
    if (status) {
        lua_pushlstring(L,buf,blen);
    } else
        luaL_error(L,"EVP_Digest method fail");
    return 1;
}

static LUA_FUNCTION(openssl_digest_info)
{
	EVP_MD *md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
	lua_newtable(L);
	add_assoc_int(L,"nid", EVP_MD_nid(md));
	add_assoc_string(L,"name", EVP_MD_name(md));
	add_assoc_int(L,"size", EVP_MD_size(md));
	add_assoc_int(L,"block_size", EVP_MD_block_size(md));

	add_assoc_int(L,"pkey_type", EVP_MD_pkey_type(md));
	add_assoc_int(L,"flags", EVP_MD_type(md));
	return 1;
}

static LUA_FUNCTION(openssl_evp_digest_init)
{
    EVP_MD* md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
    ENGINE*     e = lua_gettop(L)>1?CHECK_OBJECT(2,ENGINE,"openssl.engine"):NULL;

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    PUSH_OBJECT(ctx,"openssl.evp_digest_ctx");
    EVP_MD_CTX_init(ctx);

    if (!EVP_DigestInit_ex(ctx,md,e)) {
        luaL_error(L,"EVP_DigestInit_ex failed");
    }
    return 1;
}

/** openssl.evp_digest_ctx method */

static LUA_FUNCTION(openssl_digest_ctx_info)
{
	EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	lua_newtable(L);
	add_assoc_int(L,"block_size", EVP_MD_CTX_block_size(ctx));
	add_assoc_int(L,"size", EVP_MD_CTX_size(ctx));
	add_assoc_int(L,"type", EVP_MD_CTX_type(ctx));

	PUSH_OBJECT((void*)EVP_MD_CTX_md(ctx),"openssl.evp_digest");
	lua_setfield(L,-2,"digest");
	return 1;
}


static LUA_FUNCTION(openssl_evp_digest_update)
{
	size_t inl;
    EVP_MD_CTX* c = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
    const char* in= luaL_checklstring(L,2,&inl);

    int ret = EVP_DigestUpdate(c,in,inl);

    lua_pushboolean(L,ret);
    return 1;
}

static LUA_FUNCTION(openssl_evp_digest_final)
{
    EVP_MD_CTX* c = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
    unsigned int outl = EVP_MAX_MD_SIZE;
    char out[EVP_MAX_MD_SIZE];
	int ret;
	int raw = 0;
	if(lua_isstring(L,2)){
		size_t inl;
		const char* in= luaL_checklstring(L,2,&inl);
		ret = EVP_DigestUpdate(c,in,inl);
		if(!ret)
			luaL_error(L,"digest update fail");
		raw = (lua_isnoneornil(L,3)) ? 0 : lua_toboolean(L, 3);
	}else
		raw = (lua_isnoneornil(L,3)) ? 0 : lua_toboolean(L, 3);

    if(EVP_DigestFinal_ex(c,(byte*)out,&outl) && outl)
    {
		if(raw){
			lua_pushlstring(L,out,outl);
		}else{
			char* in;
			BIGNUM *B = BN_new();
			BN_bin2bn(out,outl,B);
			in = BN_bn2hex(B);
			lua_pushstring(L,in);
			OPENSSL_free((void*)in);
			BN_free(B);
		}
			
        return 1;
    }else
		luaL_error(L, "digest final fail");
    return 0;
}

static LUA_FUNCTION(openssl_digest_ctx_free) {
    EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
    EVP_MD_CTX_destroy(ctx);
    return 0;
}

static LUA_FUNCTION(openssl_digest_ctx_reset) {
    EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	const EVP_MD *md = EVP_MD_CTX_md(ctx);
	ENGINE* e = ctx->engine;

	EVP_MD_CTX_cleanup(ctx);
	EVP_MD_CTX_init(ctx);
	if (!EVP_DigestInit_ex(ctx, md, e))
	{
		luaL_error(L,"reset digest fail");
	}
    lua_pushboolean(L,1);
    return 1;
}

static LUA_FUNCTION(openssl_digest_ctx_clone) {
	EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	EVP_MD_CTX *d = EVP_MD_CTX_create();
	EVP_MD_CTX_init(d);
	if (!EVP_MD_CTX_copy_ex(d, ctx))
	{
		luaL_error(L, "EVP_MD_CTX_copy_ex fail");
	}
	PUSH_OBJECT(d,"openssl.evp_digest_ctx");
	return 1;
}


static luaL_Reg digest_funs[] = {
	{"new",				openssl_evp_digest_init},
	{"info",			openssl_digest_info},
	{"digest",			openssl_digest_digest},
	{"__tostring",		auxiliar_tostring},

	{NULL, NULL}
};

static luaL_Reg digest_ctx_funs[] = {
	{"update",		openssl_evp_digest_update},
	{"final",		openssl_evp_digest_final},
	{"info",		openssl_digest_ctx_info},
	{"clone",		openssl_digest_ctx_clone},
	{"reset",		openssl_digest_ctx_reset},
	{"__tostring",	auxiliar_tostring},
	{"__gc",		openssl_digest_ctx_free},
	{NULL, NULL}
};

static const luaL_Reg R[] =
{
	{ "__call",	 openssl_digest},
	{ "list",    openssl_digest_list}, 
	{ "get",	 openssl_digest_get},
	{ "new",	 openssl_digest_new},
	{ "digest",	 openssl_digest},

	{NULL,	NULL}
};

LUALIB_API int luaopen_digest(lua_State *L)
{
	auxiliar_newclass(L,"openssl.evp_digest",		digest_funs);
	auxiliar_newclass(L,"openssl.evp_digest_ctx",	digest_ctx_funs);

	luaL_newmetatable(L,MYTYPE);
	lua_setglobal(L,MYNAME);
	luaL_register(L,MYNAME,R);
	lua_pushvalue(L, -1);
	lua_setmetatable(L, -2);
	lua_pushliteral(L,"version");			/** version */
	lua_pushliteral(L,MYVERSION);
	lua_settable(L,-3);
	lua_pushliteral(L,"__index");
	lua_pushvalue(L,-2);
	lua_settable(L,-3);
	return 1;
}
