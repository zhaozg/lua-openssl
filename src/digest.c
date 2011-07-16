/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"

/* digest module for the Lua/OpenSSL binding.
 *
 * The functions in this module can be used to load, parse, export, verify... functions.
 * get_cipher()
 * cipher_info()
 */ 

/* openssl.get_digest([nil,bool aliases=true]|string alg|int alg_id|openssl.asn1_obj|alg_obj) -> table|openssl.evp_digest|null  {{{1

    openssl.get_digest([bool alias=true]) will return all md methods default with alias
	other will return a md method
*/ 

LUA_FUNCTION(openssl_get_digest) {
	const EVP_MD* md = NULL;

	if (lua_isnoneornil(L,1) || lua_isboolean(L,1))
	{
		int aliases = lua_isnoneornil(L,1)?1:lua_toboolean(L,1);

		lua_newtable(L);
		OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, aliases ? openssl_add_method_or_alias: openssl_add_method, L);
		return 1;
	}

	if (lua_isstring(L,1))
		md = EVP_get_digestbyname(lua_tostring(L,1));
	else if(lua_isnumber(L,1))
		md = EVP_get_digestbynid(lua_tointeger(L,1));
	else if(auxiliar_isclass(L,"openssl.obj",1))
		md = EVP_get_digestbyobj(CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object"));
	else
	{
		luaL_typerror(L,1,"please input correct paramater");
	}

	if(md)
		PUSH_OBJECT((void*)md,"openssl.evp_digest");
	else
		lua_pushnil(L);
	return 1;	
}
/* }}} */

LUA_FUNCTION(openssl_digest_info)
{
	EVP_MD *md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
	lua_newtable(L);
	add_assoc_int(L,"nid", EVP_MD_nid(md));
	add_assoc_string(L,"name", EVP_MD_name(md),1);
	add_assoc_int(L,"size", EVP_MD_size(md));
	add_assoc_int(L,"block_size", EVP_MD_block_size(md));

	add_assoc_int(L,"pkey_type", EVP_MD_pkey_type(md));
	add_assoc_int(L,"flags", EVP_MD_type(md));
	return 1;
}

LUA_FUNCTION(openssl_digest_digest)
{
	EVP_MD *md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
	int inl;
	const char* in = luaL_checklstring(L,2,&inl);
	ENGINE*     e = lua_gettop(L)>2?CHECK_OBJECT(3,ENGINE,"openssl.engine"):NULL;

	char buf[MAX_PATH];
	int  blen = MAX_PATH;

	int status = EVP_Digest(in, inl, buf, &blen, md, e); 
	if (status) {
		lua_pushlstring(L,buf,blen);
	}else
		lua_pushnil(L);
	return 1;
}

LUA_FUNCTION(openssl_digest_tostring)
{
	EVP_MD *md = CHECK_OBJECT(1,EVP_MD, "openssl.evp_digest");
	lua_pushfstring(L,"openssl.evp_digest:%p",md);
	return 1;
}

/*  openssl.evp_encrypt_init(openssl.evp_digest md [,openssl.engine engimp])->openssl.evp_digest_ctx{{{1
*/ 

LUA_FUNCTION(openssl_evp_digest_init)
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
/* }}} */

/*  openssl.evp_digest_init(openssl.evp_digest_ctx ctx, string data)->bool{{{1
*/ 
LUA_FUNCTION(openssl_evp_digest_update)
{
	EVP_MD_CTX* c = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	int inl;

	const char* in= luaL_checklstring(L,2,&inl);
	
	int ret = EVP_DigestUpdate(c,in,inl);

	lua_pushboolean(L,ret);
	return 1;
}
/* }}} */

/*  openssl.evp_digest_final(openssl.evp_digest_ctx ctx)->string{{{1
*/ 
LUA_FUNCTION(openssl_evp_digest_final)
{
	EVP_MD_CTX* c = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	int outl = EVP_MAX_MD_SIZE;
	char out[EVP_MAX_MD_SIZE];

	if(EVP_DigestFinal_ex(c,out,&outl) && outl)
	{
		lua_pushlstring(L,out,outl);
		return 1;
	}
	return 0;
}
/* }}} */



LUA_FUNCTION(openssl_digest_ctx_info)
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

LUA_FUNCTION(openssl_digest_ctx_tostring) {
	EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	lua_pushfstring(L,"openssl.evp_digest_ctx:%p",ctx);
	return 1;
}

LUA_FUNCTION(openssl_digest_ctx_free) {
	EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	EVP_MD_CTX_destroy(ctx);
	return 0;
}

LUA_FUNCTION(openssl_digest_ctx_cleanup) {
	EVP_MD_CTX *ctx = CHECK_OBJECT(1,EVP_MD_CTX, "openssl.evp_digest_ctx");
	lua_pushboolean(L,EVP_MD_CTX_cleanup(ctx)==0);
	return 1;
}


static luaL_Reg digest_funs[] = {
	{"info",			openssl_digest_info},
	{"digest",			openssl_digest_digest},
	{"init",			openssl_evp_digest_init},

	{"__tostring",		openssl_digest_tostring},
	{NULL, NULL}
};

static luaL_Reg digest_ctx_funs[] = {
	{"update",			openssl_evp_digest_update},
	{"final",			openssl_evp_digest_final},

	{"info",		openssl_digest_ctx_info},
	{"__tostring",	openssl_digest_ctx_tostring},
	{"__gc",		openssl_digest_ctx_free},
	{"cleanup",		openssl_digest_ctx_cleanup},
	{NULL, NULL}
};

int openssl_register_digest(lua_State* L)
{
	auxiliar_newclass(L,"openssl.evp_digest",		digest_funs);
	auxiliar_newclass(L,"openssl.evp_digest_ctx",	digest_ctx_funs);
	return 0;
}
