/*=========================================================================*\
* cipher.c
* cipher module for lua-openssl binding
* lua-openssl toolkit
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"

#define MYNAME		"cipher"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"openssl.cipher"


static LUA_FUNCTION(openssl_cipher_list) {
	int alias = lua_isnoneornil(L,1) ? 1 : lua_toboolean(L, 1);
	lua_newtable(L);
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, alias ? openssl_add_method_or_alias: openssl_add_method, L);
	return 1;
}

static const EVP_CIPHER* cipher_get(lua_State*L, int idx)
{
	const EVP_CIPHER* cipher = NULL;
	if(lua_isstring(L, idx))
		cipher = EVP_get_cipherbyname(lua_tostring(L,idx));
	else if(lua_isnumber(L, idx))
		cipher = EVP_get_cipherbynid(lua_tointeger(L,idx));
	else if(auxiliar_isclass(L,"openssl.asn1_object",idx))
		cipher = EVP_get_cipherbyobj(CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object"));
	else if(auxiliar_isclass(L,"openssl.evp_cipher",idx))
		cipher = CHECK_OBJECT(idx,EVP_CIPHER,"openssl.evp_cipher");
	else
		luaL_error(L, "argument #1 must be a string, NID number or ans1_object identify cipher method");

	return cipher;
}

static LUA_FUNCTION(openssl_cipher_get) {
    const EVP_CIPHER* cipher = cipher_get(L, 1);

    if(cipher)
        PUSH_OBJECT((void*)cipher,"openssl.evp_cipher");
    else
        lua_pushnil(L);
    return 1;
}

static LUA_FUNCTION(openssl_evp_encrypt) {
	EVP_CIPHER* cipher = NULL;
	if(lua_istable(L, 1)){
		if(lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
		{
			lua_pop(L, 1);
			lua_remove(L, 1);
		}else
			luaL_error(L,"call function with invalid state");
	}

	cipher = cipher_get(L,1);
	if(cipher){
		size_t input_len = 0;
		const char *input = luaL_checklstring(L, 2, &input_len);
		size_t key_len = 0;
		const char *key = luaL_optlstring(L, 3, NULL, &key_len); /* can be NULL */
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 4, NULL, &iv_len);   /* can be NULL */
		int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
		ENGINE *e = lua_isnoneornil(L,6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX c;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};

		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}

		EVP_CIPHER_CTX_init(&c);
		EVP_CIPHER_CTX_set_padding(&c, pad);

		if(!EVP_EncryptInit_ex(&c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL ))
		{
			luaL_error(L, "EVP_EncryptInit_ex failed, please check openssl error");
		}
		buffer = malloc(input_len + EVP_CIPHER_CTX_block_size(&c));
		EVP_EncryptUpdate(&c,(byte*) buffer, &len, (const byte*)input, input_len);
		output_len += len;
		EVP_EncryptFinal(&c, (byte*)buffer+len, &len);
		output_len += len;
		lua_pushlstring(L, (char*) buffer, output_len);
		EVP_CIPHER_CTX_cleanup(&c);
		free(buffer);
	}else
		luaL_error(L,"argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");
	return 1;
}

static LUA_FUNCTION(openssl_evp_decrypt) {
	EVP_CIPHER* cipher;
	if(lua_istable(L, 1)){
		if(lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
		{
			lua_pop(L, 1);
			lua_remove(L, 1);
		}else
			luaL_error(L,"call function with invalid state");
	}
	cipher = cipher_get(L,1);
	if(cipher)
	{
		size_t input_len = 0;
		const char *input = luaL_checklstring(L, 2, &input_len);
		size_t key_len = 0;
		const char *key = luaL_optlstring(L, 3, NULL, &key_len); /* can be NULL */
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 4, NULL, &iv_len); /* can be NULL */
		int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
		ENGINE *e = lua_isnoneornil(L,6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX c;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};
		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}

		EVP_CIPHER_CTX_init(&c);
		EVP_CIPHER_CTX_set_padding(&c, pad);
		if(!EVP_DecryptInit_ex(&c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL ))
		{
			luaL_error(L, "EVP_DecryptInit_ex failed, please check openssl error");
		}

		buffer = malloc(input_len);
		EVP_DecryptUpdate(&c, (byte*)buffer, &len, (const byte*)input, input_len);
		output_len += len;
		EVP_DecryptFinal(&c, (byte*)buffer+len, &len);
		output_len += len;
		lua_pushlstring(L, (char*) buffer, output_len);
		EVP_CIPHER_CTX_cleanup(&c);
		free(buffer);
	}else
		luaL_error(L,"argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");
	
	return 1;
}

static LUA_FUNCTION(openssl_evp_cipher) {
	EVP_CIPHER* cipher = NULL;
	if(lua_istable(L, 1)){
		if(lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
		{
			lua_pop(L, 1);
			lua_remove(L, 1);
		}else
			luaL_error(L,"call function with invalid state");
	}

	cipher = cipher_get(L, 1);
	
	if(cipher)
	{
		int enc = lua_toboolean(L, 2);
		size_t input_len = 0;
		const char *input = luaL_checklstring(L, 3, &input_len);
		size_t key_len = 0;
		const char *key = luaL_optlstring(L, 4, NULL, &key_len); /* can be NULL */
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 5, NULL, &iv_len); /* can be NULL */
		int pad = lua_isnoneornil(L, 6) ? 1 : lua_toboolean(L, 6);
		ENGINE *e = lua_isnoneornil(L,7) ? NULL : CHECK_OBJECT(7, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX c;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};
		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}

		EVP_CIPHER_CTX_init(&c);
		EVP_CIPHER_CTX_set_padding(&c, pad);
		if(!EVP_CipherInit_ex(&c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL, enc))
		{
			luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
		}

		buffer = malloc(input_len);
		EVP_CipherUpdate(&c, (byte*)buffer, &len, (const byte*)input, input_len);
		output_len += len;
		EVP_CipherFinal(&c, (byte*)buffer+len, &len);
		output_len += len;
		lua_pushlstring(L, (char*) buffer, output_len);
		EVP_CIPHER_CTX_cleanup(&c);
		free(buffer);
	}else
		luaL_error(L,"argument #2 is not a valid cipher algorithm or openssl.evp_cipher object");

	return 1;
}

typedef enum {
	DO_CIPHER = -1,
	DO_ENCRYPT = 0,
	DO_DECRYPT = 1
}CIPHER_MODE;

static LUA_FUNCTION(openssl_cipher_new) {
	const EVP_CIPHER* cipher = cipher_get(L,1);
	if(cipher)
	{
		int enc = lua_toboolean(L, 2);
		size_t key_len = 0;
		const char *key = luaL_checklstring(L, 3, &key_len);
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 4, NULL, &iv_len);
		int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
		ENGINE *e = lua_isnoneornil(L,6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX *c = NULL;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};
		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}
		c = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(c);
		EVP_CIPHER_CTX_set_padding(c, pad);
		if(!EVP_CipherInit_ex(c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL, enc))
		{
			luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
		}
		PUSH_OBJECT(c,"openssl.evp_cipher_ctx");
		lua_pushvalue(L,-1);
		lua_pushinteger(L, DO_CIPHER);
		lua_settable(L,LUA_REGISTRYINDEX);
	}else
		luaL_error(L,"argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");

	return 1;
}

static LUA_FUNCTION(openssl_cipher_encrypt_new) {
	const EVP_CIPHER* cipher  = cipher_get(L,1);
	if(cipher)
	{
		size_t key_len = 0;
		const char *key = luaL_optlstring(L, 2, NULL, &key_len); /* can be NULL */
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 3, NULL, &iv_len); /* can be NULL */
		int pad = lua_isnoneornil(L, 4) ? 1 : lua_toboolean(L, 4);
		ENGINE *e = lua_isnoneornil(L,5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX *c = NULL;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};
		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}
		c = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(c);
		EVP_CIPHER_CTX_set_padding(c, pad);
		if(!EVP_EncryptInit_ex(c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL))
		{
			luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
		}
		PUSH_OBJECT(c,"openssl.evp_cipher_ctx");
		lua_pushvalue(L,-1);
		lua_pushinteger(L, DO_ENCRYPT);
		lua_settable(L,LUA_REGISTRYINDEX);
	}else
		luaL_error(L,"argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");

	return 1;
}

static LUA_FUNCTION(openssl_cipher_decrypt_new) {
	const EVP_CIPHER* cipher = cipher_get(L,1);
	if(cipher)
	{
		size_t key_len = 0;
		const char *key = luaL_optlstring(L, 2, NULL, &key_len); /* can be NULL */
		size_t iv_len = 0;
		const char *iv = luaL_optlstring(L, 3, NULL, &iv_len); /* can be NULL */
		int pad = lua_isnoneornil(L, 4) ? 1 : lua_toboolean(L, 4);
		ENGINE *e = lua_isnoneornil(L,5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
		EVP_CIPHER_CTX *c = NULL;

		int output_len = 0;
		int len = 0;
		char *buffer = NULL;
		char evp_key[EVP_MAX_KEY_LENGTH] = {0};
		char evp_iv[EVP_MAX_IV_LENGTH] = {0};
		if (key)
		{
			key_len = EVP_MAX_KEY_LENGTH>key_len?key_len:EVP_MAX_KEY_LENGTH;
			memcpy(evp_key, key, key_len);
		}
		if (iv)
		{
			iv_len = EVP_MAX_IV_LENGTH>iv_len?iv_len:EVP_MAX_IV_LENGTH;
			memcpy(evp_iv, iv, iv_len);
		}
		c = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(c);
		EVP_CIPHER_CTX_set_padding(c, pad);
		if(!EVP_DecryptInit_ex(c, cipher, e, key?(const byte*)evp_key:NULL, iv?(const byte*)evp_iv:NULL))
		{
			luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
		}
		PUSH_OBJECT(c,"openssl.evp_cipher_ctx");
		lua_pushvalue(L,-1);
		lua_pushinteger(L, DO_DECRYPT);
		lua_settable(L,LUA_REGISTRYINDEX);
	}else
		luaL_error(L,"argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");

	return 1;
}

/* evp_cipher method */
static LUA_FUNCTION(openssl_cipher_info)
{
    EVP_CIPHER *cipher = CHECK_OBJECT(1,EVP_CIPHER, "openssl.evp_cipher");
    lua_newtable(L);
    add_assoc_string(L,"name", EVP_CIPHER_name(cipher));
    add_assoc_int(L,"block_size", EVP_CIPHER_block_size(cipher));
    add_assoc_int(L,"key_length", EVP_CIPHER_key_length(cipher));
    add_assoc_int(L,"iv_length", EVP_CIPHER_iv_length(cipher));
    add_assoc_int(L,"flags", EVP_CIPHER_flags(cipher));
    add_assoc_int(L,"mode", EVP_CIPHER_mode(cipher));

    return 1;
}


static LUA_FUNCTION(openssl_evp_BytesToKey)
{
    EVP_CIPHER* c = CHECK_OBJECT(1,EVP_CIPHER, "openssl.evp_cipher");
    EVP_MD* m = CHECK_OBJECT(2,EVP_MD, "openssl.evp_digest");
    const char* salt, *k;  /* PKCS5_SALT_LEN */
    size_t lsalt, lk;

    char key[EVP_MAX_KEY_LENGTH],iv[EVP_MAX_IV_LENGTH];

    salt = luaL_checklstring(L, 3, &lsalt);
    if(lsalt < PKCS5_SALT_LEN)
        luaL_error(L, "salt must not shorter than %d",PKCS5_SALT_LEN);

    k = luaL_checklstring(L, 4, &lk);


    EVP_BytesToKey(c,m,(unsigned char*)salt, (unsigned char*)k, lk,1,(unsigned char*)key,(unsigned char*)iv);
    lua_pushlstring(L, key, EVP_MAX_KEY_LENGTH);
    lua_pushlstring(L, iv, EVP_MAX_IV_LENGTH);
    return 2;
}


/* evp_cipher_ctx method */
static LUA_FUNCTION(openssl_evp_cipher_update)
{
    EVP_CIPHER_CTX* c = CHECK_OBJECT(1,EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
    size_t inl;
    const char* in= luaL_checklstring(L,2,&inl);
    int outl = inl + EVP_MAX_BLOCK_LENGTH;
    char* out = malloc(outl);
	CIPHER_MODE mode;
	int ret;

	lua_pushvalue(L, 1);
	lua_gettable(L,LUA_REGISTRYINDEX);
	mode = lua_tointeger(L, -1);

	if(mode == DO_CIPHER)
		ret = EVP_CipherUpdate(c,(byte*)out,&outl,(const byte*)in,inl);
	else if(mode == DO_ENCRYPT)
		ret = EVP_EncryptUpdate(c,(byte*)out,&outl,(const byte*)in,inl);
	else if(mode == DO_DECRYPT)
		ret = EVP_DecryptUpdate(c,(byte*)out,&outl,(const byte*)in,inl);
	else
		luaL_error(L,"never go here");

    if(ret)
    {
        lua_pushlstring(L,out,outl);
    }
    free(out);

    return ret ? 1 : 0;
}

static LUA_FUNCTION(openssl_evp_cipher_final)
{
    EVP_CIPHER_CTX* c = CHECK_OBJECT(1,EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
    int outl = EVP_MAX_BLOCK_LENGTH;
    char out[EVP_MAX_BLOCK_LENGTH];
	CIPHER_MODE mode;
	int ret;

	lua_pushvalue(L, 1);
	lua_gettable(L,LUA_REGISTRYINDEX);
	mode = lua_tointeger(L, -1);

	if(mode == DO_CIPHER)
		ret = EVP_CipherFinal_ex(c,(byte*)out,&outl);
	else if(mode == DO_ENCRYPT)
		ret = EVP_EncryptFinal_ex(c,(byte*)out,&outl);
	else if(mode == DO_DECRYPT)
		ret = EVP_DecryptFinal_ex(c,(byte*)out,&outl);
	else
		luaL_error(L,"never go here");

    if(ret)
    {
        lua_pushlstring(L,out,outl);
        return 1;
    }
    return 0;
}


static LUA_FUNCTION(openssl_cipher_ctx_info)
{
    EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1,EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
    lua_newtable(L);
    add_assoc_int(L,"block_size", EVP_CIPHER_CTX_block_size(ctx));
    add_assoc_int(L,"key_length", EVP_CIPHER_CTX_key_length(ctx));
    add_assoc_int(L,"iv_length", EVP_CIPHER_CTX_iv_length(ctx));
    add_assoc_int(L,"flags", EVP_CIPHER_CTX_flags(ctx));
    add_assoc_int(L,"nid", EVP_CIPHER_CTX_nid(ctx));
    add_assoc_int(L,"type", EVP_CIPHER_CTX_mode(ctx));
    add_assoc_int(L,"mode", EVP_CIPHER_CTX_type(ctx));
    PUSH_OBJECT((void*)EVP_CIPHER_CTX_cipher(ctx),"openssl.evp_cipher");
    lua_setfield(L,-2,"cipher");
    return 1;
}

static LUA_FUNCTION(openssl_cipher_ctx_free) {
    EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1,EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
	lua_pushvalue(L,1);
	lua_pushnil(L);
	lua_settable(L, LUA_REGISTRYINDEX);
	EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static luaL_Reg cipher_funs[] = {
    {"info",			openssl_cipher_info},
	{ "new",		 openssl_cipher_new},
	{ "encrypt_new", openssl_cipher_encrypt_new},
	{ "decrypt_new", openssl_cipher_decrypt_new},

    {"BytesToKey",		openssl_evp_BytesToKey},

    {"encrypt",			openssl_evp_encrypt },
    {"decrypt",			openssl_evp_decrypt },
	{"cipher",			openssl_evp_cipher },

    {"__tostring",		auxiliar_tostring},

    {NULL, NULL}
};

static luaL_Reg cipher_ctx_funs[] = {
    {"update",		openssl_evp_cipher_update},
    {"final",		openssl_evp_cipher_final},

    {"info",		openssl_cipher_ctx_info},
    {"__gc",		openssl_cipher_ctx_free},
	{"__tostring",	auxiliar_tostring},

    {NULL, NULL}
};

static const luaL_Reg R[] =
{
	{ "__call",	 openssl_evp_cipher},
	{ "list",    openssl_cipher_list}, 
	{ "get",	 openssl_cipher_get},
	{ "encrypt", openssl_evp_encrypt},
	{ "decrypt", openssl_evp_decrypt},
	{ "cipher",	 openssl_evp_cipher},

	{ "new",		 openssl_cipher_new},
	{ "encrypt_new", openssl_cipher_encrypt_new},
	{ "decrypt_new", openssl_cipher_decrypt_new},

	{NULL,	NULL}
};

LUALIB_API int luaopen_cipher(lua_State *L)
{
	auxiliar_newclass(L,"openssl.evp_cipher",		cipher_funs);
	auxiliar_newclass(L,"openssl.evp_cipher_ctx",	cipher_ctx_funs);

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

