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
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio,(void*)ctx, l);
		BIO_set_close(bio, BIO_CLOSE);
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
const EVP_CIPHER* get_cipher(lua_State*L, int idx)
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
	}		

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

int RAND_init(const char *file)
{
	int consider_randfile = (file == NULL);
	char buffer[200];
	
#ifdef OPENSSL_SYS_WINDOWS
	RAND_screen();
#endif

	if (file == NULL)
		file = RAND_file_name(buffer, sizeof buffer);
	else if (RAND_egd(file) > 0)
	{
		/* we try if the given filename is an EGD socket.
		   if it is, we don't write anything back to the file. */;
		return 1;
	}
	if (file == NULL || !RAND_load_file(file, -1))
	{
		return RAND_status();
	}

	return 1;
}

int openssl_pushresult(lua_State*L, int result)
{
	if(result==1)
	{
		lua_pushboolean(L, 1);
		return 1;
	}else{
		unsigned val = ERR_get_error();
		if (val) {
			luaL_Buffer B = {0};
			lua_pushnil(L);
			ERR_error_string_n(val, B.buffer,sizeof(B.buffer));
			lua_pushstring(L, B.buffer);
			lua_pushinteger(L,val);
			return 3;
		}
	}
	return 0;
}