/*=========================================================================*\
* openssl.c
* lua-openssl binding
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/opensslconf.h>
#include "private.h"
static int openssl_version(lua_State*L)
{
		lua_pushstring(L, LOPENSSL_VERSION_STR);
		lua_pushstring(L, LUA_VERSION);
		lua_pushstring(L, OPENSSL_VERSION_TEXT);
		return 3;
}

static LUA_FUNCTION(openssl_hex){
	size_t l = 0;
	const char* s = luaL_checklstring(L, 1, &l);
	char* h;
	BIGNUM *bn = BN_new();
	BN_bin2bn((const unsigned char*)s, (int)l, bn);
	h = BN_bn2hex(bn);
	lua_pushstring(L, h);
	OPENSSL_free(h);
	return 1;
}

static void list_callback(const OBJ_NAME *obj, void *arg)
{
	lua_State *L = (lua_State *)arg;
	int idx = (int)lua_objlen(L, -1);
	lua_pushstring(L, obj->name);
	lua_rawseti(L, -2, idx + 1);
}

static LUA_FUNCTION(openssl_list){
	static int options[] = {
		OBJ_NAME_TYPE_MD_METH,
		OBJ_NAME_TYPE_CIPHER_METH,
		OBJ_NAME_TYPE_PKEY_METH,
		OBJ_NAME_TYPE_COMP_METH
	};
	static const char *names[] = {"digests","ciphers", "pkeys", "comps", NULL};
	int type = auxiliar_checkoption (L, 1, NULL, names, options);
	lua_createtable(L, 0, 0);
	OBJ_NAME_do_all_sorted(type, list_callback, L);
	return 1;
}

static LUA_FUNCTION(openssl_error_string)
{
	char buf[1024];
	unsigned long val;
	int verbose = lua_toboolean(L,1);
	int ret = 0;
	val = ERR_get_error();
	if (val) {
		lua_pushinteger(L,val);
		ERR_error_string_n(val, buf,sizeof(buf));
		lua_pushstring(L, buf);
		ret = 2;
	}
	if(verbose)
	{
		ERR_print_errors_fp(stderr);
	}
	ERR_clear_error();

	return ret;
}

static LUA_FUNCTION(openssl_random_bytes)
{
	static int seed = 0;
	long length = luaL_checkint(L,1);
	int strong = lua_isnil(L,2) ? 0 : lua_toboolean(L,2);

	char *buffer = NULL;
	int ret = 0;
	if(!seed){
		seed = RAND_init(NULL);
	}
	if (!seed)
		luaL_error(L, "Fail to init random routines");

	if (length <= 0) {
		luaL_argerror(L, 1, "must greater than 0");
	}

	buffer = malloc(length + 1);
	if (strong)
	{
		ret = RAND_bytes((byte*)buffer,length);
		if(ret) {
			lua_pushlstring(L, buffer, length);
			lua_pushboolean(L, 1);
			ret = 2;
		} else {
			lua_pushboolean(L, 0);
			ret = 1;
		}
	}
	else {
		ret = RAND_pseudo_bytes((byte*)buffer, length);
		if(ret>=0) {
			lua_pushlstring(L, buffer, length);
			lua_pushboolean(L, ret);
			ret = 2;
		} else {
			lua_pushboolean(L, 0);
			ret = 1;
		}
	}
	free(buffer);
	return ret;
}

static int openssl_object(lua_State* L)
{
	if(lua_isnumber(L, 1)){
		int nid = luaL_checkint(L,1);
		ASN1_OBJECT* obj = OBJ_nid2obj(nid);
		if(obj)
			PUSH_OBJECT(obj,"openssl.asn1_object");
		else
			lua_pushnil(L);
	}else{
		const char* oid  = luaL_checkstring(L,1);
		if(lua_isnoneornil(L, 2))
		{
			const char* name = luaL_checkstring(L,2);
			const char* alias = luaL_optstring(L,3,name);
			if(OBJ_create(oid, name, alias)==NID_undef)
				lua_pushboolean(L,0);
			else
				lua_pushboolean(L,1);
		}else{
			int nid = OBJ_txt2nid(oid);
			if(nid!=NID_undef){
				ASN1_OBJECT* obj = OBJ_nid2obj(nid);
				if(obj)
					PUSH_OBJECT(obj,"openssl.asn1_object");
				else
					lua_pushnil(L);
			}else
				lua_pushnil(L);
		}
	}
	return 1;
}

static const luaL_Reg eay_functions[] = {
	{"version",			openssl_version},
	{"list",			openssl_list},
	{"hex",				openssl_hex},
    {"random",			openssl_random_bytes},
	{"error",			openssl_error_string},
	{"object",			openssl_object},

	{"engine",			openssl_engine},

    {NULL, NULL}
};

void CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);

LUA_API int luaopen_openssl(lua_State*L)
{
    CRYPTO_thread_setup();

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_library_init();

    ERR_load_ERR_strings();
    ERR_load_EVP_strings();
    

    ENGINE_load_dynamic();
    ENGINE_load_openssl();
#ifdef LOAD_ENGINE_CUSTOM
	LOAD_ENGINE_CUSTOM();
#endif
#ifdef OPENSSL_SYS_WINDOWS
	RAND_screen();
#endif

#if LUA_VERSION_NUM==501
    luaL_register(L,"openssl",eay_functions);
#elif LUA_VERSION_NUM==502
    lua_newtable(L);
    luaL_setfuncs(L, eay_functions, 0);
#endif
	openssl_register_lhash(L);
	openssl_register_engine(L);

	luaopen_bio(L);
	lua_setfield(L, -2, "bio");

	luaopen_asn1(L);
	lua_setfield(L, -2, "asn1");


	luaopen_digest(L);
	lua_setfield(L, -2, "digest");

	luaopen_cipher(L);
	lua_setfield(L, -2, "cipher");

	luaopen_pkey(L);
	lua_setfield(L, -2, "pkey");

#ifdef EVP_PKEY_EC
	luaopen_ec(L);
	lua_setfield(L, -2, "ec");
#endif

	luaopen_x509(L);
	lua_setfield(L, -2, "x509");

	luaopen_pkcs7(L);
	lua_setfield(L, -2, "pkcs7");

	luaopen_pkcs12(L);
	lua_setfield(L, -2, "pkcs12");

	luaopen_csr(L);
	lua_setfield(L, -2, "csr");

	luaopen_crl(L);
	lua_setfield(L, -2, "crl");

	luaopen_ocsp(L);
	lua_setfield(L, -2, "ocsp");
	
#ifdef OPENSSL_HAVE_TS
	/* timestamp handling */
	luaopen_ts(L);
	lua_setfield(L, -2, "ts");
#endif

	luaopen_ssl(L);
	lua_setfield(L, -2, "ssl");

	/* third part */
    luaopen_bn(L);
	lua_setfield(L, -2, "bn");

    return 1;
}

