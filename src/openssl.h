/*=========================================================================*\
* x509 routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#ifndef LUA_EAY_H
#define LUA_EAY_H
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "auxiliar.h"
#if LUA_VERSION_NUM>501
#define lua_objlen lua_rawlen
#endif

#include <assert.h>
#include <string.h>
/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/opensslv.h>

#define LOPENSSL_VERSION_STR	"0.0.5"

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/lhash.h>
#define OPENSSL_HAVE_TS
#define LHASH LHASH_OF(CONF_VALUE)
#endif
typedef unsigned char byte;

#define MULTI_LINE_MACRO_BEGIN do {  
#ifdef _MSC_VER
#define MULTI_LINE_MACRO_END	\
__pragma(warning(push))		\
__pragma(warning(disable:4127)) \
} while(0)			\
__pragma(warning(pop)) 
#else
#define MULTI_LINE_MACRO_END \
} while(0)
#endif

/* Common */
#include <time.h>
#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

#ifdef NETWARE
#define timezone _timezone	/* timezone is called _timezone in LibC */
#endif

#define DEFAULT_KEY_LENGTH	512
#define MIN_KEY_LENGTH		384

#define OPENSSL_ALGO_SHA1 	1
#define OPENSSL_ALGO_MD5	2
#define OPENSSL_ALGO_MD4	3
#ifdef HAVE_OPENSSL_MD2_H
#define OPENSSL_ALGO_MD2	4
#endif
#define OPENSSL_ALGO_DSS1	5

#define DEBUG_SMIME	0

#ifdef WIN32
#define snprintf _snprintf
#ifndef strcasecmp
#define strcasecmp stricmp
#endif
#endif

enum lua_openssl_key_type {
    OPENSSL_KEYTYPE_RSA,
    OPENSSL_KEYTYPE_DSA,
    OPENSSL_KEYTYPE_DH,
    OPENSSL_KEYTYPE_DEFAULT = OPENSSL_KEYTYPE_RSA,
#ifdef EVP_PKEY_EC
    OPENSSL_KEYTYPE_EC = OPENSSL_KEYTYPE_DH +1
#endif
};

enum lua_openssl_cipher_type {
    OPENSSL_CIPHER_RC2_40,
    OPENSSL_CIPHER_RC2_128,
    OPENSSL_CIPHER_RC2_64,
    OPENSSL_CIPHER_DES,
    OPENSSL_CIPHER_3DES,

    OPENSSL_CIPHER_DEFAULT = OPENSSL_CIPHER_RC2_40
};

X509_STORE * setup_verify(STACK_OF(X509)* calist);

#define LUA_FUNCTION(X) int X(lua_State *L)


int openssl_get_revoke_reason(const char*s);

LUA_FUNCTION(openssl_x509_algo_parse);
LUA_FUNCTION(openssl_x509_algo_tostring);
LUA_FUNCTION(openssl_x509_extension_parse);
LUA_FUNCTION(openssl_x509_extension_tostring);

LUA_FUNCTION(openssl_list);
LUA_FUNCTION(openssl_hex);
LUA_FUNCTION(openssl_engine);
LUA_FUNCTION(openssl_error_string);
LUA_FUNCTION(openssl_random_bytes);

LUA_FUNCTION(openssl_sk_x509_read);
LUA_FUNCTION(openssl_sk_x509_new);

LUA_FUNCTION(openssl_conf_load);


LUA_API LUA_FUNCTION(luaopen_digest);
LUA_API LUA_FUNCTION(luaopen_cipher);
LUA_API LUA_FUNCTION(luaopen_bn);
LUA_API LUA_FUNCTION(luaopen_pkey);
LUA_API LUA_FUNCTION(luaopen_x509);
LUA_API LUA_FUNCTION(luaopen_pkcs7);
LUA_API LUA_FUNCTION(luaopen_pkcs12);
LUA_API LUA_FUNCTION(luaopen_bio);
LUA_API LUA_FUNCTION(luaopen_ts);
LUA_API LUA_FUNCTION(luaopen_csr);
LUA_API LUA_FUNCTION(luaopen_crl);
LUA_API LUA_FUNCTION(luaopen_ocsp);
LUA_API LUA_FUNCTION(luaopen_ssl);
LUA_API LUA_FUNCTION(luaopen_ec);


void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) ;
void openssl_add_method(const OBJ_NAME *name, void *arg);

#define CHECK_OBJECT(n,type,name) *(type**)luaL_checkudata(L,n,name)

#define PUSH_OBJECT(o, tname)		\
	MULTI_LINE_MACRO_BEGIN		\
	*(void **)(lua_newuserdata(L, sizeof(void *))) = (void*)(o);	\
	auxiliar_setclass(L,tname,-1);	\
	MULTI_LINE_MACRO_END

#define ADD_ASSOC_BIO(bio, key)	MULTI_LINE_MACRO_BEGIN	\
	BUF_MEM *buf;	BIO_get_mem_ptr(bio, &buf);	\
	lua_pushlstring(L, buf->data, buf->length);	\
	lua_setfield(L, -2, key); BIO_reset(bio);	\
	MULTI_LINE_MACRO_END

#define ADD_ASSOC_ASN1(type, bio, asn1,  key ) MULTI_LINE_MACRO_BEGIN \
	BUF_MEM *buf;					\
	i2a_##type(bio,asn1);				\
	BIO_get_mem_ptr(bio, &buf);			\
	lua_pushlstring(L, buf->data, buf->length);	\
	lua_setfield(L, -2, key); BIO_reset(bio);	\
	MULTI_LINE_MACRO_END

#define ADD_ASSOC_ASN1_STRING(type, bio, asn1,  key ) MULTI_LINE_MACRO_BEGIN \
	BUF_MEM *buf;					\
	i2a_ASN1_STRING(bio,asn1, V_##type);		\
	BIO_get_mem_ptr(bio, &buf);			\
	lua_pushlstring(L, buf->data, buf->length);	\
	lua_setfield(L, -2, key); BIO_reset(bio);	\
	MULTI_LINE_MACRO_END

#define ADD_ASSOC_ASN1_TIME(bio, atime, key ) MULTI_LINE_MACRO_BEGIN	\
	ASN1_TIME_print(bio,atime);					\
	ADD_ASSOC_BIO(bio, key);					\
	lua_pushfstring(L, "%s_time_t", key);				\
	lua_pushinteger(L, (lua_Integer)asn1_time_to_time_t(atime));	\
	lua_settable (L,-3);    \
	MULTI_LINE_MACRO_END


void add_assoc_name_entry(lua_State*L, const  char *key, X509_NAME *name, int shortname);
void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* ext, BIO* bio);

time_t asn1_time_to_time_t(ASN1_UTCTIME * timestr);

int openssl_register_x509(lua_State* L);
int openssl_register_sk_x509(lua_State* L);
int openssl_register_conf(lua_State* L);


int openssl_register_engine(lua_State* L);

#endif

