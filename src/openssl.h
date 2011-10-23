/* 
$Id:$ 
$Revision:$
*/

#ifndef LUA_EAY_H
#define LUA_EAY_H
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "auxiliar.h"

#include <assert.h>
#include "openssl.h"

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
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000002L 
#define OPENSSL_HAVE_TS
#define LHASH LHASH_OF(CONF_VALUE)
#else
#ifndef HEADER_EC_H
#undef EVP_PKEY_EC
#endif
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
#define strcasecmp stricmp
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
void add_assoc_asn1_string(lua_State*L, char * key, ASN1_STRING * str);

int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH * config);

extern char default_ssl_conf_filename[MAX_PATH];


#define LUA_FUNCTION(X) int X(lua_State*L)

LUA_FUNCTION(openssl_x509_read);
LUA_FUNCTION(openssl_x509_free);
LUA_FUNCTION(openssl_x509_parse);
LUA_FUNCTION(openssl_x509_checkpurpose);
LUA_FUNCTION(openssl_x509_export);
LUA_FUNCTION(openssl_x509_tostring);
LUA_FUNCTION(openssl_x509_check_private_key);
LUA_FUNCTION(openssl_x509_public_key);
LUA_FUNCTION(openssl_sk_x509_read);
LUA_FUNCTION(openssl_sk_x509_new);


LUA_FUNCTION(openssl_pkey_tostring);
LUA_FUNCTION(openssl_pkey_read);
LUA_FUNCTION(openssl_pkey_export);
LUA_FUNCTION(openssl_pkey_free);
LUA_FUNCTION(openssl_pkey_new);
LUA_FUNCTION(openssl_pkey_is_private);
LUA_FUNCTION(openssl_pkey_parse);

LUA_FUNCTION(openssl_pkey_encrypt);
LUA_FUNCTION(openssl_pkey_decrypt);

LUA_FUNCTION(openssl_sign);
LUA_FUNCTION(openssl_verify);
LUA_FUNCTION(openssl_seal);
LUA_API LUA_FUNCTION(openssl_open);

LUA_FUNCTION(openssl_pkcs7_verify);
LUA_FUNCTION(openssl_pkcs7_decrypt);
LUA_FUNCTION(openssl_pkcs7_sign);
LUA_FUNCTION(openssl_pkcs7_encrypt);
LUA_FUNCTION(openssl_pkcs7_read);
LUA_FUNCTION(openssl_pkcs7_parse);


LUA_FUNCTION(openssl_error_string);


LUA_FUNCTION(openssl_pkcs12_export);
LUA_FUNCTION(openssl_pkcs12_read);

LUA_FUNCTION(openssl_csr_new);
LUA_FUNCTION(openssl_csr_read);

LUA_FUNCTION(openssl_crl_new);
LUA_FUNCTION(openssl_crl_read);


LUA_FUNCTION(openssl_dh_compute_key);
LUA_FUNCTION(openssl_random_bytes);
LUA_FUNCTION(openssl_bio_new_mem);
LUA_FUNCTION(openssl_bio_new_file);

LUA_FUNCTION(openssl_get_digest);
LUA_FUNCTION(openssl_get_cipher);

LUA_FUNCTION(openssl_ts_req_new);
LUA_FUNCTION(openssl_ts_req_d2i);
LUA_FUNCTION(openssl_ts_resp_d2i);
LUA_FUNCTION(openssl_ts_resp_ctx_new);
LUA_FUNCTION(openssl_ts_verify_ctx_new);

LUA_FUNCTION(openssl_conf_load);

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) ;
void openssl_add_method(const OBJ_NAME *name, void *arg);

#define CHECK_OBJECT(n,type,name) *(type**)luaL_checkudata(L,n,name)
#define PUSH_OBJECT(o, tname)  do {							\
	*(void **)(lua_newuserdata(L, sizeof(void *))) = (o);	\
	auxiliar_setclass(L,tname,-1);} while(0)

#define ADD_ASSOC_BIO(bio, key)	{	\
	BUF_MEM *buf;	BIO_get_mem_ptr(bio, &buf);	\
	lua_pushlstring(L, buf->data, buf->length);	\
	lua_setfield(L, -2, key); BIO_reset(bio);	\
}

#define ADD_ASSOC_ASN1(type, bio, asn1,  key ) {	\
	BUF_MEM *buf;									\
	i2a_##type(bio,asn1);							\
	BIO_get_mem_ptr(bio, &buf);						\
	lua_pushlstring(L, buf->data, buf->length);		\
	lua_setfield(L, -2, key); BIO_reset(bio);		\
}

#define ADD_ASSOC_ASN1_STRING(type, bio, asn1,  key ) {	\
	BUF_MEM *buf;									\
	i2a_ASN1_STRING(bio,asn1, V_##type);							\
	BIO_get_mem_ptr(bio, &buf);						\
	lua_pushlstring(L, buf->data, buf->length);		\
	lua_setfield(L, -2, key); BIO_reset(bio);		\
}

#define ADD_ASSOC_ASN1_TIME(bio, atime, key )	\
	ASN1_TIME_print(bio,atime);					\
	ADD_ASSOC_BIO(bio, key);					\
	lua_pushfstring(L, "%s_time_t", key);			\
	lua_pushinteger(L, (lua_Integer)asn1_time_to_time_t(atime));	\
	lua_settable (L,-3)

void add_assoc_name_entry(lua_State*L, char * key, X509_NAME * name, int shortname) ;
void add_assoc_x509_extension(lua_State*L, char* key, STACK_OF(X509_EXTENSION)* ext, BIO* bio);

void add_assoc_string(lua_State *L, const char*name, const char*val, int flag);
void add_index_bool(lua_State* L, int i, int b);
void add_assoc_int(lua_State* L, const char* i, int b);

time_t asn1_time_to_time_t(ASN1_UTCTIME * timestr);
int openssl_object_create(lua_State* L);

int openssl_register_digest(lua_State* L);
int openssl_register_cipher(lua_State* L);
int openssl_register_x509(lua_State* L);
int openssl_register_sk_x509(lua_State* L);
int openssl_register_pkey(lua_State* L);
int openssl_register_csr(lua_State* L);
int openssl_register_bio(lua_State* L);
int openssl_register_crl(lua_State* L);
int openssl_register_ts(lua_State* L);
int openssl_register_conf(lua_State* L);

int openssl_register_pkcs7(lua_State* L);
int openssl_register_misc(lua_State* L);

#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
