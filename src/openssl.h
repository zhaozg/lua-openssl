/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2012 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/
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
int luaL_typerror (lua_State *L, int narg, const char *tname);
#endif

#include <assert.h>

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
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/lhash.h>
#define OPENSSL_HAVE_TS
#define LHASH LHASH_OF(CONF_VALUE)
#endif
typedef unsigned char byte;

#define MULTI_LINE_MACRO_BEGIN do {  
#define MULTI_LINE_MACRO_END	\
__pragma(warning(push))		\
__pragma(warning(disable:4127)) \
} while(0)			\
__pragma(warning(pop)) 

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

#if OPENSSL_VERSION_NUMBER >= 0x10000002L
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH_OF(CONF_VALUE) * config); 
#else
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH * config);
#endif


extern char default_ssl_conf_filename[MAX_PATH];


#define LUA_FUNCTION(X) int X(lua_State *L)

LUA_FUNCTION(openssl_bio_new_mem);
LUA_FUNCTION(openssl_bio_new_file);
LUA_FUNCTION(openssl_bio_read);
LUA_FUNCTION(openssl_bio_gets);
LUA_FUNCTION(openssl_bio_write);
LUA_FUNCTION(openssl_bio_puts);
LUA_FUNCTION(openssl_bio_get_mem);
LUA_FUNCTION(openssl_bio_close);
LUA_FUNCTION(openssl_bio_free);
LUA_FUNCTION(openssl_bio_type);
LUA_FUNCTION(openssl_bio_reset);
LUA_FUNCTION(openssl_bio_tostring);
LUA_FUNCTION(openssl_get_cipher);
LUA_FUNCTION(openssl_cipher_info);
LUA_FUNCTION(openssl_cipher_tostring);
LUA_FUNCTION(openssl_evp_BytesToKey);
LUA_FUNCTION(openssl_evp_encrypt_init);
LUA_FUNCTION(openssl_evp_encrypt_update);
LUA_FUNCTION(openssl_evp_encrypt_final);
LUA_FUNCTION(openssl_evp_decrypt_init);
LUA_FUNCTION(openssl_evp_decrypt_update);
LUA_FUNCTION(openssl_evp_decrypt_final);
LUA_FUNCTION(openssl_evp_cipher_init);
LUA_FUNCTION(openssl_evp_cipher_update);
LUA_FUNCTION(openssl_evp_cipher_final);
LUA_FUNCTION(openssl_cipher_ctx_info);
LUA_FUNCTION(openssl_cipher_ctx_tostring);
LUA_FUNCTION(openssl_cipher_ctx_free);
LUA_FUNCTION(openssl_cipher_ctx_cleanup);
LUA_FUNCTION(openssl_evp_encrypt);
LUA_FUNCTION(openssl_evp_decrypt);
LUA_FUNCTION(openssl_conf_load);
LUA_FUNCTION(openssl_conf_gc);
LUA_FUNCTION(openssl_conf_tostring);
LUA_FUNCTION(openssl_conf_get_number);
LUA_FUNCTION(openssl_conf_get_string);
LUA_FUNCTION(openssl_conf_parse);
LUA_FUNCTION(openssl_crl_new);
LUA_FUNCTION(openssl_crl_read);
LUA_FUNCTION(openssl_crl_set_version);
LUA_FUNCTION(openssl_crl_set_issuer);
LUA_FUNCTION(openssl_crl_set_updatetime);
LUA_FUNCTION(openssl_crl_sort);
LUA_FUNCTION(openssl_crl_verify);
LUA_FUNCTION(openssl_crl_sign);
LUA_FUNCTION(openssl_crl_add_revocked);
LUA_FUNCTION(openssl_crl_parse);
LUA_FUNCTION(openssl_crl_tostring);
LUA_FUNCTION(openssl_crl_free);
LUA_FUNCTION(openssl_register_crl);
LUA_FUNCTION(openssl_csr_parse);
LUA_FUNCTION(openssl_csr_read);
LUA_FUNCTION(openssl_csr_export);
LUA_FUNCTION(openssl_csr_sign);
LUA_FUNCTION(openssl_csr_export);
LUA_FUNCTION(openssl_csr_sign);
LUA_FUNCTION(openssl_csr_new);
LUA_FUNCTION(openssl_csr_parse);
LUA_FUNCTION(openssl_register_csr);
LUA_FUNCTION(openssl_get_digest);
LUA_FUNCTION(openssl_digest_info);
LUA_FUNCTION(openssl_digest_digest);
LUA_FUNCTION(openssl_digest_tostring);
LUA_FUNCTION(openssl_evp_digest_init);
LUA_FUNCTION(openssl_evp_digest_update);
LUA_FUNCTION(openssl_evp_digest_final);
LUA_FUNCTION(openssl_digest_ctx_info);
LUA_FUNCTION(openssl_digest_ctx_tostring);
LUA_FUNCTION(openssl_digest_ctx_free);
LUA_FUNCTION(openssl_digest_ctx_cleanup);
LUA_FUNCTION(openssl_random_bytes);
LUA_FUNCTION(openssl_x509_algo_parse);
LUA_FUNCTION(openssl_x509_algo_tostring);
LUA_FUNCTION(openssl_x509_extension_parse);
LUA_FUNCTION(openssl_x509_extension_tostring);
LUA_FUNCTION(openssl_ec_list_curve_name);
LUA_FUNCTION(openssl_error_string);
LUA_FUNCTION(openssl_sign);
LUA_FUNCTION(openssl_verify);
LUA_FUNCTION(openssl_seal);

LUA_FUNCTION(openssl_dh_compute_key);
LUA_FUNCTION(openssl_ts_resp_ctx_new);
LUA_FUNCTION(openssl_ts_sign);
LUA_FUNCTION(openssl_ts_resp_ctx_gc);
LUA_FUNCTION(openssl_ts_resp_ctx_tostring);
LUA_FUNCTION(openssl_ts_req_new);
LUA_FUNCTION(openssl_ts_req_gc);
LUA_FUNCTION(openssl_ts_req_tostring);
LUA_FUNCTION(openssl_ts_req_to_verify_ctx);
LUA_FUNCTION(openssl_ts_req_parse);
LUA_FUNCTION(openssl_ts_req_i2d);
LUA_FUNCTION(openssl_ts_req_d2i);
LUA_FUNCTION(openssl_ts_resp_gc);
LUA_FUNCTION(openssl_ts_resp_i2d);
LUA_FUNCTION(openssl_ts_resp_parse);
LUA_FUNCTION(openssl_ts_resp_d2i);
LUA_FUNCTION(openssl_ts_resp_tst_info);
LUA_FUNCTION(openssl_ts_resp_tostring);
LUA_FUNCTION(openssl_ts_verify_ctx_new);
LUA_FUNCTION(openssl_ts_verify_ctx_gc);
LUA_FUNCTION(openssl_ts_verify_ctx_response);
LUA_FUNCTION(openssl_ts_verify_ctx_token);
LUA_FUNCTION(openssl_ts_verify_ctx_tostring);
LUA_FUNCTION(openssl_pkcs12_export);
LUA_FUNCTION(openssl_pkcs12_read);
LUA_FUNCTION(openssl_pkcs7_read);
LUA_FUNCTION(openssl_pkcs7_gc);
LUA_FUNCTION(openssl_pkcs7_tostring);
LUA_FUNCTION(openssl_pkcs7_export);
LUA_FUNCTION(openssl_pkcs7_parse);
LUA_FUNCTION(openssl_pkcs7_sign);
LUA_FUNCTION(openssl_pkcs7_verify);
LUA_FUNCTION(openssl_pkcs7_encrypt);
LUA_FUNCTION(openssl_pkcs7_decrypt);
LUA_FUNCTION(openssl_pkey_new);
LUA_FUNCTION(openssl_pkey_export);
LUA_FUNCTION(openssl_pkey_free);
LUA_FUNCTION(openssl_pkey_parse);
LUA_FUNCTION(openssl_pkey_read);
LUA_FUNCTION(openssl_pkey_encrypt);
LUA_FUNCTION(openssl_pkey_decrypt);
LUA_FUNCTION(openssl_pkey_is_private);
LUA_FUNCTION(openssl_pkey_tostring);
LUA_FUNCTION(openssl_x509_read);
LUA_FUNCTION(openssl_x509_export);
LUA_FUNCTION(openssl_x509_check_private_key);
LUA_FUNCTION(openssl_x509_parse);
LUA_FUNCTION(openssl_x509_checkpurpose);
LUA_FUNCTION(openssl_x509_free);
LUA_FUNCTION(openssl_x509_tostring);
LUA_FUNCTION(openssl_x509_public_key);
LUA_FUNCTION(openssl_sk_x509_read);
LUA_FUNCTION(openssl_sk_x509_new);

LUA_API LUA_FUNCTION(openssl_open);

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) ;
void openssl_add_method(const OBJ_NAME *name, void *arg);

#define CHECK_OBJECT(n,type,name) *(type**)luaL_checkudata(L,n,name)

#define PUSH_OBJECT(o, tname)		\
	MULTI_LINE_MACRO_BEGIN		\
	*(void **)(lua_newuserdata(L, sizeof(void *))) = (o);	\
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

void add_assoc_name_entry(lua_State*L, const  char * key, X509_NAME * name, int shortname);
void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* ext, BIO* bio);

void add_assoc_string(lua_State *L, const char*name, const char*val);
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

