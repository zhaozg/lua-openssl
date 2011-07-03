#ifndef LUA_EAY_H
#define LUA_EAY_H
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "auxiliar.h"

#include <assert.h>
#include "openssl.h"

/* PHP Includes */

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

/* Common */
#include <time.h>

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
#endif

/* FIXME: Use the openssl constants instead of
 * enum. It is now impossible to match real values
 * against php constants. Also sorry to break the
 * enum principles here, BC...
 */
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



struct x509_request { /* {{{ */
#if OPENSSL_VERSION_NUMBER >= 0x10000002L
	LHASH_OF(CONF_VALUE) * global_config;	/* Global SSL config */
	LHASH_OF(CONF_VALUE) * req_config;		/* SSL config for this request */
#else
	LHASH * global_config;  /* Global SSL config */
	LHASH * req_config;             /* SSL config for this request */
#endif
	const EVP_MD * md_alg;
	const EVP_MD * digest;
	const char	* section_name,
		* config_filename,
		* digest_name,
		* extensions_section,
		* request_extensions_section;
	int priv_key_bits;
	int priv_key_type;

	int priv_key_encrypt;

	EVP_PKEY * priv_key;
};
/* }}} */

int check_cert(X509_STORE *ctx, X509 *x, STACK_OF(X509) *untrustedchain, int purpose);
X509_STORE * setup_verify(STACK_OF(X509)* calist);
void add_assoc_asn1_string(lua_State*L, char * key, ASN1_STRING * str);

int openssl_parse_config(lua_State*L, struct x509_request * req, int n);
void openssl_dispose_config(struct x509_request * req) ;
#if OPENSSL_VERSION_NUMBER >= 0x10000002L
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH_OF(CONF_VALUE) * config);
#else
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH * config);
#endif

#define SSL_REQ_INIT(req)		memset(req, 0, sizeof(*req))
#define SSL_REQ_DISPOSE(req)	openssl_dispose_config(req)
#define SSL_REQ_PARSE(L, req, n)	openssl_parse_config(L, req, n)
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

LUA_FUNCTION(openssl_pkey_tostring);
LUA_FUNCTION(openssl_pkey_read);
LUA_FUNCTION(openssl_pkey_export);
LUA_FUNCTION(openssl_pkey_free);
LUA_FUNCTION(openssl_pkey_new);
LUA_FUNCTION(openssl_pkey_is_private);
LUA_FUNCTION(openssl_pkey_get_details);

LUA_FUNCTION(openssl_sign);
LUA_FUNCTION(openssl_verify);
LUA_FUNCTION(openssl_seal);
LUA_FUNCTION(openssl_open);
LUA_FUNCTION(openssl_private_encrypt);
LUA_FUNCTION(openssl_private_decrypt);
LUA_FUNCTION(openssl_public_encrypt);
LUA_FUNCTION(openssl_public_decrypt);

LUA_FUNCTION(openssl_pkcs7_verify);
LUA_FUNCTION(openssl_pkcs7_decrypt);
LUA_FUNCTION(openssl_pkcs7_sign);
LUA_FUNCTION(openssl_pkcs7_encrypt);

LUA_FUNCTION(openssl_error_string);


LUA_FUNCTION(openssl_pkcs12_export);
LUA_FUNCTION(openssl_pkcs12_export_to_file);
LUA_FUNCTION(openssl_pkcs12_read);

LUA_FUNCTION(openssl_csr_new);
LUA_FUNCTION(openssl_csr_export);
LUA_FUNCTION(openssl_csr_export_to_file);
LUA_FUNCTION(openssl_csr_sign);
LUA_FUNCTION(openssl_csr_get_subject);
LUA_FUNCTION(openssl_csr_get_public_key);


LUA_FUNCTION(openssl_encrypt);
LUA_FUNCTION(openssl_decrypt);
LUA_FUNCTION(openssl_cipher_iv_length);

LUA_FUNCTION(openssl_dh_compute_key);
LUA_FUNCTION(openssl_random_pseudo_bytes);

LUA_FUNCTION(openssl_get_digest);
LUA_FUNCTION(openssl_get_cipher);

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) ;
void openssl_add_method(const OBJ_NAME *name, void *arg);

#define CHECK_OBJECT(n,type,name) *(type**)luaL_checkudata(L,n,name)
#define PUSH_OBJECT(o, tname)  do {							\
	*(void **)(lua_newuserdata(L, sizeof(void *))) = (o);	\
	auxiliar_setclass(L,tname,-1);} while(0)

void add_assoc_name_entry(lua_State*L, char * key, X509_NAME * name, int shortname) ;
void add_assoc_string(lua_State *L, const char*name, const char*val, int flag);
void add_index_bool(lua_State* L, int i, int b);
void add_assoc_int(lua_State* L, const char* i, int b);

void add_assoc_asn1_time(lua_State*L, char * key, ASN1_UTCTIME * timestr);
STACK_OF(X509) * load_all_certs_from_file(const char *certfile);

int openssl_load_rand_file(const char * file, int *egdsocket, int *seeded);
int openssl_write_rand_file(const char * file, int egdsocket, int seeded) ;

const EVP_CIPHER * openssl_get_evp_cipher_from_algo(long algo) ;


int openssl_register_digest(lua_State* L);

#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
