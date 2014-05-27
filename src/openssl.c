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
* main routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/opensslconf.h>

#if LUA_VERSION_NUM>501
int luaL_typerror (lua_State *L, int narg, const char *tname) {
  const char *msg = lua_pushfstring(L, "%s expected, got %s",
                                    tname, luaL_typename(L, narg));
  return luaL_argerror(L, narg, msg);
}
#endif

static int openssl_version(lua_State*L)
{
		lua_pushstring(L, LOPENSSL_VERSION_STR);
		lua_pushstring(L, LUA_VERSION);
		lua_pushstring(L, OPENSSL_VERSION_TEXT);
		return 3;
}
/* true global; readonly after module startup */
char default_ssl_conf_filename[MAX_PATH];


typedef struct {
	const char* name;
	int value;
} namedInteger;

static namedInteger consts[] = {
	{"LEAVE",       -1},
	{"ENGINE_F_DYNAMIC_CTRL",					 ENGINE_F_DYNAMIC_CTRL},
	{"ENGINE_F_DYNAMIC_GET_DATA_CTX",			 ENGINE_F_DYNAMIC_GET_DATA_CTX},
	{"ENGINE_F_DYNAMIC_LOAD",					 ENGINE_F_DYNAMIC_LOAD},
	{"ENGINE_F_DYNAMIC_SET_DATA_CTX",			 ENGINE_F_DYNAMIC_SET_DATA_CTX},
	{"ENGINE_F_ENGINE_ADD",						 ENGINE_F_ENGINE_ADD},
	{"ENGINE_F_ENGINE_BY_ID",					 ENGINE_F_ENGINE_BY_ID},
	{"ENGINE_F_ENGINE_CMD_IS_EXECUTABLE",		 ENGINE_F_ENGINE_CMD_IS_EXECUTABLE},
	{"ENGINE_F_ENGINE_CTRL",					 ENGINE_F_ENGINE_CTRL},
	{"ENGINE_F_ENGINE_CTRL_CMD",				 ENGINE_F_ENGINE_CTRL_CMD},
	{"ENGINE_F_ENGINE_CTRL_CMD_STRING",			 ENGINE_F_ENGINE_CTRL_CMD_STRING},
	{"ENGINE_F_ENGINE_FINISH",					 ENGINE_F_ENGINE_FINISH},
	{"ENGINE_F_ENGINE_FREE_UTIL",				 ENGINE_F_ENGINE_FREE_UTIL},
	{"ENGINE_F_ENGINE_GET_CIPHER",				 ENGINE_F_ENGINE_GET_CIPHER},
	{"ENGINE_F_ENGINE_GET_DEFAULT_TYPE",		 ENGINE_F_ENGINE_GET_DEFAULT_TYPE},
	{"ENGINE_F_ENGINE_GET_DIGEST",				 ENGINE_F_ENGINE_GET_DIGEST},
	{"ENGINE_F_ENGINE_GET_NEXT",				 ENGINE_F_ENGINE_GET_NEXT},
	{"ENGINE_F_ENGINE_GET_PREV",				 ENGINE_F_ENGINE_GET_PREV},
	{"ENGINE_F_ENGINE_INIT",					 ENGINE_F_ENGINE_INIT},
	{"ENGINE_F_ENGINE_LIST_ADD",				 ENGINE_F_ENGINE_LIST_ADD},
	{"ENGINE_F_ENGINE_LIST_REMOVE",				 ENGINE_F_ENGINE_LIST_REMOVE},
	{"ENGINE_F_ENGINE_LOAD_PRIVATE_KEY",		 ENGINE_F_ENGINE_LOAD_PRIVATE_KEY},
	{"ENGINE_F_ENGINE_LOAD_PUBLIC_KEY",			 ENGINE_F_ENGINE_LOAD_PUBLIC_KEY},
#ifdef ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT
	{"ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT",	 ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT},
#endif
	{"ENGINE_F_ENGINE_NEW",						 ENGINE_F_ENGINE_NEW},
	{"ENGINE_F_ENGINE_REMOVE",					 ENGINE_F_ENGINE_REMOVE},
	{"ENGINE_F_ENGINE_SET_DEFAULT_STRING",		 ENGINE_F_ENGINE_SET_DEFAULT_STRING},
	{"ENGINE_F_ENGINE_SET_DEFAULT_TYPE",		 ENGINE_F_ENGINE_SET_DEFAULT_TYPE},
	{"ENGINE_F_ENGINE_SET_ID",					 ENGINE_F_ENGINE_SET_ID},
	{"ENGINE_F_ENGINE_SET_NAME",				 ENGINE_F_ENGINE_SET_NAME},
	{"ENGINE_F_ENGINE_TABLE_REGISTER",			 ENGINE_F_ENGINE_TABLE_REGISTER},
	{"ENGINE_F_ENGINE_UNLOAD_KEY",				 ENGINE_F_ENGINE_UNLOAD_KEY},
	{"ENGINE_F_ENGINE_UNLOCKED_FINISH",			 ENGINE_F_ENGINE_UNLOCKED_FINISH},
	{"ENGINE_F_ENGINE_UP_REF",					 ENGINE_F_ENGINE_UP_REF},
	{"ENGINE_F_INT_CTRL_HELPER",				 ENGINE_F_INT_CTRL_HELPER},
	{"ENGINE_F_INT_ENGINE_CONFIGURE",			 ENGINE_F_INT_ENGINE_CONFIGURE},
	{"ENGINE_F_INT_ENGINE_MODULE_INIT",			 ENGINE_F_INT_ENGINE_MODULE_INIT},
	{"ENGINE_F_LOG_MESSAGE",					 ENGINE_F_LOG_MESSAGE},
	{"ENGINE_METHOD_RSA",	 	ENGINE_METHOD_RSA},
	{"ENGINE_METHOD_DSA",		ENGINE_METHOD_DSA},
	{"ENGINE_METHOD_DH",		ENGINE_METHOD_DH},
	{"ENGINE_METHOD_RAND",	ENGINE_METHOD_RAND},
	{"ENGINE_METHOD_ECDH",	ENGINE_METHOD_ECDH},
	{"ENGINE_METHOD_ECDSA",	ENGINE_METHOD_ECDSA},
	{"ENGINE_METHOD_CIPHERS",	ENGINE_METHOD_CIPHERS},
	{"ENGINE_METHOD_DIGESTS",	ENGINE_METHOD_DIGESTS},
	{"ENGINE_METHOD_STORE",	ENGINE_METHOD_STORE},
	{"ENGINE_METHOD_ALL",		ENGINE_METHOD_ALL},
	{"ENGINE_METHOD_NONE",	ENGINE_METHOD_NONE},

	{NULL,	-1}
};

void setNamedIntegers(lua_State* L, namedInteger* p) {
	while(p->name) {
		lua_pushinteger(L, p->value);
		lua_setfield(L, -2, p->name);
		p++;
	}
}

int openssl_topointer(lua_State*L){
	void* p = NULL;
	if(lua_isuserdata(L, 1))
		p = *(void**)lua_touserdata(L,1);
	else if(lua_islightuserdata(L, 1)){
		p = lua_touserdata(L,1);
	}
	if(p)
		lua_pushlightuserdata(L, p);
	else
		lua_pushnil(L);
	return 1;
}


const BIT_STRING_BITNAME reason_flags[] = {
	{0, "Unused", "unused"},
	{1, "Key Compromise", "keyCompromise"},
	{2, "CA Compromise", "CACompromise"},
	{3, "Affiliation Changed", "affiliationChanged"},
	{4, "Superseded", "superseded"},
	{5, "Cessation Of Operation", "cessationOfOperation"},
	{6, "Certificate Hold", "certificateHold"},
	{7, "Privilege Withdrawn", "privilegeWithdrawn"},
	{8, "AA Compromise", "AACompromise"},
	{-1, NULL, NULL}
};

const int reason_num = sizeof(reason_flags)/sizeof(BIT_STRING_BITNAME) - 1;


/* {{{ openssl_functions[]
 */
static const luaL_Reg eay_functions[] = {
	{"topointer",			openssl_topointer	},
    /* pkey */
    {"pkey_read",			openssl_pkey_read	},
    {"pkey_new",			openssl_pkey_new	},

    /* x.509 cert funcs */
    {"x509_read",			openssl_x509_read	},
    {"sk_x509_read",			openssl_sk_x509_read	},
    {"sk_x509_new",			openssl_sk_x509_new	},


    /* CSR funcs */
    {"csr_new",				openssl_csr_new	},
    {"csr_read",			openssl_csr_read	},

    /* CRL funcs */
    {"crl_new",				openssl_crl_new	},
    {"crl_read",			openssl_crl_read	},

    /* cipher/digest functions */
    {"get_digest",			openssl_get_digest},
    {"get_cipher",			openssl_get_cipher},

    /* misc function */
    {"random_bytes",		openssl_random_bytes	},
    {"error_string",		openssl_error_string	},
    {"object_create",		openssl_object_create	},
    {"bio_new_file",		openssl_bio_new_file	},
    {"bio_new_mem",			openssl_bio_new_mem	   },
	{"bio_new_accept",		openssl_bio_new_accept },

    {"sign",				openssl_sign	},
    {"verify",				openssl_verify	},
    {"seal",				openssl_seal	},
    {"open",				openssl_open	},

    /* PKCS12 funcs */
    {"pkcs12_export",		openssl_pkcs12_export	},
    {"pkcs12_read",			openssl_pkcs12_read	},

    /* for S/MIME handling */
    {"pkcs7_read",			openssl_pkcs7_read	},
    {"pkcs7_verify",		openssl_pkcs7_verify	},
    {"pkcs7_decrypt",		openssl_pkcs7_decrypt	},
    {"pkcs7_sign",			openssl_pkcs7_sign		},
    {"pkcs7_encrypt",		openssl_pkcs7_encrypt	},

    {"dh_compute_key",		openssl_dh_compute_key	},

#ifdef OPENSSL_HAVE_TS
    /* timestamp handling */
    {"ts_req_new",		openssl_ts_req_new	},
    {"ts_req_d2i",		openssl_ts_req_d2i	},
    {"ts_resp_d2i",		openssl_ts_resp_d2i	},
    {"ts_resp_ctx_new",		openssl_ts_resp_ctx_new	},
    {"ts_verify_ctx_new",	openssl_ts_verify_ctx_new	},
#endif

	{"engine",			openssl_engine},
#ifdef EVP_PKEY_EC
    {"list_curve_name",	openssl_ec_list_curve_name },
#endif
	{"ssl_ctx_new",		openssl_ssl_ctx_new },
	{"ssl_session_new",	openssl_ssl_session_read},

    /* conf handle */
    {"conf_load",		openssl_conf_load	},
	{"version",			openssl_version },

	/* ocsp handle */
	{"ocsp_request_read", openssl_ocsp_request_new},
	{"ocsp_request_new", openssl_ocsp_request_new},
	{"ocsp_response_new", openssl_ocsp_response},
	{"ocsp_response_read",openssl_ocsp_response},

    {NULL, NULL}
};
/* }}} */
#if 0
static int ssl_stream_data_index;


/* {{{ openssl safe_mode & open_basedir checks */
inline static int openssl_safe_mode_chk(char *filename)
{
    if (PG(safe_mode) && (!checkuid(filename, NULL, CHECKUID_CHECK_FILE_AND_DIR))) {
        return -1;
    }
    if (check_open_basedir(filename)) {
        return -1;
    }

    return 0;
}
/* }}} */

#endif



#if OPENSSL_VERSION_NUMBER >= 0x10000002L
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH_OF(CONF_VALUE) * config) /* {{{ */
#else
int openssl_config_check_syntax(const char * section_label, const char * config_filename, const char * section, LHASH * config)
#endif
{
    X509V3_CTX ctx;

    X509V3_set_ctx_test(&ctx);
    X509V3_set_conf_lhash(&ctx, config);
    if (!X509V3_EXT_add_conf(config, &ctx, (char *)section, NULL)) {
        printf("Error loading %s section %s of %s",
               section_label,
               section,
               config_filename);
        return -1;
    }
    return 0;
}



/* {{{ proto mixed openssl_error_string(void)
   Returns a description of the last error, and alters the index of the error messages. Returns false when the are no more messages */
LUA_FUNCTION(openssl_error_string)
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
/* }}} */

/* {{{ proto signature openssl_sign(string data,  evp_pkey key [, digest md|string md_alg=SHA1]) ->string
   Signs data */
LUA_FUNCTION(openssl_sign)
{
    size_t data_len;
    const char * data = luaL_checklstring(L,1,&data_len);
    EVP_PKEY *pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");

    int siglen;
    unsigned char *sigbuf;

    EVP_MD_CTX md_ctx;

    int ret = 0;
    int top = lua_gettop(L);

    const EVP_MD *mdtype = NULL;
    if(top>2) {
        if(lua_isstring(L,3))
            mdtype = EVP_get_digestbyname(lua_tostring(L,3));
        else if(lua_isuserdata(L,3))
            mdtype = CHECK_OBJECT(3,EVP_MD,"openssl.evp_digest");
        else
            luaL_error(L, "#3 must be nil, string, or openssl.evp_digest object");
    }
    if(!mdtype)
        mdtype = EVP_get_digestbynid(OPENSSL_ALGO_SHA1);

    siglen = EVP_PKEY_size(pkey);
    sigbuf = malloc(siglen + 1);

    EVP_SignInit(&md_ctx, mdtype);
    EVP_SignUpdate(&md_ctx, data, data_len);
    if (EVP_SignFinal (&md_ctx, sigbuf,(unsigned int *)&siglen, pkey)) {
        lua_pushlstring(L,(char *)sigbuf, siglen);
        ret = 1;
    }
    free(sigbuf);
    EVP_MD_CTX_cleanup(&md_ctx);
    return ret;
}
/* }}} */

/* {{{ proto int openssl_verify(string data, string signature, evp_pkey key[, digest md|string md_alg=SHA1]) ->boolean
   Verifys data */
LUA_FUNCTION(openssl_verify)
{
    size_t data_len, signature_len;
    const char* data = luaL_checklstring(L,1,&data_len);
    const char* signature = luaL_checklstring(L,2,&signature_len);

    EVP_PKEY *pkey = CHECK_OBJECT(3,EVP_PKEY,"openssl.evp_pkey");
    int top = lua_gettop(L);
    int err;
    EVP_MD_CTX     md_ctx;

    const EVP_MD *mdtype = NULL;
    if(top>3) {
        if(lua_isstring(L,4))
            mdtype = EVP_get_digestbyname(lua_tostring(L,4));
        else if(lua_isuserdata(L,4))
            mdtype = CHECK_OBJECT(4,EVP_MD,"openssl.evp_digest");
        else
            luaL_error(L, "#4 must be nil, string, or openssl.evp_digest object");
    }
    if(!mdtype)
        mdtype = EVP_get_digestbynid(OPENSSL_ALGO_SHA1);


    EVP_VerifyInit   (&md_ctx, mdtype);
    EVP_VerifyUpdate (&md_ctx, data, data_len);
    err = EVP_VerifyFinal (&md_ctx, (unsigned char *)signature, signature_len, pkey);
    EVP_MD_CTX_cleanup(&md_ctx);
    lua_pushinteger(L,err);

    return 1;
}
/* }}} */


/* {{{ proto sealdata,ekeys openssl_seal(string data, tables pubkeys [, cipher enc|string md_alg=RC4])
   Seals data */
LUA_FUNCTION(openssl_seal)
{
    size_t data_len;
    const char * data = luaL_checklstring(L,1,&data_len);

    EVP_PKEY **pkeys;

    int i, len1, len2, *eksl, nkeys;
    unsigned char *buf;
    unsigned char **eks;

    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX ctx;
    int ret = 0;
    int top = lua_gettop(L);


    luaL_checktype(L,2, LUA_TTABLE);
    nkeys = lua_objlen(L,2);
    if (!nkeys) {
        luaL_error(L,"#2 argument to openssl_seal() must be a non-empty table");
    }

    if(top>2) {
        if(lua_isstring(L,3))
            cipher = EVP_get_cipherbyname(lua_tostring(L,3));
        else if(lua_isuserdata(L,3))
            cipher = CHECK_OBJECT(3,EVP_CIPHER,"openssl.evp_cipher");
        else
            luaL_error(L, "#3 argument must be nil, string, or openssl.evp_cipher object");
    }
    if(!cipher)
        cipher = EVP_rc4();

    pkeys = malloc(nkeys*sizeof(*pkeys));
    eksl = malloc(nkeys*sizeof(*eksl));
    eks = malloc(nkeys*sizeof(*eks));
    memset(eks, 0, sizeof(*eks) * nkeys);

    /* get the public keys we are using to seal this data */
    for(i=0; i<nkeys; i++) {
        lua_rawgeti(L,2,i+1);

        pkeys[i] =  CHECK_OBJECT(-1,EVP_PKEY, "openssl.evp_pkey");
        if (pkeys[i] == NULL) {
            luaL_error(L,"not a public key (%dth member of pubkeys)", i+1);
        }
        eks[i] = malloc(EVP_PKEY_size(pkeys[i]) + 1);
        lua_pop(L,1);
    }
    if (!EVP_EncryptInit(&ctx,cipher,NULL,NULL)) {
        luaL_error(L,"EVP_EncryptInit failed");
    }

    /* allocate one byte extra to make room for \0 */
    len1 = data_len + EVP_CIPHER_CTX_block_size(&ctx)+1;
    buf = malloc(data_len + EVP_CIPHER_CTX_block_size(&ctx));
    if (!EVP_SealInit(&ctx, cipher, eks, eksl, NULL, pkeys, nkeys) || !EVP_SealUpdate(&ctx, buf, &len1, (unsigned char *)data, data_len)) {
        free(buf);
        luaL_error(L,"EVP_SealInit failed");
    }

    EVP_SealFinal(&ctx, buf + len1, &len2);

    if (len1 + len2 > 0) {
        buf[len1 + len2] = '\0';
        lua_pushlstring(L,(const char*)buf,len1 + len2);

        lua_newtable(L);
        for (i=0; i<nkeys; i++) {
            eks[i][eksl[i]] = '\0';
            lua_pushlstring(L, (const char*)eks[i], eksl[i]);
            free(eks[i]);
            eks[i] = NULL;
            lua_rawseti(L,-2, i+1);
        }
        ret = 2;

    }

    free(buf);
    free(eks);
    free(eksl);
    free(pkeys);
    return ret;
}
/* }}} */

/* {{{ proto opendata openssl_open(string data, string ekey, mixed privkey, [, cipher enc|string md_alg=RC4])
   Opens data */
LUA_API LUA_FUNCTION(openssl_open)
{
    size_t data_len, ekey_len;
    const char * data = luaL_checklstring(L, 1, &data_len);
    const char * ekey = luaL_checklstring(L, 2, &ekey_len);
    EVP_PKEY *pkey =  CHECK_OBJECT(3,EVP_PKEY, "openssl.evp_pkey");
    int top = lua_gettop(L);

    int len1, len2 = 0;
    unsigned char *buf;

    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = NULL;

    if(top>3) {
        if(lua_isstring(L,4))
            cipher = EVP_get_cipherbyname(lua_tostring(L,4));
        else if(lua_isuserdata(L,4))
            cipher = CHECK_OBJECT(4,EVP_CIPHER,"openssl.evp_cipher");
        else
            luaL_error(L, "#4 argument must be nil, string, or openssl.evp_cipher object");
    }
    if(!cipher)
        cipher = EVP_rc4();

    len1 = data_len + 1;
    buf = malloc(len1);

    if (EVP_OpenInit(&ctx, cipher, (unsigned char *)ekey, ekey_len, NULL, pkey) && EVP_OpenUpdate(&ctx, buf, &len1, (unsigned char *)data, data_len))
	{
		len2 = data_len - len1;
	    if (!EVP_OpenFinal(&ctx, buf + len1, &len2) || (len1 + len2 == 0))
		{
			luaL_error(L,"EVP_OpenFinal() failed.");
			free(buf);
			return 0;
		}
	}
	else
	{
		luaL_error(L,"EVP_OpenInit() failed.");
		free(buf);
		return 0;
	}

    buf[len1 + len2] = '\0';
    lua_pushlstring(L, (const char*)buf, len1 + len2);
    free(buf);
    return 1;
}
/* }}} */

/* SSL verification functions */

#define GET_VER_OPT(name)               (stream->context && 0 == stream_context_get_option(stream->context, "ssl", name, &val))
#define GET_VER_OPT_STRING(name, str)   if (GET_VER_OPT(name)) { convert_to_string_ex(val); str = Z_STRVAL_PP(val); }
#if 0
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) /* {{{ */
{
    void *stream;
    SSL *ssl;
    X509 *err_cert;
    int err, depth, ret;

    ret = preverify_ok;

    /* determine the status for the current cert */
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    /* conjure the stream & context to use */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    stream = SSL_get_ex_data(ssl, ssl_stream_data_index);

    /* if allow_self_signed is set, make sure that verification succeeds */
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT && GET_VER_OPT("allow_self_signed") && zval_is_true(*val)) {
        ret = 1;
    }

    /* check the depth */
    if (GET_VER_OPT("verify_depth")) {
        convert_to_long_ex(val);

        if (depth > Z_LVAL_PP(val)) {
            ret = 0;
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
        }
    }

    return ret;

}
/* }}} */

int openssl_apply_verification_policy(SSL *ssl, X509 *peer, stream *stream) /* {{{ */
{
    zval **val = NULL;
    char *cnmatch = NULL;
    X509_NAME *name;
    char buf[1024];
    int err;

    /* verification is turned off */
    if (!(GET_VER_OPT("verify_peer") && zval_is_true(*val))) {
        return 0;
    }

    if (peer == NULL) {
        error_docref(NULL, E_WARNING, "Could not get peer certificate");
        return -1;
    }

    err = SSL_get_verify_result(ssl);
    switch (err) {
    case X509_V_OK:
        /* fine */
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        if (GET_VER_OPT("allow_self_signed") && zval_is_true(*val)) {
            /* allowed */
            break;
        }
        /* not allowed, so fall through */
    default:
        error_docref(NULL, E_WARNING, "Could not verify peer: code:%d %s", err, X509_verify_cert_error_string(err));
        return -1;
    }

    /* if the cert passed the usual checks, apply our own local policies now */

    name = X509_get_subject_name(peer);

    /* Does the common name match ? (used primarily for https://) */
    GET_VER_OPT_STRING("CN_match", cnmatch);
    if (cnmatch) {
        int match = 0;
        int name_len = X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf));

        if (name_len == -1) {
            error_docref(NULL, E_WARNING, "Unable to locate peer certificate CN");
            return -1;
        } else if (name_len != strlen(buf)) {
            error_docref(NULL, E_WARNING, "Peer certificate CN=`%.*s' is malformed", name_len, buf);
            return -1;
        }

        match = strcmp(cnmatch, buf) == 0;
        if (!match && strlen(buf) > 3 && buf[0] == '*' && buf[1] == '.') {
            /* Try wildcard */

            if (strchr(buf+2, '.')) {
                char *tmp = strstr(cnmatch, buf+1);

                match = tmp && strcmp(tmp, buf+2) && tmp == strchr(cnmatch, '.');
            }
        }

        if (!match) {
            /* didn't match */
            error_docref(NULL, E_WARNING, "Peer certificate CN=`%.*s' did not match expected CN=`%s'", name_len, buf, cnmatch);
            return -1;
        }
    }

    return 0;
}
/* }}} */

static int passwd_callback(char *buf, int num, int verify, void *data) /* {{{ */
{
    stream *stream = (stream *)data;
    zval **val = NULL;
    char *passphrase = NULL;
    /* TODO: could expand this to make a callback into Lua user-space */

    GET_VER_OPT_STRING("passphrase", passphrase);

    if (passphrase) {
        if (Z_STRLEN_PP(val) < num - 1) {
            memcpy(buf, Z_STRVAL_PP(val), Z_STRLEN_PP(val)+1);
            return Z_STRLEN_PP(val);
        }
    }
    return 0;
}
/* }}} */

SSL *SSL_new_from_context(SSL_CTX *ctx, stream *stream) /* {{{ */
{
    zval **val = NULL;
    char *cafile = NULL;
    char *capath = NULL;
    char *certfile = NULL;
    char *cipherlist = NULL;
    int ok = 1;

    ERR_clear_error();

    /* look at context options in the stream and set appropriate verification flags */
    if (GET_VER_OPT("verify_peer") && zval_is_true(*val)) {

        /* turn on verification callback */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

        /* CA stuff */
        GET_VER_OPT_STRING("cafile", cafile);
        GET_VER_OPT_STRING("capath", capath);

        if (cafile || capath) {
            if (!SSL_CTX_load_verify_locations(ctx, cafile, capath)) {
                error_docref(NULL, E_WARNING, "Unable to set verify locations `%s' `%s'", cafile, capath);
                return NULL;
            }
        }

        if (GET_VER_OPT("verify_depth")) {
            convert_to_long_ex(val);
            SSL_CTX_set_verify_depth(ctx, Z_LVAL_PP(val));
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* callback for the passphrase (for localcert) */
    if (GET_VER_OPT("passphrase")) {
        SSL_CTX_set_default_passwd_cb_userdata(ctx, stream);
        SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }

    GET_VER_OPT_STRING("ciphers", cipherlist);
    if (!cipherlist) {
        cipherlist = "DEFAULT";
    }
    if (SSL_CTX_set_cipher_list(ctx, cipherlist) != 1) {
        return NULL;
    }

    GET_VER_OPT_STRING("local_cert", certfile);
    if (certfile) {
        X509 *cert = NULL;
        EVP_PKEY *key = NULL;
        SSL *tmpssl;
        char resolved_path_buff[MAXPATHLEN];
        const char * private_key = NULL;

        if (VCWD_REALPATH(certfile, resolved_path_buff)) {
            /* a certificate to use for authentication */
            if (SSL_CTX_use_certificate_chain_file(ctx, resolved_path_buff) != 1) {
                error_docref(NULL, E_WARNING, "Unable to set local cert chain file `%s'; Check that your cafile/capath settings include details of your certificate and its issuer", certfile);
                return NULL;
            }
            GET_VER_OPT_STRING("local_pk", private_key);

            if (private_key) {
                char resolved_path_buff_pk[MAXPATHLEN];
                if (VCWD_REALPATH(private_key, resolved_path_buff_pk)) {
                    if (SSL_CTX_use_PrivateKey_file(ctx, resolved_path_buff_pk, SSL_FILETYPE_PEM) != 1) {
                        error_docref(NULL, E_WARNING, "Unable to set private key file `%s'", resolved_path_buff_pk);
                        return NULL;
                    }
                }
            } else {
                if (SSL_CTX_use_PrivateKey_file(ctx, resolved_path_buff, SSL_FILETYPE_PEM) != 1) {
                    error_docref(NULL, E_WARNING, "Unable to set private key file `%s'", resolved_path_buff);
                    return NULL;
                }
            }

            tmpssl = SSL_new(ctx);
            cert = SSL_get_certificate(tmpssl);

            if (cert) {
                key = X509_get_pubkey(cert);
                EVP_PKEY_copy_parameters(key, SSL_get_privatekey(tmpssl));
                EVP_PKEY_free(key);
            }
            SSL_free(tmpssl);

            if (!SSL_CTX_check_private_key(ctx)) {
                error_docref(NULL, E_WARNING, "Private key does not match certificate!");
            }
        }
    }
    if (ok) {
        SSL *ssl = SSL_new(ctx);

        if (ssl) {
            /* map SSL => stream */
            SSL_set_ex_data(ssl, ssl_stream_data_index, stream);
        }
        return ssl;
    }

    return NULL;
}
/* }}} */

#endif


/* {{{ proto string openssl_dh_compute_key(string pub_key, resource dh_key)
   Computes shared sicret for public value of remote DH key and local DH key */
LUA_FUNCTION(openssl_dh_compute_key)
{
    const char *pub_str;
    size_t pub_len;
    EVP_PKEY *pkey;
    BIGNUM *pub;
    char *data;
    int len;
    int ret = 0;

    pub_str = luaL_checklstring(L,1,&pub_len);
    pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");

    if (!pkey || EVP_PKEY_type(pkey->type) != EVP_PKEY_DH || !pkey->pkey.dh) {
        luaL_error(L,"paramater 2 must dh key");
    }

    pub = BN_bin2bn((unsigned char*)pub_str, pub_len, NULL);

    data = malloc(DH_size(pkey->pkey.dh) + 1);
    len = DH_compute_key((unsigned char*)data, pub, pkey->pkey.dh);

    if (len >= 0) {
        data[len] = 0;
        lua_pushlstring(L,data,len);
        ret = 1;
    } else {
        free(data);
        ret = 0;
    }

    BN_free(pub);
    return ret;
}
/* }}} */

void CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
int luaopen_bn(lua_State *L);
LUA_API int luaopen_openssl(lua_State*L)
{
    char * config_filename;
    CRYPTO_thread_setup();

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_library_init();

    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    ERR_load_EVP_strings();
    ERR_load_SSL_strings();

    ENGINE_load_dynamic();
    ENGINE_load_openssl();

    /* Determine default SSL configuration file */
    config_filename = getenv("OPENSSL_CONF");
    if (config_filename == NULL) {
        config_filename = getenv("SSLEAY_CONF");
    }

    /* default to 'openssl.cnf' if no environment variable is set */
    if (config_filename == NULL) {
        snprintf(default_ssl_conf_filename, sizeof(default_ssl_conf_filename), "%s/%s",
                 X509_get_default_cert_area(),
                 "openssl.cnf");
    } else {
        strncpy(default_ssl_conf_filename, config_filename, sizeof(default_ssl_conf_filename));
    }

    openssl_register_pkey(L);
    openssl_register_x509(L);
    openssl_register_csr(L);
    openssl_register_digest(L);
    openssl_register_cipher(L);
    openssl_register_sk_x509(L);
    openssl_register_bio(L);
    openssl_register_crl(L);
#ifdef OPENSSL_HAVE_TS
    openssl_register_ts(L);
#endif
    openssl_register_conf(L);
    openssl_register_pkcs7(L);
    openssl_register_misc(L);
    openssl_register_engine(L);
    openssl_register_ssl(L);
    openssl_register_ocsp(L);

#if LUA_VERSION_NUM==501
    luaL_register(L,"openssl",eay_functions);
#elif LUA_VERSION_NUM==502
    lua_newtable(L);
    luaL_setfuncs(L, eay_functions, 0);
#endif
    setNamedIntegers(L, consts);

    /* third part */
    luaopen_bn(L);
    lua_setfield(L, -2, "bn");

    return 1;
}

/*
 * Local variables:
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
