#include "openssl.h"


/* {{{ arginfo */

/* }}} */

/* true global; readonly after module startup */
char default_ssl_conf_filename[MAX_PATH];

/* {{{ openssl_functions[]
 */
const static luaL_Reg eay_functions[] = {
	/* pkey */
	{"pkey_new",   openssl_pkey_new	},
	{"pkey_free",   openssl_pkey_free	},

	{"pkey_export",			openssl_pkey_export	},
	{"pkey_read",			openssl_pkey_read	},
	{"pkey_get_details",	openssl_pkey_get_details	},


	/* x.509 cert funcs */
	{"x509_read",			openssl_x509_read	},
	{"x509_parse",			openssl_x509_parse	},
	{"x509_export",			openssl_x509_export	},
	{"x509_checkpurpose",	openssl_x509_checkpurpose	},
	{"x509_check_private_key",	openssl_x509_check_private_key	},


/* PKCS12 funcs */
	{"pkcs12_export",			openssl_pkcs12_export	},
	{"pkcs12_read",				openssl_pkcs12_read	},

/* CSR funcs */
	{"csr_new",				openssl_csr_new	},
	{"csr_export",				openssl_csr_export	},
	{"csr_export_to_file",				openssl_csr_export_to_file	},
	{"csr_sign",				openssl_csr_sign	},
	{"csr_get_subject",				openssl_csr_get_subject	},
	{"csr_get_public_key",				openssl_csr_get_public_key	},

	{"digest",				openssl_digest	},
	{"encrypt",				openssl_encrypt	},
	{"decrypt",				openssl_decrypt	},
	{"cipher_iv_length",				openssl_cipher_iv_length	},
	{"sign",				openssl_sign	},
	{"verify",				openssl_verify	},
	{"seal",				openssl_seal	},
	{"open",				openssl_open	},


/* for S/MIME handling */
	{"pkcs7_verify",				openssl_pkcs7_verify	},
	{"pkcs7_decrypt",				openssl_pkcs7_decrypt	},
	{"pkcs7_sign",					openssl_pkcs7_sign	},
	{"pkcs7_encrypt",				openssl_pkcs7_encrypt	},

	{"private_encrypt",				openssl_private_encrypt	},
	{"private_decrypt",				openssl_private_decrypt	},
	{"public_encrypt",				openssl_public_encrypt	},
	{"public_decrypt",				openssl_public_decrypt	},

	{"get_md_methods",				openssl_get_md_methods	},
	{"get_cipher_methods",				openssl_get_cipher_methods	},
	{"dh_compute_key",				openssl_dh_compute_key	},
	{"random_pseudo_bytes",				openssl_random_pseudo_bytes	},
	{"error_string",				openssl_error_string	},

	{NULL, NULL}
};
/* }}} */


static int le_key;
static int le_x509;
static int le_csr;
static int ssl_stream_data_index;

int openssl_get_x509_list_id(void) /* {{{ */
{
	return le_x509;
}
/* }}} */

/* {{{ resource destructors */
static void pkey_free(lua_State *L)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.pkey");

	assert(pkey != NULL);

	EVP_PKEY_free(pkey);
}

static void csr_free(lua_State *L)
{
	X509_REQ * csr  = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	X509_REQ_free(csr);
}
/* }}} */
#if 0
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
/* openssl -> PHP "bridging" */
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



static EVP_MD * openssl_get_evp_md_from_algo(long algo) { /* {{{ */
	EVP_MD *mdtype;

	switch (algo) {
		case OPENSSL_ALGO_SHA1:
			mdtype = (EVP_MD *) EVP_sha1();
			break;
		case OPENSSL_ALGO_MD5:
			mdtype = (EVP_MD *) EVP_md5();
			break;
		case OPENSSL_ALGO_MD4:
			mdtype = (EVP_MD *) EVP_md4();
			break;
#ifdef HAVE_OPENSSL_MD2_H
		case OPENSSL_ALGO_MD2:
			mdtype = (EVP_MD *) EVP_md2();
			break;
#endif
		case OPENSSL_ALGO_DSS1:
			mdtype = (EVP_MD *) EVP_dss1();
			break;
		default:
			return NULL;
			break;
	}
	return mdtype;
}
/* }}} */

const EVP_CIPHER * openssl_get_evp_cipher_from_algo(long algo) { /* {{{ */
	switch (algo) {
#ifndef OPENSSL_NO_RC2
		case OPENSSL_CIPHER_RC2_40:
			return EVP_rc2_40_cbc();
			break;
		case OPENSSL_CIPHER_RC2_64:
			return EVP_rc2_64_cbc();
			break;
		case OPENSSL_CIPHER_RC2_128:
			return EVP_rc2_cbc();
			break;
#endif

#ifndef OPENSSL_NO_DES
		case OPENSSL_CIPHER_DES:
			return EVP_des_cbc();
			break;
		case OPENSSL_CIPHER_3DES:
			return EVP_des_ede3_cbc();
			break;
#endif
		default:
			return NULL;
			break;
	}
}
/* }}} */







static STACK_OF(X509) * array_to_X509_sk(lua_State *L, int n) /* {{{ */
{
	STACK_OF(X509) * sk = NULL;
    X509 * cert;
    int len,i;

	sk = sk_X509_new_null();

	/* get certs */
	if (lua_istable(L,n))
	{
		len = lua_objlen(L,n);
		for (i=1; i<=len; i++)
		{
			lua_rawgeti(L,n,i);
			cert = CHECK_OBJECT(-1,X509,"openssl.x509");
			cert = X509_dup(cert);
			sk_X509_push(sk, cert);
		}
	}else
	{
		cert = CHECK_OBJECT(n,X509,"openssl.x509");
		cert = X509_dup(cert);
		sk_X509_push(sk, cert);
	}
	return sk;
}
/* }}} */


/* {{{ proto crypted openssl_private_encrypt(string data, mixed key [, int padding])
   Encrypts data with private key */
LUA_FUNCTION(openssl_private_encrypt)
{
	EVP_PKEY *pkey;
	int cryptedlen;
	unsigned char *cryptedbuf = NULL;
	int ful = 0;
	long keyresource = -1;
	const char * data;
	int data_len;
	long padding = RSA_PKCS1_PADDING;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");
	padding = luaL_optint(L,3,RSA_PKCS1_PADDING);

	cryptedlen = EVP_PKEY_size(pkey);
	cryptedbuf = malloc(cryptedlen + 1);

	switch (pkey->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			ful =  (RSA_private_encrypt(data_len, 
						(unsigned char *)data, 
						cryptedbuf, 
						pkey->pkey.rsa, 
						padding) == cryptedlen);
			break;
		default:
			luaL_error(L,"key type not supported in this PHP build!");
	}

	if (ful) {
		cryptedbuf[cryptedlen] = '\0';
		lua_pushlstring(L,(char *)cryptedbuf, cryptedlen);
		ret = 1;
	}
	if (cryptedbuf) {
		free(cryptedbuf);
	}
	if (keyresource == -1) { 
		EVP_PKEY_free(pkey);
	}
	return ret;
}
/* }}} */

/* {{{ proto decrypted openssl_private_decrypt(string data, mixed key [, int padding])
   Decrypts data with private key */
LUA_FUNCTION(openssl_private_decrypt)
{
	EVP_PKEY *pkey;
	int cryptedlen;
	unsigned char *cryptedbuf = NULL;
	unsigned char *crypttemp;
	int ful = 0;
	long padding = RSA_PKCS1_PADDING;
	long keyresource = -1;
	const char * data;
	int data_len;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");
	padding = luaL_optint(L,3,RSA_PKCS1_PADDING);

	cryptedlen = EVP_PKEY_size(pkey);
	crypttemp = malloc(cryptedlen + 1);

	switch (pkey->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			cryptedlen = RSA_private_decrypt(data_len, 
					(unsigned char *)data, 
					crypttemp, 
					pkey->pkey.rsa, 
					padding);
			if (cryptedlen != -1) {
				cryptedbuf = malloc(cryptedlen + 1);
				memcpy(cryptedbuf, crypttemp, cryptedlen);
				ful = 1;
			}
			break;
		default:
			luaL_error(L,"key type not supported in this PHP build!");
	}

	free(crypttemp);

	if (ful) {
		lua_pushlstring(L,(char *)cryptedbuf, cryptedlen);
		ret = 1;
	}

	if (keyresource == -1) {
		EVP_PKEY_free(pkey);
	}
	if (cryptedbuf) { 
		free(cryptedbuf);
	}
	return 1;
}
/* }}} */

/* {{{ proto crypted openssl_public_encrypt(string data, mixed key [, int padding])
   Encrypts data with public key */
LUA_FUNCTION(openssl_public_encrypt)
{
	EVP_PKEY *pkey;
	int cryptedlen;
	unsigned char *cryptedbuf;
	int ful = 0;
	long keyresource = -1;
	long padding = RSA_PKCS1_PADDING;
	const char * data;
	int data_len;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");
	padding = luaL_optint(L,3,RSA_PKCS1_PADDING);

	cryptedlen = EVP_PKEY_size(pkey);
	cryptedbuf = malloc(cryptedlen + 1);

	switch (pkey->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			ful = (RSA_public_encrypt(data_len, 
						(unsigned char *)data, 
						cryptedbuf, 
						pkey->pkey.rsa, 
						padding) == cryptedlen);
			break;
		default:
			luaL_error(L,"key type not supported in this PHP build!");

	}

	if (ful) {
		lua_pushlstring(L,(char *)cryptedbuf, cryptedlen);
		ret = 1;
	}
	if (keyresource == -1) {
		EVP_PKEY_free(pkey);
	}
	if (cryptedbuf) {
		free(cryptedbuf);
	}
	return 1;
}
/* }}} */

/* {{{ proto bool openssl_public_decrypt(string data, string &crypted, resource key [, int padding])
   Decrypts data with public key */
LUA_FUNCTION(openssl_public_decrypt)
{
	EVP_PKEY *pkey;
	int cryptedlen;
	unsigned char *cryptedbuf = NULL;
	unsigned char *crypttemp;
	int ful = 0;
	long keyresource = -1;
	long padding = RSA_PKCS1_PADDING;
	const char * data;
	int data_len;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");
	padding = luaL_optint(L,3,RSA_PKCS1_PADDING);


	cryptedlen = EVP_PKEY_size(pkey);
	crypttemp = malloc(cryptedlen + 1);

	switch (pkey->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			cryptedlen = RSA_public_decrypt(data_len, 
					(unsigned char *)data, 
					crypttemp, 
					pkey->pkey.rsa, 
					padding);
			if (cryptedlen != -1) {
				cryptedbuf = malloc(cryptedlen + 1);
				memcpy(cryptedbuf, crypttemp, cryptedlen);
				ful = 1;
			}
			break;
			
		default:
			luaL_error(L,"key type not supported in this PHP build!");
		 
	}

	free(crypttemp);

	if (ful) {
		lua_pushlstring(L,(char *)cryptedbuf, cryptedlen);
		ret = 1;
	}

	if (cryptedbuf) {
		free(cryptedbuf);
	}
	if (keyresource == -1) {
		EVP_PKEY_free(pkey);
	}
	return 1;
}
/* }}} */

/* {{{ proto mixed openssl_error_string(void)
   Returns a description of the last error, and alters the index of the error messages. Returns false when the are no more messages */
LUA_FUNCTION(openssl_error_string)
{
	char buf[512];
	unsigned long val;

	val = ERR_get_error();
	if (val) {
		lua_pushinteger(L,val);
		lua_pushstring(L, ERR_error_string(val, buf));
		return 2;
	} 
	return 0;
}
/* }}} */

/* {{{ proto signature openssl_sign(string data,  mixed key[, mixed method])
   Signs data */
LUA_FUNCTION(openssl_sign)
{
	EVP_PKEY *pkey;
	int siglen;
	unsigned char *sigbuf;
	long keyresource = -1;
	const char * data;
	int data_len;
	EVP_MD_CTX md_ctx;
	long signature_algo = OPENSSL_ALGO_SHA1;
	const EVP_MD *mdtype;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	pkey = CHECK_OBJECT(2,EVP_PKEY,"openssl.evp_pkey");
	if(lua_isstring(L,3))
	{
		mdtype = EVP_get_digestbyname(lua_tostring(L,3));
	}else if(lua_isnumber(L,3))
		mdtype = openssl_get_evp_md_from_algo(lua_tointeger(L,3));
	else
		mdtype = openssl_get_evp_md_from_algo(signature_algo);

	siglen = EVP_PKEY_size(pkey);
	sigbuf = malloc(siglen + 1);

	EVP_SignInit(&md_ctx, mdtype);
	EVP_SignUpdate(&md_ctx, data, data_len);
	if (EVP_SignFinal (&md_ctx, sigbuf,(unsigned int *)&siglen, pkey)) {
		lua_pushlstring(L,(char *)sigbuf, siglen);
		ret = 1;
	} else {
		free(sigbuf);
	}
	EVP_MD_CTX_cleanup(&md_ctx);
	if (keyresource == -1) {
		EVP_PKEY_free(pkey);
	}
	return ret;
}
/* }}} */

/* {{{ proto int openssl_verify(string data, string signature, mixed key[, mixed method])
   Verifys data */
LUA_FUNCTION(openssl_verify)
{
	EVP_PKEY *pkey;
	int err;
	EVP_MD_CTX     md_ctx;
	const EVP_MD *mdtype;
	long keyresource = -1;
	const char * data;	int data_len;
	const char * signature;	int signature_len;
	long signature_algo = OPENSSL_ALGO_SHA1;
	
	data = luaL_checklstring(L,1,&data_len);
	signature = luaL_checklstring(L,2,&signature_len);
	pkey = CHECK_OBJECT(3,EVP_PKEY,"openssl.evp_pkey");

	if(lua_isstring(L,4))
	{
		mdtype = EVP_get_digestbyname(lua_tostring(L,4));
	}else if(lua_isnumber(L,4))
		mdtype = openssl_get_evp_md_from_algo(lua_tointeger(L,4));
	else
		mdtype = openssl_get_evp_md_from_algo(signature_algo);

	EVP_VerifyInit   (&md_ctx, mdtype);
	EVP_VerifyUpdate (&md_ctx, data, data_len);
	err = EVP_VerifyFinal (&md_ctx, (unsigned char *)signature, signature_len, pkey);
	EVP_MD_CTX_cleanup(&md_ctx);

	if (keyresource == -1) {
		EVP_PKEY_free(pkey);
	}
	lua_pushinteger(L,err);
	return 1;
}
/* }}} */

/* {{{ proto sealdata,ekeys openssl_seal(string data, array pubkeys [, string method])
   Seals data */
LUA_FUNCTION(openssl_seal)
{
	EVP_PKEY **pkeys;
	long * key_resources;	/* so we know what to cleanup */
	int i, len1, len2, *eksl, nkeys;
	unsigned char *buf = NULL, **eks;
	const char * data; int data_len;
	const char *method =NULL;
	int method_len = 0;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	luaL_checktype(L,2, LUA_TTABLE);
	nkeys = lua_objlen(L,2);
	method = luaL_optstring(L, 3, NULL);

	if (!nkeys) {
		luaL_error(L,"Fourth argument to openssl_seal() must be a non-empty array");
	}

	if (method) {
		cipher = EVP_get_cipherbyname(method);
		if (!cipher) {
			luaL_error(L, "Unknown signature algorithm.");
		}
	} else {
		cipher = EVP_rc4();
	}

	pkeys = malloc(nkeys*sizeof(*pkeys));
	eksl = malloc(nkeys*sizeof(*eksl));
	eks = malloc(nkeys*sizeof(*eks));
	memset(eks, 0, sizeof(*eks) * nkeys);
	key_resources = malloc(nkeys*sizeof(long));
	memset(key_resources, 0, sizeof(*key_resources) * nkeys);

	/* get the public keys we are using to seal this data */

	i = 0;
	for(i=1; i<=nkeys; i++) {
		lua_rawgeti(L,2,i);

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

#if 0
	/* Need this if allow ciphers that require initialization vector */
	ivlen = EVP_CIPHER_CTX_iv_length(&ctx);
	iv = ivlen ? malloc(ivlen + 1) : NULL;
#endif
	/* allocate one byte extra to make room for \0 */
	buf = malloc(data_len + EVP_CIPHER_CTX_block_size(&ctx));

	if (!EVP_SealInit(&ctx, cipher, eks, eksl, NULL, pkeys, nkeys) || !EVP_SealUpdate(&ctx, buf, &len1, (unsigned char *)data, data_len)) {
		free(buf);
		luaL_error(L,"EVP_SealInit failed");
	}

	EVP_SealFinal(&ctx, buf + len1, &len2);

	if (len1 + len2 > 0) {
		buf[len1 + len2] = '\0';
		lua_pushlstring(L,buf,len1 + len2);
		lua_newtable(L);
		for (i=0; i<nkeys; i++) {
			eks[i][eksl[i]] = '\0';
			lua_pushlstring(L, eks[i], eksl[i]);
			free(eks[i]);
			eks[i] = NULL;
			lua_rawseti(L,-2, i+1);
		}
		ret = 2;
#if 0
		/* If allow ciphers that need IV, we need this */
		zval_dtor(*ivec);
		if (ivlen) {
			iv[ivlen] = '\0';
			ZVAL_STRINGL(*ivec, erealloc(iv, ivlen + 1), ivlen, 0);
		} else {
			ZVAL_EMPTY_STRING(*ivec);
		}
#endif

	} else {
		free(buf);
	}


	for (i=0; i<nkeys; i++) {
		if (key_resources[i] == -1) {
			EVP_PKEY_free(pkeys[i]);
		}
		if (eks[i]) { 
			free(eks[i]);
		}
	}
	free(eks);
	free(eksl);
	free(pkeys);
	free(key_resources);
	return ret;
}
/* }}} */

/* {{{ proto opendata openssl_open(string data, string ekey, mixed privkey, string method)
   Opens data */
LUA_FUNCTION(openssl_open)
{
	EVP_PKEY *pkey;
	int len1, len2;
	unsigned char *buf;
	long keyresource = -1;
	EVP_CIPHER_CTX ctx;
	const char * data;	int data_len;
	const char * ekey;	int ekey_len;
	const char *method =NULL;
	int method_len = 0;
	const EVP_CIPHER *cipher;
	int ret = 0;

	data = luaL_checklstring(L, 1, &data_len);
	ekey = luaL_checklstring(L, 2, &ekey_len);
	pkey = CHECK_OBJECT(3,EVP_PKEY, "openssl.evp_pkey");
	method = luaL_optstring(L,4, NULL);

	if (method) {
		cipher = EVP_get_cipherbyname(method);
		if (!cipher) {
			luaL_error(L,"Unknown signature algorithm.");
		}
	} else {
		cipher = EVP_rc4();
	}
	
	buf = malloc(data_len + 1);

	if (EVP_OpenInit(&ctx, cipher, (unsigned char *)ekey, ekey_len, NULL, pkey) && EVP_OpenUpdate(&ctx, buf, &len1, (unsigned char *)data, data_len)) {
		if (!EVP_OpenFinal(&ctx, buf + len1, &len2) || (len1 + len2 == 0)) {
			free(buf);
		}
	} else {
		free(buf);
	}

	buf[len1 + len2] = '\0';
	lua_pushlstring(L, buf, len1 + len2);
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
    /* TODO: could expand this to make a callback into PHP user-space */

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

static void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) /* {{{ */
{
	lua_State *L = (lua_State *)arg;
	int i = lua_objlen(L,-1);
	lua_pushstring(L,name->name);
	lua_rawseti(L,-2,i+1);
}
/* }}} */

static void openssl_add_method(const OBJ_NAME *name, void *arg) /* {{{ */
{
	if (name->alias == 0) {
		openssl_add_method_or_alias(name,arg);
	}
}
/* }}} */

/* {{{ proto array openssl_get_md_methods([bool aliases = false])
   Return array of available digest methods */
LUA_FUNCTION(openssl_get_md_methods)
{
	int aliases = lua_isnil(L,1)?0:lua_toboolean(L,1);

	lua_newtable(L);
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, aliases ? openssl_add_method_or_alias: openssl_add_method, L);
	return 1;
}
/* }}} */

/* {{{ proto array openssl_get_cipher_methods([bool aliases = false])
   Return array of available cipher methods */
LUA_FUNCTION(openssl_get_cipher_methods)
{
	int aliases = lua_isnil(L,1)?0:lua_toboolean(L,1);

	lua_newtable(L);
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, aliases ? openssl_add_method_or_alias: openssl_add_method, L);
	return 1;
}
/* }}} */

/* {{{ proto string openssl_digest(string data, string method [, bool raw_output=false])
   Computes digest hash value for given data using given method, returns raw or binhex encoded string */
LUA_FUNCTION(openssl_digest)
{
	int raw_output = 0;
	const char *data, *method;
	int data_len;
	const EVP_MD *mdtype;
	EVP_MD_CTX md_ctx;
	int siglen;
	unsigned char *sigbuf;
	int ret = 0;

	data = luaL_checklstring(L,1,&data_len);
	method = luaL_checkstring(L,2);
	raw_output = lua_isnil(L,3)?0:lua_toboolean(L,3);

	mdtype = EVP_get_digestbyname(method);
	if (!mdtype) {
		luaL_error(L,"Unknown signature algorithm");
	}

	siglen = EVP_MD_size(mdtype);
	sigbuf = malloc(siglen + 1);

	EVP_DigestInit(&md_ctx, mdtype);
	EVP_DigestUpdate(&md_ctx, (unsigned char *)data, data_len);
	if (EVP_DigestFinal (&md_ctx, (unsigned char *)sigbuf, (unsigned int *)&siglen)) {
		if (raw_output) {
			sigbuf[siglen] = '\0';
			lua_pushlstring(L,sigbuf, siglen);
		} else {
			int digest_str_len = siglen * 2;
			char *digest_str = malloc(digest_str_len + 1);

			//make_digest_ex(digest_str, sigbuf, siglen);

			free(sigbuf);
			lua_pushlstring(L,digest_str, digest_str_len);
		}
	} else {
		free(sigbuf);
		ret = 0;
	}
	return ret;
}
/* }}} */

static int openssl_validate_iv(char **piv, int *piv_len, int iv_required_len)
{
	char *iv_new;

	/* Best case scenario, user behaved */
	if (*piv_len == iv_required_len) {
		return 0;
	}

	iv_new = calloc(1, iv_required_len + 1);

	if (*piv_len <= 0) {
		/* BC behavior */
		*piv_len = iv_required_len;
		*piv     = iv_new;
		return 1;
	}

	if (*piv_len < iv_required_len) {
		memcpy(iv_new, *piv, *piv_len);
		*piv_len = iv_required_len;
		*piv     = iv_new;
		return 1;
	}

	memcpy(iv_new, *piv, iv_required_len);
	*piv_len = iv_required_len;
	*piv     = iv_new;
	return 1;

}

/* {{{ proto string openssl_encrypt(string data, string method, string password [, bool raw_output=false [, string $iv='']])
   Encrypts given data with given method and key, returns raw or base64 encoded string */
LUA_FUNCTION(openssl_encrypt)
{
	int raw_output = 0;
	const char *data, *method, *password;
	char *iv = "";
	int data_len, password_len, iv_len = 0, max_iv_len;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i, outlen, keylen;
	unsigned char *outbuf, *key;
	int top = lua_gettop(L);
	int ret = 0;

	int free_iv = 0;

	data = luaL_checklstring(L,1,&data_len);
	method = luaL_checkstring(L,2);
	password = luaL_checklstring(L,3, &password_len);
	if(top>3)
		raw_output = lua_toboolean(L,4);
	if(top>4)
		iv = (char*)luaL_checklstring(L,5,&iv_len);

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		luaL_error(L,"Unknown cipher algorithm");
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = malloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	if (iv_len <= 0 && max_iv_len > 0) {
		luaL_error(L,"Using an empty Initialization Vector (iv) is potentially insecure and not recommended");
	}
	free_iv = openssl_validate_iv(&iv, &iv_len, max_iv_len);

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = malloc(outlen + 1);

	EVP_EncryptInit(&cipher_ctx, cipher_type, key, (unsigned char *)iv);
	EVP_EncryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	outlen = i;
	if (EVP_EncryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		if (raw_output) {
			outbuf[outlen] = '\0';
			lua_pushlstring(L,(char *)outbuf, outlen);
			ret = 1;
		} else {
			/*
			int base64_str_len;
			char *base64_str;

			base64_str = (char*)base64_encode(outbuf, outlen, &base64_str_len);
			free(outbuf);
			lua_pushlstring(L,base64_str, base64_str_len);
			ret = 1;
			*/
		}
	} else {
		free(outbuf);
	}
	if (key != (unsigned char*)password) {
		free(key);
	}
	if (free_iv) {
		free(iv);
	}
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	return 1;
}
/* }}} */

/* {{{ proto string openssl_decrypt(string data, string method, string password [, bool raw_input=false [, string $iv = '']])
   Takes raw or base64 encoded string and dectupt it using given method and key */
LUA_FUNCTION(openssl_decrypt)
{
	int raw_input = 0;
	const char *data, *method, *password;
	char *iv = "";
	int data_len, password_len, iv_len = 0;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i, outlen, keylen;
	unsigned char *outbuf, *key;
	char *base64_str = NULL;
	int free_iv;
	int ret = 0;
	int top = lua_gettop(L);


	data = luaL_checklstring(L,1,&data_len);
	method = luaL_checkstring(L,2);
	password = luaL_checklstring(L,3, &password_len);
	if(top>3)
		raw_input = lua_toboolean(L,4);
	if(top>4)
		iv = (char*) luaL_checklstring(L,5,&iv_len);

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		luaL_error(L,"Unknown cipher algorithm");
	}

	if (!raw_input) {
		/*
		base64_str = (char*)base64_decode((unsigned char*)data, data_len, &base64_str_len);
		data_len = base64_str_len;
		data = base64_str;
		*/
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = malloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	free_iv = openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type));

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = malloc(outlen + 1);

	EVP_DecryptInit(&cipher_ctx, cipher_type, key, (unsigned char *)iv);
	EVP_DecryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	outlen = i;
	if (EVP_DecryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		outbuf[outlen] = '\0';
		lua_pushlstring(L,(char *)outbuf, outlen);
		ret = 1;
	} else {
		free(outbuf);
	}
	if (key != (unsigned char*)password) {
		free(key);
	}
	if (free_iv) {
		free(iv);
	}
	if (base64_str) {
		free(base64_str);
	}
 	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	return 1;
}
/* }}} */

/* {{{ proto int openssl_cipher_iv_length(string $method) */
LUA_FUNCTION(openssl_cipher_iv_length)
{
	const char *method;
	int method_len;
	const EVP_CIPHER *cipher_type;
	method = luaL_checklstring(L,1,&method_len);

	if (!method_len) {
		luaL_error(L,"Unknown cipher algorithm");
	}

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		luaL_error(L,"Unknown cipher algorithm");
	}

	lua_pushinteger(L,EVP_CIPHER_iv_length(cipher_type));
	return 1;
}
/* }}} */


/* {{{ proto string openssl_dh_compute_key(string pub_key, resource dh_key)
   Computes shared sicret for public value of remote DH key and local DH key */
LUA_FUNCTION(openssl_dh_compute_key)
{
	const char *pub_str;
	int pub_len;
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

/* {{{ proto string openssl_random_pseudo_bytes(integer length [, &bool returned_strong_result])
   Returns a string of the length specified filled with random pseudo bytes */
LUA_FUNCTION(openssl_random_pseudo_bytes)
{
	long buffer_length;
	unsigned char *buffer = NULL;
	int strong_result = 0;
	int ret = 0;

	buffer_length = luaL_checkint(L,1);
	strong_result = lua_isnil(L,2)? 0 : lua_toboolean(L,2);

	if (buffer_length <= 0) {
		luaL_error(L,"paramater 1 must not be nego");
	}

	buffer = malloc(buffer_length + 1);

#ifdef WINDOWS
        RAND_screen();
#endif

	if ((strong_result = RAND_pseudo_bytes(buffer, buffer_length)) < 0) {
		free(buffer);
		luaL_error(L,"generate random data failed");
	}

	lua_pushlstring(L,(char *)buffer, buffer_length);

	if (strong_result) {
		lua_pushboolean(L,strong_result);
		return 2;
	}
	return 1;
}
/* }}} */


extern luaL_Reg x509_funcs[];
extern luaL_Reg pkey_funcs[];

LUA_API int luaopen_openssl(lua_State*L)
{
	char * config_filename;

	SSL_library_init();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	ERR_load_EVP_strings();


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

	auxiliar_newclass(L,"openssl.x509", x509_funcs);
	auxiliar_newclass(L,"openssl.evp_pkey", x509_funcs);

	luaL_register(L,"openssl",eay_functions);
	
	return 0;
}

/*
 * Local variables:
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
