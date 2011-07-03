#include "openssl.h"



/* {{{ x509 CSR functions */

/* {{{ openssl_make_REQ */
static int openssl_make_REQ(lua_State*L, struct x509_request * req, X509_REQ * csr, int dn, int attribs)
{
	STACK_OF(CONF_VALUE) * dn_sk, *attr_sk = NULL;
	char * str, *dn_sect, *attr_sect;

	dn_sect = CONF_get_string(req->req_config, req->section_name, "distinguished_name");
	if (dn_sect == NULL) {
		return -1;
	}
	dn_sk = CONF_get_section(req->req_config, dn_sect);
	if (dn_sk == NULL) { 
		return -1;
	}
	attr_sect = CONF_get_string(req->req_config, req->section_name, "attributes");
	if (attr_sect == NULL) {
		attr_sk = NULL;
	} else {
		attr_sk = CONF_get_section(req->req_config, attr_sect);
		if (attr_sk == NULL) {
			return -1;
		}
	}
	/* setup the version number: version 1 */
	if (X509_REQ_set_version(csr, 0L)) {
		int i, nid;
		char * type;
		CONF_VALUE * v;
		X509_NAME * subj;
		
		subj = X509_REQ_get_subject_name(csr);
		/* apply values from the dn hash */

		/* table is in the stack at index 't' */
		lua_pushnil(L);  /* first key */
		while (lua_next(L, dn) != 0) {
			/* uses 'key' (at index -2) and 'value' (at index -1) */
			/* 
			printf("%s - %s\n", lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
			*/
			const char * strindex = lua_tostring(L,-2); 
			const char * strval = lua_tostring(L,-1); 

			if (strindex) {
				int nid;

				nid = OBJ_txt2nid(strindex);
				if (nid != NID_undef) {
					if (!X509_NAME_add_entry_by_NID(subj, nid, MBSTRING_ASC, (unsigned char*)strval, -1, -1, 0))
					{
						luaL_error(L, "dn: add_entry_by_NID %d -> %s (failed)", nid, strval);
						return -1;
					}
				} else {
					luaL_error(L, "dn: %s is not a recognized name", strindex);
				}
			}
			/* removes 'value'; keeps 'key' for next iteration */
			lua_pop(L, 1);
		}

		/* Finally apply defaults from config file */
		for(i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
			int len;
			char buffer[200 + 1]; /*200 + \0 !*/
			
			v = sk_CONF_VALUE_value(dn_sk, i);
			type = v->name;
			
			len = strlen(type);
			if (len < sizeof("_default")) {
				continue;
			}
			len -= sizeof("_default") - 1;
			if (strcmp("_default", type + len) != 0) {
				continue;
			}
			if (len > 200) {
				len = 200;
			}
			memcpy(buffer, type, len);
			buffer[len] = '\0';
			type = buffer;
		
			/* Skip past any leading X. X: X, etc to allow for multiple
			 * instances */
			for (str = type; *str; str++) {
				if (*str == ':' || *str == ',' || *str == '.') {
					str++;
					if (*str) {
						type = str;
					}
					break;
				}
			}
			/* if it is already set, skip this */
			nid = OBJ_txt2nid(type);
			if (X509_NAME_get_index_by_NID(subj, nid, -1) >= 0) {
				continue;
			}
			if (!X509_NAME_add_entry_by_txt(subj, type, MBSTRING_ASC, (unsigned char*)v->value, -1, -1, 0)) {
				luaL_error(L,"add_entry_by_txt %s -> %s (failed)", type, v->value);
			}
			if (!X509_NAME_entry_count(subj)) {
				luaL_error(L,"no objects specified in config file");
			}
		}
		if (attribs) {
			/* table is in the stack at index 't' */
			lua_pushnil(L);  /* first key */
			while (lua_next(L, attribs) != 0) {
				/* uses 'key' (at index -2) and 'value' (at index -1) */
				/* 
				printf("%s - %s\n", lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
				*/
				const char * strindex = lua_tostring(L,-2); 
				const char * strval = lua_tostring(L,-1); 

				if (strindex) {
					int nid;

					nid = OBJ_txt2nid(strindex);
					if (nid != NID_undef) {
						if (!X509_NAME_add_entry_by_NID(subj, nid, MBSTRING_ASC, (unsigned char*)strval, -1, -1, 0)) {
							luaL_error(L, "attribs: add_entry_by_NID %d -> %s (failed)", nid, strval);
							return -1;
						}
					} else {
						luaL_error(L, "dn: %s is not a recognized name", strindex);
					}
				}


				/* removes 'value'; keeps 'key' for next iteration */
				lua_pop(L, 1);
			}

			for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
				v = sk_CONF_VALUE_value(attr_sk, i);
				/* if it is already set, skip this */
				nid = OBJ_txt2nid(v->name);
				if (X509_REQ_get_attr_by_NID(csr, nid, -1) >= 0) {
					continue;
				}
				if (!X509_REQ_add1_attr_by_txt(csr, v->name, MBSTRING_ASC, (unsigned char*)v->value, -1)) {
					luaL_error(L,"add1_attr_by_txt %s -> %s (failed)", v->name, v->value);
					return -1;
				}
			}
		}
	}

	X509_REQ_set_pubkey(csr, req->priv_key);
	return 0;
}

/* }}} */
#if 0
/* {{{ openssl_csr_from_zval */
static X509_REQ * openssl_csr_from_zval(zval ** val, int makeresource, long * resourceval)
{
	X509_REQ * csr = NULL;
	char * filename = NULL;
	BIO * in;
	
	if (resourceval) {
		*resourceval = -1;
	}
	if (Z_TYPE_PP(val) == IS_RESOURCE) {
		void * what;
		int type;

		what = zend_fetch_resource(val, -1, "OpenSSL X.509 CSR", &type, 1, le_csr);
		if (what) {
			if (resourceval) {
				*resourceval = Z_LVAL_PP(val);
			}
			return (X509_REQ*)what;
		}
		return NULL;
	} else if (Z_TYPE_PP(val) != IS_STRING) {
		return NULL;
	}

	if (Z_STRLEN_PP(val) > 7 && memcmp(Z_STRVAL_PP(val), "file://", sizeof("file://") - 1) == 0) {
		filename = Z_STRVAL_PP(val) + (sizeof("file://") - 1);
	}
	if (filename) {
		if (openssl_safe_mode_chk(filename)) {
			return NULL;
		}
		in = BIO_new_file(filename, "r");
	} else {
		in = BIO_new_mem_buf(Z_STRVAL_PP(val), Z_STRLEN_PP(val));
	}
	csr = PEM_read_bio_X509_REQ(in, NULL,NULL,NULL);
	BIO_free(in);

	return csr;
}
#endif
/* }}} */

/* {{{ proto bool openssl_csr_export_to_file(openssl.x509_req csr, string outfilename [, bool notext=true])
   Exports a CSR to file */
LUA_FUNCTION(openssl_csr_export_to_file)
{
	X509_REQ * csr;
	int notext = 1;
	const char * filename = NULL;
	BIO * bio_out;

	csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	filename = luaL_checkstring(L,2);
	notext = lua_isnil(L,3) ? 1 : lua_toboolean(L,3);

	bio_out = BIO_new_file(filename, "w");
	if (bio_out) {
		if (!notext) {
			X509_REQ_print(bio_out, csr);
		}
		PEM_write_bio_X509_REQ(bio_out, csr);
		lua_pushboolean(L,1);
	} else {
		luaL_error(L,"error opening file %s", filename);
		lua_pushboolean(L,0);
	}
	BIO_free(bio_out);
	return 1;
}
/* }}} */

/* {{{ proto string openssl_csr_export(resource csr [, bool notext=true])
   Exports a CSR to file or a var */
LUA_FUNCTION(openssl_csr_export)
{
	X509_REQ * csr;
	int notext = 1;
	BIO * bio_out;

	
	csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	notext = lua_gettop(L)==1 ? 1 : lua_toboolean(L,2);
	/* export to a var */

	bio_out = BIO_new(BIO_s_mem());
	if (!notext) {
		X509_REQ_print(bio_out, csr);
	}

	if (PEM_write_bio_X509_REQ(bio_out, csr)) {
		BUF_MEM *bio_buf;

		BIO_get_mem_ptr(bio_out, &bio_buf);
		lua_pushlstring(L,bio_buf->data, bio_buf->length);
	}else
	{
		lua_pushnil(L);
	}

	BIO_free(bio_out);
	return 1;
}
/* }}} */

/* {{{ proto resource openssl_csr_sign(mixed csr, mixed x509, mixed priv_key, long days [, array config_args [, long serial]])
   Signs a cert with another CERT */
LUA_FUNCTION(openssl_csr_sign)
{
	long num_days;
	long serial = 0L;
	X509 * cert = NULL, *new_cert = NULL;
	X509_REQ * csr;
	EVP_PKEY * key = NULL, *priv_key = NULL;
	long certresource = 0, keyresource = -1;
	int i;
	struct x509_request req;
	int ret = 0;

	csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	cert = CHECK_OBJECT(2,X509,"openssl.x509");
	priv_key = CHECK_OBJECT(3,EVP_PKEY,"openssl.evp_pkey");
	num_days = luaL_checkint(L,4);
	SSL_REQ_INIT(&req);
	
	if (cert && !X509_check_private_key(cert, priv_key)) {
		luaL_error(L,"private key does not correspond to signing cert");
	}
	
	if (SSL_REQ_PARSE(L, &req, 5) == -1) {
		goto cleanup;
	}
	/* Check that the request matches the signature */
	key = X509_REQ_get_pubkey(csr);
	if (key == NULL) {
		luaL_error(L,"error unpacking public key");
		goto cleanup;
	}
	i = X509_REQ_verify(csr, key);

	if (i < 0) {
		luaL_error(L,"Signature verification problems");
		goto cleanup;
	}
	else if (i == 0) {
		luaL_error(L,"Signature did not match the certificate request");
		goto cleanup;
	}
	
	/* Now we can get on with it */
	
	new_cert = X509_new();
	if (new_cert == NULL) {
		luaL_error(L, "No memory");
		goto cleanup;
	}
	/* Version 3 cert */
	if (!X509_set_version(new_cert, 2))
		goto cleanup;

	ASN1_INTEGER_set(X509_get_serialNumber(new_cert), serial);
	
	X509_set_subject_name(new_cert, X509_REQ_get_subject_name(csr));

	if (cert == NULL) {
		cert = new_cert;
	}
	if (!X509_set_issuer_name(new_cert, X509_get_subject_name(cert))) {
		goto cleanup;
	}
	X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(new_cert), (long)60*60*24*num_days);
	i = X509_set_pubkey(new_cert, key);
	if (!i) {
		goto cleanup;
	}
	if (req.extensions_section) {
		X509V3_CTX ctx;
		
		X509V3_set_ctx(&ctx, cert, new_cert, csr, NULL, 0);
		X509V3_set_conf_lhash(&ctx, req.req_config);
		if (!X509V3_EXT_add_conf(req.req_config, &ctx, (char*)req.extensions_section, new_cert)) {
			goto cleanup;
		}
	}

	/* Now sign it */
	if (!X509_sign(new_cert, priv_key, req.digest)) {
		luaL_error(L,"failed to sign it");
		goto cleanup;
	}
	
	/* Succeeded; lets return the cert */
	PUSH_OBJECT(new_cert,"openssl.x509");
	ret = 1;

	new_cert = NULL;
	
cleanup:

	if (cert == new_cert) {
		cert = NULL;
	}
	SSL_REQ_DISPOSE(&req);

	if (keyresource == -1 && priv_key) {
		EVP_PKEY_free(priv_key);
	}
	if (key) {
		EVP_PKEY_free(key);
	}

	if (new_cert) {
		X509_free(new_cert);
	}
	return ret;
}
/* }}} */

/* {{{openssl.csr_new(resource privkey, table dn,  [, array configargs [, array extraattribs]]) = >openssl.x509_req
   Generates CSR with gived private key, dn, configargs and extraattribs */
LUA_FUNCTION(openssl_csr_new)
{
	struct x509_request req;
	int  args, dn ,attribs;

	X509_REQ * csr = NULL;

	EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
	dn = 2;
	args = 3;
	attribs = 4;
	
	SSL_REQ_INIT(&req);

	if (SSL_REQ_PARSE(L, &req, args) == 0) {
		req.priv_key = pkey;

			csr = X509_REQ_new();
			if (csr) {
				if (openssl_make_REQ(L,&req, csr, dn, attribs) == 0) {
					X509V3_CTX ext_ctx;

					X509V3_set_ctx(&ext_ctx, NULL, NULL, csr, NULL, 0);
					X509V3_set_conf_lhash(&ext_ctx, req.req_config);

					/* Add extensions */
					if (req.request_extensions_section && !X509V3_EXT_REQ_add_conf(req.req_config,
								&ext_ctx, (char*)req.request_extensions_section, csr))
					{
						luaL_error(L,"Error loading extension section %s", req.request_extensions_section);
					} else {
						
						if (X509_REQ_sign(csr, req.priv_key, req.digest)) {
							PUSH_OBJECT(csr,"openssl.x509_req");
						} else {
							luaL_error(L,"Error signing request");
						}

						req.priv_key = NULL; /* make sure the cleanup code doesn't zap it! */
					}
				}
		}
	}
	if (csr) {
		X509_REQ_free(csr);
	}
	SSL_REQ_DISPOSE(&req);
}
/* }}} */

/* {{{ proto mixed openssl_csr_get_subject(mixed csr)
   Returns the subject of a CERT or FALSE on error */
LUA_FUNCTION(openssl_csr_get_subject)
{
	int  use_shortnames = 1;
	X509_NAME * subject;
	X509_REQ * csr;

	csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	use_shortnames = lua_gettop(L)==1?1:lua_toboolean(L,2);


	subject = X509_REQ_get_subject_name(csr);

	lua_newtable(L);
	add_assoc_name_entry(L, NULL, subject, use_shortnames);
	return 1;
}
/* }}} */

/* {{{ proto mixed openssl_csr_get_public_key(mixed csr)
	Returns the subject of a CERT or FALSE on error */
LUA_FUNCTION(openssl_csr_get_public_key)
{
	int use_shortnames = 1;

	X509_REQ * csr;
	EVP_PKEY *tpubkey;

	csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	use_shortnames = lua_gettop(L)==1?1:lua_toboolean(L,2);

	tpubkey=X509_REQ_get_pubkey(csr);
	PUSH_OBJECT(tpubkey,"openssl.evp_pkey");
	return 1;
}

/* }}} */

/* }}} */
