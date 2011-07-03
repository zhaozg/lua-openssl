#include "openssl.h"

/* X509 module for the Lua/OpenSSL binding.
 *
 * The functions in this module can be used to load, parse, export, verify... functions.
 * parse()
 * export()
 * check_private_key()
 * checkpurpose()
 * public_key()
 */ 


luaL_Reg x509_funcs[] = {
	{"parse",				openssl_x509_parse},
	{"export",				openssl_x509_export},
	{"check_private_key",	openssl_x509_check_private_key},
	{"checkpurpose",		openssl_x509_checkpurpose},
	{"public_key",			openssl_x509_public_key},
	{"__gc",				openssl_x509_free},
	{"__tostring",			openssl_x509_tostring},


	{NULL,			NULL},
};

/*  openssl.x509_read(string val) -> openssl.x509 {{{1

	Read string val into an X509 object and returned, otherwise a nil
	The val can be:
	. if it starts with file:// then it will be interpreted as the path to that cert
	. it will be interpreted as the cert data
*/ 
LUA_FUNCTION(openssl_x509_read)
{
	X509 *cert = NULL;
	int data_len;
	const char *data = luaL_checklstring(L, 1, &data_len);

	if (data_len > 7 && memcmp(data, "file://", 7)==0)
	{
		BIO* in = BIO_new_file(data + 7, "r");
		if (in == NULL) {
			return 0;
		}
		cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
		if(!cert)
		{
			BIO_reset(in);
			cert = d2i_X509_bio(in,NULL);
		}
		BIO_free(in);
	} else {
		BIO *in = BIO_new_mem_buf((void*)data, data_len);
		if (in == NULL) {
			return 0;
		}
#ifdef TYPEDEF_D2I_OF
		cert = (X509 *) PEM_ASN1_read_bio((d2i_of_void *)d2i_X509, PEM_STRING_X509, in, NULL, NULL, NULL);
#else
		cert = (X509 *) PEM_ASN1_read_bio((char *(*)())d2i_X509, PEM_STRING_X509, in, NULL, NULL, NULL);
#endif
		if(!cert)
		{
			BIO_reset(in);
			cert = d2i_X509_bio(in,NULL);
		}
		BIO_free(in);
	}

	if (cert)
		

	if (cert)
	{
		PUSH_OBJECT(cert,"openssl.x509");
		return 1;
	}
	return 0;
}
/* }}} */ 

/*  openssl.x509_export(openssl.x509 x509 [, bool notext=true [, string outfilename]]) -> string|bool{{{1

	export an X509 object to var or save to file

	x509 object is openssl.x509 object.
	option notext and outfilename
	if outfilename not gived, encoded cert content is return, or save to gived filename.
	if noext not gived or value is true, will not export extend detail.
*/ 

LUA_FUNCTION(openssl_x509_export)
{
	int notext;
	const char * filename;
	X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
	int top = lua_gettop(L);

	notext = top > 1 ? lua_toboolean(L, 2) : 1;
	filename = top > 2 ? luaL_checkstring(L, 3) : NULL;

	if (filename) {
		BIO * bio_out = BIO_new_file(filename, "w");
		if (bio_out) {
			if (!notext) {
				X509_print(bio_out, cert);
			}
			PEM_write_bio_X509(bio_out, cert);

			BIO_free(bio_out);
			lua_pushboolean(L,1);
			return 1;
		} else {
			luaL_error(L,"error opening file %s", filename);
		}
	}else
	{
		BIO* bio_out = BIO_new(BIO_s_mem());
		if (!notext) {
			X509_print(bio_out, cert);
		}
		if (PEM_write_bio_X509(bio_out, cert))  {
			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(bio_out, &bio_buf);
			lua_pushlstring(L,bio_buf->data, bio_buf->length);
		}

		BIO_free(bio_out);
		return 1;
	}
	return 0;
}
/* }}} */

/*  openssl.x509_check_private_key(openssl.x509 x509, openssl.evp_pkey pkey) -> bool{{{1

	check an X509 object whether match with an EVP_PKEY, and return match result.
*/ 

LUA_FUNCTION(openssl_x509_check_private_key)
{
	X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
	EVP_PKEY * key = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");

	lua_pushboolean(L,X509_check_private_key(cert, key));
	return 1;
}
/* }}} */


/*  openssl.x509_parse(openssl.x509 x509 [,bool shortnames=true]) -> table{{{1

	parse an X509 object and return parsed information as a fields/values table.
*/ 

LUA_FUNCTION(openssl_x509_parse)
{
	X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
	int useshortnames = lua_isnil(L,2)?1:lua_toboolean(L,2);

	int i;
	char * tmpstr;
	X509_EXTENSION *extension;
	char *extname;
	BIO  *bio_out;
	BUF_MEM *bio_buf;
	char buf[256];

	lua_newtable(L);
	if (cert->name) {
		lua_pushstring(L,cert->name); lua_setfield(L,-2,"name");
	}

	lua_pushboolean(L,cert->valid);
	lua_setfield(L,-2,"valid");

	add_assoc_name_entry(L, "subject", 		X509_get_subject_name(cert), useshortnames);
	/* hash as used in CA directories to lookup cert by subject name */
	{
		char buf[32];
		snprintf(buf, sizeof(buf), "%08lx", X509_subject_name_hash(cert));
		lua_pushstring(L,buf); lua_setfield(L,-2,"hash");
	}
	
	add_assoc_name_entry(L, "issuer", 		X509_get_issuer_name(cert), useshortnames);

	lua_pushinteger(L,X509_get_version(cert)); lua_setfield(L,-2,"version");

	lua_pushstring(L,i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(cert))); lua_setfield(L,-2,"serialNumber");

	add_assoc_asn1_string(L, "validFrom", 	X509_get_notBefore(cert));
	add_assoc_asn1_string(L, "validTo", 		X509_get_notAfter(cert));
	add_assoc_asn1_time(L, "validFrom_time_t", X509_get_notBefore(cert));
	add_assoc_asn1_time(L, "validTo_time_t", X509_get_notAfter(cert));


	tmpstr = (char *)X509_alias_get0(cert, NULL);
	if (tmpstr) {
		add_assoc_string(L, "alias",tmpstr , 1);
	}
/*
	add_assoc_long(return_value, "signaturetypeLONG", X509_get_signature_type(cert));
	add_assoc_string(return_value, "signaturetype", OBJ_nid2sn(X509_get_signature_type(cert)), 1);
	add_assoc_string(return_value, "signaturetypeLN", OBJ_nid2ln(X509_get_signature_type(cert)), 1);
*/

	lua_newtable(L);
	/* NOTE: the purposes are added as integer keys - the keys match up to the X509_PURPOSE_SSL_XXX defines
	   in x509v3.h */
	for (i = 0; i < X509_PURPOSE_get_count(); i++) {
		int id, purpset;
		char * pname;
		X509_PURPOSE * purp;
		lua_newtable(L);
		purp = X509_PURPOSE_get0(i);
		id = X509_PURPOSE_get_id(purp);

		purpset = X509_check_purpose(cert, id, 0);
		add_index_bool(L, 1, purpset);

		purpset = X509_check_purpose(cert, id, 1);
		add_index_bool(L, 2, purpset);

		pname = useshortnames ? X509_PURPOSE_get0_sname(purp) : X509_PURPOSE_get0_name(purp);
		lua_pushstring(L,pname);
		lua_rawseti(L,-2,3);

		lua_rawseti(L,-2,i+1);

		/* NOTE: if purpset > 1 then it's a warning - we should mention it ? */
	}
	lua_setfield(L,-2,"purposes");

	lua_newtable(L);
	for (i = 0; i < X509_get_ext_count(cert); i++) {
		extension = X509_get_ext(cert, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_undef) {
			extname = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(extension)));
		} else {
			OBJ_obj2txt(buf, sizeof(buf)-1, X509_EXTENSION_get_object(extension), 1);
			extname = buf;
		}
		bio_out = BIO_new(BIO_s_mem());
		if (X509V3_EXT_print(bio_out, extension, 0, 0)) {
			BIO_get_mem_ptr(bio_out, &bio_buf);
			lua_pushlstring(L,bio_buf->data, bio_buf->length);
			lua_setfield(L,-2,extname);
		} else {
			add_assoc_asn1_string(L, extname, X509_EXTENSION_get_data(extension));
		}
		BIO_free(bio_out);
	}
	lua_setfield(L,-2,"extensions");
	return 1;
}
/* }}} */

/*  openssl.checkpurpose(openssl.x509 x509 int purpose, openssl.stack_of_x509 cainfo [, string untrustedfile]) -> boolean{{{1

	Checks the CERT to see if it can be used for the purpose in purpose. cainfo holds information about trusted CAs
*/ 
   
LUA_FUNCTION(openssl_x509_checkpurpose)
{
	X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
	long purpose = luaL_checkint(L,2);
	STACK_OF(X509)* cert_stack = CHECK_OBJECT(3,STACK_OF(X509),"openssl.stack_of_x509");
	X509_STORE * cainfo;	
	const char * untrusted = luaL_optstring(L,4,NULL);

	STACK_OF(X509) * untrustedchain = NULL;

	int untrusted_len = 0, ret;

	if (untrusted) {
		untrustedchain = load_all_certs_from_file(untrusted);
		if (untrustedchain == NULL) {
			goto clean_exit;
		}
	}

	cainfo = setup_verify(cert_stack);
	if (cainfo == NULL) {
		goto clean_exit;
	}

	ret = check_cert(cainfo, cert, untrustedchain, purpose);
	if (ret != 0 && ret != 1) {
		lua_pushinteger(L,ret);
	} else {
		lua_pushboolean(L,ret);
	}
	return 1;
clean_exit:
	if (cainfo) { 
		X509_STORE_free(cainfo); 
	}
	if (untrustedchain) {
		sk_X509_pop_free(untrustedchain, X509_free);
	}
	lua_pushnil(L);
	return 1;
}
/* }}} */

LUA_FUNCTION(openssl_x509_free)
{
	X509 *cert = CHECK_OBJECT(1,X509,"openssl.x509");
	X509_free(cert);
	return 0;
}

LUA_FUNCTION(openssl_x509_tostring)
{
	X509 *cert = CHECK_OBJECT(1,X509,"openssl.x509");
	lua_pushfstring(L,"openssl.x509:%p",cert);
	return 1;
}

LUA_FUNCTION(openssl_x509_public_key)
{
	X509 *cert = CHECK_OBJECT(1,X509,"openssl.x509");
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	PUSH_OBJECT(pkey,"openssl.evp_pkey");
	return 1;
}

