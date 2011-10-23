/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"



/* PKCS11 module for the Lua/OpenSSL binding.
 *
 * The functions in this module can be used to load, parse, export, verify... functions.
 * pkcs12_read()
 * pkcs12_export()
 */ 

/*  openssl.pkcs12_export(openssl.x509 x509, openssl.evp_pkey pkey, string pass [[, string friendname ], table extracerts]) -> string{{{1

	Creates and exports a PKCS to file *

	x509 is openssl.x509 object.
	pkey is openssl.evp_pkey object.
	pass is pkcs12 file password.
	option paramaers
	   friendly_name:	frinedly_name for pkcs11
	   extracerts:		extra certs in cert chains
	file is option
*/ 

LUA_FUNCTION(openssl_pkcs12_export)
{
	X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
	EVP_PKEY *priv_key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
	char * pass = (char*)luaL_checkstring(L,3);
	int top = lua_gettop(L);

	BIO * bio_out = NULL;
	PKCS12 * p12 = NULL;
	const char * friendly_name = NULL;
	STACK_OF(X509) *ca = NULL;

	if (top>3) {
		if(lua_isstring(L,4))
			friendly_name = lua_tostring(L,4);
		else if(lua_isuserdata(L, 4))
			ca = CHECK_OBJECT(4, STACK_OF(X509), "openssl.stack_of_x509");
		else
			luaL_typerror(L,4,"must be a string or openssl.stack_of_x509 object");

		if (top>4)
			ca = CHECK_OBJECT(5, STACK_OF(X509), "openssl.stack_of_x509");
	}

	if (cert && !X509_check_private_key(cert, priv_key)) {
		luaL_error(L,"private key does not correspond to cert");
	}

	/* end parse extra config */

	/*PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca,
                                       int nid_key, int nid_cert, int iter, int mac_iter, int keytype);*/

	p12 = PKCS12_create(pass, (char*)friendly_name, priv_key, cert, ca, 0, 0, 0, 0, 0);
	if (!p12)
		luaL_error(L,"PKCS12_careate failed,pleases get more error info");

	bio_out = BIO_new(BIO_s_mem());
	if (i2d_PKCS12_bio(bio_out, p12))  {
		BUF_MEM *bio_buf;
		
		BIO_get_mem_ptr(bio_out, &bio_buf);
		lua_pushlstring(L,bio_buf->data, bio_buf->length);
		BIO_free(bio_out);
		PKCS12_free(p12);
		return 1;
	}
	PKCS12_free(p12);

	return 0;
}
/* }}} */


/*  openssl.pkcs12_read(string pkcs12, string pass) -> table|nil{{{1

	Parses a PKCS12 to an table
	pkcs12 are file path or pkcs11 data
	. if it starts with file:// then it will be interpreted as the path to that pkcs12
	. it will be interpreted as the pkcs12 data

*/ 

LUA_FUNCTION(openssl_pkcs12_read)
{
	const char *pass, *zp12;
	int zp12_len;
	PKCS12 * p12 = NULL;
	EVP_PKEY * pkey = NULL;
	X509 * cert = NULL;
	STACK_OF(X509) * ca = NULL;
	BIO * bio_in = NULL;

	zp12 = luaL_checklstring(L, 1, &zp12_len);
	pass = luaL_checkstring(L, 2);
	
	bio_in = BIO_new_mem_buf((void*)zp12, zp12_len);

	
	if(d2i_PKCS12_bio(bio_in, &p12) && PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
			lua_newtable(L);

			PUSH_OBJECT(cert,"openssl.x509");
			lua_setfield(L,-2,"cert");

			PUSH_OBJECT(pkey,"openssl.evp_pkey");
			lua_setfield(L,-2,"pkey");

			PUSH_OBJECT(ca,"openssl.stack_of_x509");
			lua_setfield(L,-2,"extracerts");

			return 1;
	}
	return 0;
}
/* }}} */


/* }}} */

