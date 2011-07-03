#include "openssl.h"



/* PKCS11 module for the Lua/OpenSSL binding.
 *
 * The functions in this module can be used to load, parse, export, verify... functions.
 * pkcs12_read()
 * pkcs12_export()
 */ 


/*  openssl.pkcs12_export(openssl.x509 x509, openssl.evp_pkey pkey, string pass [, table args | string filename | [table args , string filename]]) -> string|bool{{{1

	Creates and exports a PKCS to file *

	x509 is openssl.x509 object.
	pkey is openssl.evp_pkey object.
	pass is pkcs12 file password.
	args is option table
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
	char * friendly_name = NULL;
	char * filename = NULL;
	int args = 0;
	STACK_OF(X509) *ca = NULL;

	if (top==4 && lua_isstring(L,4))
		filename = (char*)lua_tostring(L,4);
	else if (top==4 && lua_istable(L,4))
		args = 4;
	else {
		luaL_checktype(L,4,LUA_TTABLE);
		args = 4;
		filename = (char*)luaL_checkstring(L,5);
	}

	if (cert && !X509_check_private_key(cert, priv_key)) {
		luaL_error(L,"private key does not correspond to cert");
	}

	if (args)
	{
		lua_getfield(L,5,"friendly_name");
		friendly_name = lua_isnil(L,-1)?NULL:(char*)luaL_checkstring(L,-1);
		lua_pop(L,1);

		lua_getfield(L,5,"extracerts");
		ca = lua_isnil(L,-1)?NULL:CHECK_OBJECT(-1,STACK_OF(X509),"openssl.stack_of_x509");
		lua_pop(L,1);
	}
	/* end parse extra config */

	/*PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca,
                                       int nid_key, int nid_cert, int iter, int mac_iter, int keytype);*/

	p12 = PKCS12_create(pass, friendly_name, priv_key, cert, ca, 0, 0, 0, 0, 0);
	if (!p12)
		luaL_error(L,"PKCS12_careate failed,pleases get more error info");

	if (filename) {
		bio_out = BIO_new_file(filename, "w"); 
		if (bio_out) {
			i2d_PKCS12_bio(bio_out, p12);
			BIO_free(bio_out);
			PKCS12_free(p12);
			lua_pushboolean(L,1);
			return 1;
		} else {
			PKCS12_free(p12);
			luaL_error(L,"error opening file %s", filename);
		}
	}else {
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
	}

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
	
	

	if (zp12_len > 7 && memcmp(zp12, "file://", 7)==0)
	{
		bio_in = BIO_new_file(zp12 + 7, "r");
	}else
	{
		bio_in = BIO_new(BIO_s_mem());
		BIO_write(bio_in, zp12, zp12_len);
	}

	
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