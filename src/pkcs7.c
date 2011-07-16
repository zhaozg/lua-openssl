/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"

/* {{{ PKCS7 S/MIME functions */

/* {{{ proto bool openssl_pkcs7_sign(openssl.bio in, openssl.bio out, x509 signcert, evp_pkey signkey, table headers 
		[, long flags [, stack_of_x509 extracertsfilename]])

   Signs the MIME message in the BIO in with signcert/signkey and output the result to BIO out. 
   headers lists plain text headers to exclude from the signed portion of the message, and should include to, from and subject as a minimum */

LUA_FUNCTION(openssl_pkcs7_sign)
{
	X509 * cert = NULL;
	EVP_PKEY * privkey = NULL;
	long flags = PKCS7_DETACHED;
	PKCS7 * p7 = NULL;
	BIO * infile = NULL, * outfile = NULL;
	STACK_OF(X509) *others = NULL;

	int headers = 5;
	int top = lua_gettop(L);
	int ret = 0;

	infile = CHECK_OBJECT(1, BIO, "openssl.bio");
	outfile = CHECK_OBJECT(2, BIO, "openssl.bio");
	cert = CHECK_OBJECT(3,X509,"openssl.x509");
	privkey = CHECK_OBJECT(4, EVP_PKEY,"openssl.evp_pkey");
	headers = 5;
	if(top>5)
		flags = luaL_checkint(L,6);
	if(top>6)
		others = CHECK_OBJECT(7, STACK_OF(X509), "openssl.stack_of_x509");

	p7 = PKCS7_sign(cert, privkey, others, infile, flags);
	if (p7 == NULL) {
		luaL_error(L,"error creating PKCS7 structure!");
		goto clean_exit;
	}

	(void)BIO_reset(infile);

	/* tack on extra headers */
	/* table is in the stack at index 't' */
	lua_pushnil(L);  /* first key */
	while (lua_next(L, headers) != 0) {
		/* uses 'key' (at index -2) and 'value' (at index -1) */
		//printf("%s - %s\n",lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
		const char *idx = lua_tostring(L,-2);
		const char *val = luaL_checkstring(L,-1);

		BIO_printf(outfile, "%s: %s\n", idx, val);

		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	/* write the signed data */
	ret = SMIME_write_PKCS7(outfile, p7, infile, flags);


clean_exit:
	PKCS7_free(p7);
	lua_pushboolean(L,ret);
	return 1;
}
/* }}} */


/* {{{ proto bool openssl.pkcs7_verify(bio in, long flags 
		[, stack_of_x509 signerscerts [, stack_of_x509 cainfo [, stack_of_x509 extracerts [, string content]]]])
   Verifys that the data block is intact, the signer is who they say they are, and returns the CERTs of the signers */
LUA_FUNCTION(openssl_pkcs7_verify)
{
	X509_STORE * store = NULL;
	STACK_OF(X509) *cainfo = NULL;
	STACK_OF(X509) *signers= NULL;
	STACK_OF(X509) *others = NULL;
	PKCS7 * p7 = NULL;
	BIO * in = NULL, * datain = NULL, * dataout = NULL;
	long flags = 0;

	int ret;
	int top = lua_gettop(L);
	
	in = CHECK_OBJECT(1,BIO,"openssl.bio");
	flags = luaL_checkinteger(L,2);
	if(top>2)
		signers = lua_isnoneornil(L,3) ? NULL : CHECK_OBJECT(3, STACK_OF(X509),"openssl.stack_of_x509");
	if(top>3)
		cainfo = CHECK_OBJECT(4, STACK_OF(X509),"openssl.stack_of_x509");
	if(top>4)
		others = CHECK_OBJECT(5, STACK_OF(X509),"openssl.stack_of_x509");

	if(top>5)
		dataout = CHECK_OBJECT(6, BIO, "openssl.bio");


	flags = flags & ~PKCS7_DETACHED;
	store = setup_verify(cainfo);

	if (!store) {
		goto clean_exit;
	}


	p7 = SMIME_read_PKCS7(in, &datain);
	if (p7 == NULL) {
		goto clean_exit;
	}


	if (PKCS7_verify(p7, others, store, datain, dataout, flags)) {
		ret = 1;
		if (signers) {
			int i;
			STACK_OF(X509) *signers1 = PKCS7_get0_signers(p7, NULL, flags);

			for(i = 0; i < sk_X509_num(signers1); i++) {
				sk_X509_push(signers,sk_X509_value(signers1, i));
			}
			sk_X509_free(signers1);
		}
		goto clean_exit;
	} else {
		ret = 0;
	}
clean_exit:
	X509_STORE_free(store);
	PKCS7_free(p7);
	lua_pushboolean(L,ret);
	return 1;
}
/* }}} */

/* {{{ proto bool openssl.pkcs7_encrypt(bio in, bio out, stack_of_x509 recipcerts, array headers [, long flags [, long cipher]])
   Encrypts the message in the file named infile with the certificates in recipcerts and output the result to the file named outfile */
LUA_FUNCTION(openssl_pkcs7_encrypt)
{
	STACK_OF(X509) * recipcerts = NULL;
	BIO * infile = NULL, * outfile = NULL;
	long flags = 0;
	PKCS7 * p7 = NULL;
	const EVP_CIPHER *cipher = EVP_get_cipherbynid(OPENSSL_CIPHER_DEFAULT);
	int ret = 0;
	int headers;
	int top = lua_gettop(L);

	infile = CHECK_OBJECT(1, BIO,"openssl.bio");
	outfile = CHECK_OBJECT(2, BIO,"openssl.bio");
	recipcerts = CHECK_OBJECT(3,STACK_OF(X509),"openssl.stack_of_x509");
	headers = 4;
	if (top>4)
		flags = luaL_checkinteger(L,5);
	if(top>5)
		cipher = CHECK_OBJECT(6,EVP_CIPHER,"openssl.evp_cipher");

	/* sanity check the cipher */
	if (cipher == NULL) {
		/* shouldn't happen */
		luaL_error(L, "Failed to get cipher");
	}

	p7 = PKCS7_encrypt(recipcerts, infile, (EVP_CIPHER*)cipher, flags);

	if (p7 == NULL) {
		goto clean_exit;
	}

	/* tack on extra headers */
	/* table is in the stack at index 't' */
	lua_pushnil(L);  /* first key */
	while (lua_next(L, headers) != 0) {
		/* uses 'key' (at index -2) and 'value' (at index -1) */
		//printf("%s - %s\n",lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
		const char *idx = lua_tostring(L,-2);
		const char *val = luaL_checkstring(L,-1);

		BIO_printf(outfile, "%s: %s\n", idx, val);

		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}


	(void)BIO_reset(infile);

	/* write the encrypted data */
	ret = SMIME_write_PKCS7(outfile, p7, infile, flags);

clean_exit:
	PKCS7_free(p7);

	lua_pushboolean(L,ret);
	return 1;
}
/* }}} */

/* {{{ proto bool openssl_pkcs7_decrypt(bio in, bio out, x509 recipcert [, evp_pkey recipkey])
   Decrypts the S/MIME message in the file name infilename and output the results to the file name outfilename.  recipcert is a CERT for one of the recipients. recipkey specifies the private key matching recipcert, if recipcert does not include the key */

LUA_FUNCTION(openssl_pkcs7_decrypt)
{
	X509 * cert = NULL;
	EVP_PKEY * key = NULL;

	BIO * in = NULL, * out = NULL, * datain = NULL;
	PKCS7 * p7 = NULL;

	int top = lua_gettop(L);
	int ret = 0;

	in = CHECK_OBJECT(1, BIO, "openssl.bio");
	out = CHECK_OBJECT(2, BIO, "openssl.bio");
	cert = CHECK_OBJECT(3,X509,"openssl.x509");
	key = lua_isnil(L,4)?NULL: CHECK_OBJECT(4,EVP_PKEY,"openssl.evp_pkey");

	p7 = SMIME_read_PKCS7(in, &datain);

	if (p7 == NULL) {
		goto clean_exit;
	}
	if (PKCS7_decrypt(p7, key, cert, out, PKCS7_DETACHED)) { 
		ret = 1;
	}
clean_exit:
	PKCS7_free(p7);
	BIO_free(datain);


	lua_pushboolean(L,ret);
	return 1;
}
/* }}} */


/* }}} */
