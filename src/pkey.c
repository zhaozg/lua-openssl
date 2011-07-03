#include "openssl.h"
#include "auxiliar.h"

/* {{{ EVP Public/Private key functions */


luaL_Reg pkey_funcs[] = {
	{"is_private",		openssl_pkey_is_private},
	{"read",			openssl_pkey_read},
	{"export",			openssl_pkey_export},
	{"get_details",		openssl_pkey_get_details},

	{"__gc",			openssl_pkey_free},
	{"__tostring",		openssl_pkey_tostring},


	{NULL,			NULL},
};

static int openssl_is_private_key(EVP_PKEY* pkey);
static EVP_PKEY * openssl_generate_private_key(lua_State*L,struct x509_request * req);

/* {{{ openssl_evp_read(string data|openssl.x509 x509 [,bool public_key=true [,string passphrase]]) => openssl.evp_pkey
   Read from a file or a data, coerce it into a EVP_PKEY object.
	It can be:
		1. private key resource from openssl_get_privatekey()
		2. X509 resource -> public key will be extracted from it
		3. if it starts with file:// interpreted as path to key file
		4. interpreted as the data from the cert/key file and interpreted in same way as openssl_get_privatekey()
		5. an array(0 => [items 2..4], 1 => passphrase)
		6. if val is a string (possibly starting with file:///) and it is not an X509 certificate, then interpret as public key
	NOTE: If you are requesting a private key but have not specified a passphrase, you should use an
	empty string rather than NULL for the passphrase - NULL causes a passphrase prompt to be emitted in
	the Apache error log!
*/
int openssl_pkey_read(lua_State*L)
{
	EVP_PKEY * key = NULL;
	X509 * cert = NULL;
	const char * filename = NULL;

	int public_key = 1;
	const char * passphrase = NULL;

	int top = lua_gettop(L);
	public_key = top > 1 ? lua_toboolean(L,2):1;
	passphrase = top > 2 ? luaL_checkstring(L, 3) : NULL;

	if (auxiliar_getclassudata(L,"openssl.evp_pkey", 1)) {
		int is_priv;
		key = CHECK_OBJECT(1, EVP_PKEY,"openssl.evp_pkey");
		
		is_priv = openssl_is_private_key(key);
		if(public_key && is_priv)
			luaL_error(L,"evp_pkey object is not a public key");
	}else if(auxiliar_getclassudata(L,"openssl.x509", 1)) {
		if (!public_key)
			luaL_error(L,"evp_pkey object is not a private key");
		cert = CHECK_OBJECT(1, X509, "openssl.x509");
		key = X509_get_pubkey(cert);
	}else if(lua_isstring(L,1))
	{
		/* force it to be a string and check if it refers to a file */
		/* passing non string values leaks, object uses toString, it returns NULL 
		 * See bug38255.phpt 
		 */
		int len;
		const char *str = luaL_checklstring(L,1,&len);
		if(len>7 && memcmp(str, "file://", sizeof("file://") - 1) == 0)
		{
			filename = str + (sizeof("file://") - 1);
		}

		/* it's an X509 file/cert of some kind, and we need to extract the data from that */
		if (public_key) {
				/* not a X509 certificate, try to retrieve public key */
				BIO* in;
				if (filename) {
					in = BIO_new_file(filename, "r");
				} else {
					in = BIO_new_mem_buf((void*)str, len);
				}
				key = PEM_read_bio_PUBKEY(in, NULL,NULL, NULL);
				if (!key) {
					BIO_reset(in);
					key = d2i_PUBKEY_bio(in,NULL);
				}
				BIO_free(in);
		} else {
			BIO *in = NULL;
			if (filename) {
				in = BIO_new_file(filename, "r");
			} else {
				in = BIO_new_mem_buf((void*)str, len);
			}

			key = PEM_read_bio_PrivateKey(in, NULL,NULL, (void*)passphrase);
			BIO_free(in);
		}
	}

	if (public_key && cert && key == NULL) {
		/* extract public key from X509 cert */
		key = (EVP_PKEY *) X509_get_pubkey(cert);
	}

	if (key)
		PUSH_OBJECT(key,"openssl.evp_pkey");
	else
		lua_pushnil(L);
	return 1;
}
/* }}} */

/* {{{ openssl_generate_private_key */
static EVP_PKEY * openssl_generate_private_key(lua_State*L, struct x509_request * req)
{
	char * randfile = NULL;
	int egdsocket, seeded;
	EVP_PKEY * return_val = NULL;
	
	if (req->priv_key_bits < MIN_KEY_LENGTH) {
		luaL_error(L, "private key length is too short; it needs to be at least %d bits, not %d",
				MIN_KEY_LENGTH, req->priv_key_bits);
	}

	randfile = CONF_get_string(req->req_config, req->section_name, "RANDFILE");
	openssl_load_rand_file(randfile, &egdsocket, &seeded);
	
	if ((req->priv_key = EVP_PKEY_new()) != NULL) {
		switch(req->priv_key_type) {
			case OPENSSL_KEYTYPE_RSA:
				if (EVP_PKEY_assign_RSA(req->priv_key, RSA_generate_key(req->priv_key_bits, 0x10001, NULL, NULL))) {
					return_val = req->priv_key;
				}
				break;
#if !defined(NO_DSA) && defined(HAVE_DSA_DEFAULT_METHOD)
			case OPENSSL_KEYTYPE_DSA:
				{
					DSA *dsapar = DSA_generate_parameters(req->priv_key_bits, NULL, 0, NULL, NULL, NULL, NULL);
					if (dsapar) {
						DSA_set_method(dsapar, DSA_get_default_method());
						if (DSA_generate_key(dsapar)) {
							if (EVP_PKEY_assign_DSA(req->priv_key, dsapar)) {
								return_val = req->priv_key;
							}
						} else {
							DSA_free(dsapar);
						}
					}
				}
				break;
#endif
#if !defined(NO_DH)
			case OPENSSL_KEYTYPE_DH:
				{
					DH *dhpar = DH_generate_parameters(req->priv_key_bits, 2, NULL, NULL);
					int codes = 0;

					if (dhpar) {
						DH_set_method(dhpar, DH_get_default_method());
						if (DH_check(dhpar, &codes) && codes == 0 && DH_generate_key(dhpar)) {
							if (EVP_PKEY_assign_DH(req->priv_key, dhpar)) {
								return_val = req->priv_key;
							}
						} else {
							DH_free(dhpar);
						}
					}
				}
				break;
#endif
			default:
				luaL_error(L,"Unsupported private key type");
		}
	}

	openssl_write_rand_file(randfile, egdsocket, seeded);
	
	if (return_val == NULL) {
		EVP_PKEY_free(req->priv_key);
		req->priv_key = NULL;
		return NULL;
	}
	
	return return_val;
}
/* }}} */

/* {{{ openssl_is_private_key
	Check whether the supplied key is a private key by checking if the secret prime factors are set */
static int openssl_is_private_key(EVP_PKEY* pkey)
{
	assert(pkey != NULL);

	switch (pkey->type) {
#ifndef NO_RSA
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			assert(pkey->pkey.rsa != NULL);
			if (pkey->pkey.rsa != NULL && (NULL == pkey->pkey.rsa->p || NULL == pkey->pkey.rsa->q)) {
				return 0;
			}
			break;
#endif
#ifndef NO_DSA
		case EVP_PKEY_DSA:
		case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			assert(pkey->pkey.dsa != NULL);

			if (NULL == pkey->pkey.dsa->p || NULL == pkey->pkey.dsa->q || NULL == pkey->pkey.dsa->priv_key){ 
				return 0;
			}
			break;
#endif
#ifndef NO_DH
		case EVP_PKEY_DH:
			assert(pkey->pkey.dh != NULL);

			if (NULL == pkey->pkey.dh->p || NULL == pkey->pkey.dh->priv_key) {
				return 0;
			}
			break;
#endif
		default:
			return -1;
			break;
	}
	return 1;
}
/* }}} */

#define OPENSSL_PKEY_GET_BN(_type, _name) do {							\
		if (pkey->pkey._type->_name != NULL) {							\
			int len = BN_num_bytes(pkey->pkey._type->_name);			\
			char *str = malloc(len + 1);								\
			BN_bn2bin(pkey->pkey._type->_name, (unsigned char*)str);	\
			str[len] = 0;                                           	\
			lua_pushlstring(L,str,len);									\
			lua_setfield(L,-2,#_name);									\
		}																\
	} while (0)

#define OPENSSL_PKEY_SET_BN(n, _type, _name) do {						\
	lua_getfield(L,n,#_name);											\
	if(lua_isstring(L,-1)) {											\
		size_t l; const char* bn = luaL_checklstring(L,-1,&l);				\
		_type->_name = BN_bin2bn(bn,l,NULL);							\
	};																	\
	lua_pop(L,1);	} while (0);


/* {{{ proto resource openssl_pkey_new([array configargs])
   Generates a new private key */
LUA_FUNCTION(openssl_pkey_new)
{
	struct x509_request req;
	int args = lua_gettop(L);
	EVP_PKEY *pkey = NULL;

	if (args && lua_istable(L,args)) {
		lua_getfield(L,1,"rsa");
		if (lua_istable(L,-1))
		{
			pkey = EVP_PKEY_new();
			if (pkey) {
				RSA *rsa = RSA_new();
				if (rsa) {
					OPENSSL_PKEY_SET_BN(-1, rsa, n);
					OPENSSL_PKEY_SET_BN(-1, rsa, e);
					OPENSSL_PKEY_SET_BN(-1, rsa, d);
					OPENSSL_PKEY_SET_BN(-1, rsa, p);
					OPENSSL_PKEY_SET_BN(-1, rsa, q);
					OPENSSL_PKEY_SET_BN(-1, rsa, dmp1);
					OPENSSL_PKEY_SET_BN(-1, rsa, dmq1);
					OPENSSL_PKEY_SET_BN(-1, rsa, iqmp);
					if (rsa->n && rsa->d) {
						if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
							EVP_PKEY_free(pkey);
							pkey = NULL;
						}
					}
					RSA_free(rsa);
				}
			}
		}
		lua_pop(L,1);
		if(!pkey)
		{
			lua_getfield(L,1,"dsa");
			if (lua_istable(L,-1)) {
				pkey = EVP_PKEY_new();
				if (pkey) {
					DSA *dsa = DSA_new();
					if (dsa) {
						OPENSSL_PKEY_SET_BN(-1, dsa, p);
						OPENSSL_PKEY_SET_BN(-1, dsa, q);
						OPENSSL_PKEY_SET_BN(-1, dsa, g);
						OPENSSL_PKEY_SET_BN(-1, dsa, priv_key);
						OPENSSL_PKEY_SET_BN(-1, dsa, pub_key);
						if (dsa->p && dsa->q && dsa->g) {
							if (!dsa->priv_key && !dsa->pub_key) {
								DSA_generate_key(dsa);
							}
							if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
								EVP_PKEY_free(pkey);
								pkey = NULL;
							}
						}
						DSA_free(dsa);
					}
				}
			}
			lua_pop(L,1);
		}
		if(!pkey) {
			lua_getfield(L,1,"dh");
			if (lua_istable(L,-1)) {
				pkey = EVP_PKEY_new();
				if (pkey) {
					DH *dh = DH_new();
					if (dh) {
						OPENSSL_PKEY_SET_BN(-1, dh, p);
						OPENSSL_PKEY_SET_BN(-1, dh, g);
						OPENSSL_PKEY_SET_BN(-1, dh, priv_key);
						OPENSSL_PKEY_SET_BN(-1, dh, pub_key);
						if (dh->p && dh->g) {
							if (!dh->pub_key) {
								DH_generate_key(dh);
							}
							if (!EVP_PKEY_assign_DH(pkey, dh)) {
								EVP_PKEY_free(pkey);
								pkey = NULL;
							}
						}
						DH_free(dh);
					}
				}
			}
			lua_pop(L,1);
		}
		if(pkey)
		{
			PUSH_OBJECT(pkey,"openssl.evp_pkey");
			return 1;
		}
	}else
	{
		SSL_REQ_INIT(&req);

		if (SSL_REQ_PARSE(L, &req, args) == 0)
		{
			if (openssl_generate_private_key(L,&req)) {
				/* pass back a key resource */
				pkey = req.priv_key;
				req.priv_key = NULL;
			}
		}
		SSL_REQ_DISPOSE(&req);
	}
	if(pkey)
	{
		PUSH_OBJECT(pkey,"openssl.evp_pkey");
		return 1;
	}
	return 0;

}
/* }}} */

/* {{{ openssl.pkey_export(mixed key, [, string passphrase, array config_args [string outfilename]) => data | bool
   Gets an exportable representation of a key into a file or a var */

LUA_FUNCTION(openssl_pkey_export)
{
	struct x509_request req;
	int args;
	const char * passphrase = NULL;
	int passphrase_len = 0;
	const char * filename = NULL;
	BIO * bio_out = NULL;
	int ret = 0;
	const EVP_CIPHER * cipher;

	EVP_PKEY * key = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	passphrase = luaL_optlstring(L,2, NULL,&passphrase_len);
	args = lua_gettop(L)>2 ? 3 : 0;
	filename = luaL_optstring(L,4,NULL);
	
	SSL_REQ_INIT(&req);

	if(filename)
	{
		if (SSL_REQ_PARSE(L,&req, args) == 0) {
			bio_out = BIO_new_file(filename, "w");

			if (passphrase && req.priv_key_encrypt) {
				cipher = (EVP_CIPHER *) EVP_des_ede3_cbc();
			} else {
				cipher = NULL;
			}
			if (PEM_write_bio_PrivateKey(bio_out, key, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)) {
				/* 0!
				 * If returning the output as a string, do so now */
				ret = 1;
			}
			if (bio_out) {
				BIO_free(bio_out);
			}
		}
		SSL_REQ_DISPOSE(&req);
		lua_pushboolean(L,ret);
		return 1;
	}else
	{
		if (SSL_REQ_PARSE(L, &req, args) == 0) {
			bio_out = BIO_new(BIO_s_mem());

			if (passphrase && req.priv_key_encrypt) {
				cipher = (EVP_CIPHER *) EVP_des_ede3_cbc();
			} else {
				cipher = NULL;
			}
			if (PEM_write_bio_PrivateKey(bio_out, key, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)) {
				/* 0!
				 * If returning the output as a string, do so now */

				char * bio_mem_ptr;
				long bio_mem_len;

				bio_mem_len = BIO_get_mem_data(bio_out, &bio_mem_ptr);

				lua_pushlstring(L, bio_mem_ptr, bio_mem_len);
				ret = 1;
			}

			if (bio_out) {
				BIO_free(bio_out);
			}
		}
	}
	SSL_REQ_DISPOSE(&req);
	return ret;
}

/* }}} */

/* {{{ proto void openssl_pkey_free(int key)
   Frees a key */
LUA_FUNCTION(openssl_pkey_free)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	EVP_PKEY_free(pkey);
	return 0;
}
/* }}} */


/* {{{ proto resource openssl_pkey_get_details(resource key)
	returns an array with the key details (bits, pkey, type)*/
LUA_FUNCTION(openssl_pkey_get_details)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	BIO *out;
	unsigned int pbio_len;
	char *pbio;
	long ktype;

	out = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(out, pkey);
	pbio_len = BIO_get_mem_data(out, &pbio);

	lua_newtable(L);

	lua_pushinteger(L,EVP_PKEY_bits(pkey));
	lua_setfield(L,-2,"bits");

	lua_pushlstring(L,pbio, pbio_len);
	lua_setfield(L,-2,"key");

	/*TODO: Use the real values once the openssl constants are used 
	 * See the enum at the top of this file
	 */
	switch (EVP_PKEY_type(pkey->type)) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			ktype = OPENSSL_KEYTYPE_RSA;

			if (pkey->pkey.rsa != NULL) {
				lua_newtable(L);
				OPENSSL_PKEY_GET_BN(rsa, n);
				OPENSSL_PKEY_GET_BN(rsa, e);
				OPENSSL_PKEY_GET_BN(rsa, d);
				OPENSSL_PKEY_GET_BN(rsa, p);
				OPENSSL_PKEY_GET_BN(rsa, q);
				OPENSSL_PKEY_GET_BN(rsa, dmp1);
				OPENSSL_PKEY_GET_BN(rsa, dmq1);
				OPENSSL_PKEY_GET_BN(rsa, iqmp);
				lua_setfield(L,-2, "rsa");
			}

			break;	
		case EVP_PKEY_DSA:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			ktype = OPENSSL_KEYTYPE_DSA;

			if (pkey->pkey.dsa != NULL) {
				lua_newtable(L);
				OPENSSL_PKEY_GET_BN(dsa, p);
				OPENSSL_PKEY_GET_BN(dsa, q);
				OPENSSL_PKEY_GET_BN(dsa, g);
				OPENSSL_PKEY_GET_BN(dsa, priv_key);
				OPENSSL_PKEY_GET_BN(dsa, pub_key);
				lua_setfield(L,-2, "dsa");
			}
			break;
		case EVP_PKEY_DH:
			
			ktype = OPENSSL_KEYTYPE_DH;

			if (pkey->pkey.dh != NULL) {
				lua_newtable(L);
				OPENSSL_PKEY_GET_BN(dh, p);
				OPENSSL_PKEY_GET_BN(dh, g);
				OPENSSL_PKEY_GET_BN(dh, priv_key);
				OPENSSL_PKEY_GET_BN(dh, pub_key);
				lua_setfield(L,-2, "dh");
			}

			break;
#ifdef EVP_PKEY_EC 
		case EVP_PKEY_EC:
			ktype = OPENSSL_KEYTYPE_EC;
			break;
#endif
		default:
			ktype = -1;
			break;
	}
	lua_pushinteger(L,ktype);
	lua_setfield(L,2,"type");

	BIO_free(out);
	return 1;
}
/* }}} */

LUA_FUNCTION(openssl_pkey_is_private)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	int private = openssl_is_private_key(pkey);
	if (private==0)
		lua_pushboolean(L,0);
	else if(private==1)
		lua_pushboolean(L,1);
	else
		luaL_error(L,"openssl.evp_pkey is not support");
	return 1;
}

LUA_FUNCTION(openssl_pkey_tostring)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	lua_pushfstring(L,"openssl.evp_pkey:%p",pkey);
	return 1;
}


/* }}} */
