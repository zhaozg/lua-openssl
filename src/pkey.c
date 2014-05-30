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
* evp_pkey routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "auxiliar.h"
#ifndef OPENSSL_NO_EC
#include "ec_lcl.h"
#endif

static int openssl_pkey_bits(lua_State *L) {
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	lua_Integer ret=EVP_PKEY_bits(pkey);
	lua_pushinteger(L,ret);
	return  1;
};

/* {{{ EVP Public/Private key functions */

static luaL_Reg pkey_funcs[] = {
    {"is_private",		openssl_pkey_is_private},
    {"export",			openssl_pkey_export},
    {"parse",			openssl_pkey_parse},
    {"bits",			openssl_pkey_bits},

    {"encrypt",			openssl_pkey_encrypt},
    {"decrypt",			openssl_pkey_decrypt},

    {"__gc",			openssl_pkey_free},
    {"__tostring",		auxiliar_tostring},

    {NULL,			NULL},
};

static int openssl_is_private_key(EVP_PKEY* pkey);

/* {{{ openssl_evp_read(string data|openssl.x509 x509 [,bool public_key=true [,string passphrase]]) => openssl.evp_pkey
Read from a file or a data, coerce it into a EVP_PKEY object.
It can be:
1. private key resource from openssl_get_privatekey()
2. X509 resource -> public key will be extracted from it
3. interpreted as the data from the cert/key file and interpreted in same way as openssl_get_privatekey()
4. an array(0 => [items 2..4], 1 => passphrase)
5. if val is a string and it is not an X509 certificate, then interpret as public key
NOTE: If you are requesting a private key but have not specified a passphrase, you should use an
empty string rather than NULL for the passphrase - NULL causes a passphrase prompt to be emitted in
the Apache error log!
*/
int openssl_pkey_read(lua_State*L)
{
    EVP_PKEY * key = NULL;

    int public_key = 1;
    const char * passphrase = NULL;

    int top = lua_gettop(L);
    public_key = top > 1 ? lua_toboolean(L,2):1;
    passphrase = top > 2 ? luaL_checkstring(L, 3) : NULL;

    if(auxiliar_isclass(L,"openssl.x509", 1)) {
        X509 * cert = NULL;
        if (!public_key)
            luaL_error(L,"x509 object not have a private key");
        cert = CHECK_OBJECT(1, X509, "openssl.x509");
        key = X509_get_pubkey(cert);
    }

    if (auxiliar_isclass(L,"openssl.evp_pkey", 1)) {
        int is_priv;
        key = CHECK_OBJECT(1, EVP_PKEY,"openssl.evp_pkey");

        is_priv = openssl_is_private_key(key);
        if(public_key) {
            if(is_priv)
                luaL_error(L,"evp_pkey object is not a public key, NYI read from private");
        }
	key->references++;
    }

    if(lua_isstring(L,1))
    {
        size_t len;
        const char *str = luaL_checklstring(L,1,&len);

        /* it's an X509 file/cert of some kind, and we need to extract the data from that */
        if (public_key) {
            /* not a X509 certificate, try to retrieve public key */
            BIO* in = BIO_new_mem_buf((void*)str, len);
            key = PEM_read_bio_PUBKEY(in, NULL,NULL, NULL);
            if (!key) {
                BIO_reset(in);
                key = d2i_PUBKEY_bio(in,NULL);
            }
            BIO_free(in);
        } else {
            BIO *in = BIO_new_mem_buf((void*)str, len);

            key = PEM_read_bio_PrivateKey(in, NULL,NULL, (void*)passphrase);
            if(!key)
            {
                BIO_reset(in);
                d2i_PrivateKey_bio(in, &key);
            }
            BIO_free(in);
        }
    }

    if (key)
        PUSH_OBJECT(key,"openssl.evp_pkey");
    else
        lua_pushnil(L);
    return 1;
}
/* }}} */

/* {{{ openssl_is_private_key
Check whether the supplied key is a private key by checking if the secret prime factors are set */
static int openssl_is_private_key(EVP_PKEY* pkey)
{
    assert(pkey != NULL);

    switch (pkey->type) {
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        assert(pkey->pkey.rsa != NULL);
        if (pkey->pkey.rsa != NULL && (NULL == pkey->pkey.rsa->p || NULL == pkey->pkey.rsa->q)) {
            return 0;
        }
        break;
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
    case EVP_PKEY_DSA1:
    case EVP_PKEY_DSA2:
    case EVP_PKEY_DSA3:
    case EVP_PKEY_DSA4:
        assert(pkey->pkey.dsa != NULL);

        if (NULL == pkey->pkey.dsa->p || NULL == pkey->pkey.dsa->q || NULL == pkey->pkey.dsa->priv_key) {
            return 0;
        }
        break;
#endif
#ifndef OPENSSL_NO_DH
    case EVP_PKEY_DH:
        assert(pkey->pkey.dh != NULL);

        if (NULL == pkey->pkey.dh->p || NULL == pkey->pkey.dh->priv_key) {
            return 0;
        }
        break;
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        assert(pkey->pkey.ec != NULL);

        if (NULL == pkey->pkey.ec->priv_key) {
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

#define OPENSSL_PKEY_GET_BN(bn, _name)  if (bn != NULL) {	\
	char *str = BN_bn2hex(bn);	\
	lua_pushstring(L,str);									\
	lua_setfield(L,-2,#_name);									\
	OPENSSL_free(str);									\
}

#define OPENSSL_PKEY_SET_BN(n, _type, _name) {						\
	lua_getfield(L,n,#_name);											\
	if(lua_isstring(L,-1)) {											\
	    size_t l; const char* bn = luaL_checklstring(L,-1,&l);				\
	    BN_hex2bn(&_type->_name,bn);							\
	};																	\
	lua_pop(L,1);}


int EC_KEY_generate_key_part(EC_KEY *eckey)
{	
	int	ok = 0;
	BN_CTX	*ctx = NULL;
	BIGNUM	*priv_key = NULL, *order = NULL;
	EC_POINT *pub_key = NULL;
	const EC_GROUP *group;

	if (!eckey)
	{
		return 0;
	}
	group = EC_KEY_get0_group(eckey);

	if ((order = BN_new()) == NULL) goto err;
	if ((ctx = BN_CTX_new()) == NULL) goto err;
	priv_key = (BIGNUM*)EC_KEY_get0_private_key(eckey);

	if (priv_key == NULL)
	{
		goto err;
	}

	if (!EC_GROUP_get_order(group, order, ctx))
		goto err;

	if(BN_is_zero(priv_key))
		goto err;
	pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);

	if (pub_key == NULL)
	{
		pub_key = EC_POINT_new(group);
		if (pub_key == NULL)
			goto err;
	}

	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;
	{
		EC_POINT_make_affine(EC_KEY_get0_group(eckey),
			(EC_POINT *)EC_KEY_get0_public_key(eckey),
			NULL);
	}
	EC_KEY_set_private_key(eckey,priv_key);
	EC_KEY_set_public_key(eckey, pub_key);

	ok=1;

err:	
	if (order)
		BN_free(order);

	if (ctx != NULL)
		BN_CTX_free(ctx);
	return(ok);
}
/* {{{ openssl_pkey_new([table config args])->openssl.evp_pkey
Generates a new private key */
LUA_FUNCTION(openssl_pkey_new)
{
    EVP_PKEY *pkey = NULL;
    const char* alg = "rsa";

    if (lua_isnoneornil(L,1) || lua_isstring(L,1)) {
        alg = luaL_optstring(L,1,alg);

        if (strcasecmp(alg,"rsa")==0)
        {
            int bits = luaL_optint(L,2,1024);
            int e = luaL_optint(L,3,65537);
            RSA* rsa = bits?RSA_generate_key(bits,e,NULL,NULL):RSA_new();
			if(bits==0 || rsa->n==0)
				rsa->n = BN_new();
            pkey = EVP_PKEY_new();
			EVP_PKEY_set1_RSA(pkey,rsa);
        } else if(strcasecmp(alg,"dsa")==0)
        {
            int bits = luaL_optint(L,2,1024);
       	    size_t seed_len = 0;
            const char* seed = luaL_optlstring(L,3,NULL,&seed_len);

            DSA *dsa = DSA_generate_parameters(bits, (byte*)seed,seed_len, NULL,  NULL, NULL, NULL);
            if( !DSA_generate_key(dsa))
            {
                DSA_free(dsa);
                luaL_error(L,"DSA_generate_key failed");
            }
            pkey = EVP_PKEY_new();
            EVP_PKEY_set1_DSA(pkey, dsa);

        } else if(strcasecmp(alg,"dh")==0)
        {
            int bits = luaL_optint(L,2,512);
            int generator = luaL_optint(L,3,2);

            DH* dh = DH_new(); //dh = DH_generate_parameters(bits,generator,NULL,NULL);
            if(!DH_generate_parameters_ex(dh, bits, generator, NULL))
            {
                DH_free(dh);
                luaL_error(L,"DH_generate_parameters_ex failed");
            }
            DH_generate_key(dh);
            pkey = EVP_PKEY_new();
            EVP_PKEY_set1_DH(pkey,dh);
        }
#ifndef OPENSSL_NO_EC
        else if(strcasecmp(alg,"ec")==0)
        {
            int ec_name = NID_undef;
            EC_KEY *ec = NULL;
            
			int flag = OPENSSL_EC_NAMED_CURVE;

            if (lua_isnumber(L, 2)) {
                ec_name = luaL_checkint(L, 2);
            } else if(lua_isstring(L, 2)) {
                const char* name = luaL_checkstring(L,2);
                ec_name = OBJ_sn2nid(name);
            }
			flag = lua_isnoneornil(L, 3)? flag : lua_toboolean(L, 3);
            ec = EC_KEY_new();
			if(ec_name!=NID_undef){
				EC_GROUP *group = EC_GROUP_new_by_curve_name(ec_name);
				if (!group) {
					luaL_error(L,"not support curve_name %d:%s!!!!", ec_name, OBJ_nid2sn(ec_name));
				}
				EC_KEY_set_group(ec, group);
				if(!EC_KEY_generate_key(ec))
				{
					EC_KEY_free(ec);
					luaL_error(L,"EC_KEY_generate_key failed");
				}
			}

			EC_KEY_set_asn1_flag(ec, flag);

            pkey = EVP_PKEY_new();
            EVP_PKEY_set1_EC_KEY(pkey, ec);
        }
#endif
        else
        {
            luaL_error(L,"not support %s!!!!",alg);
        }
    } else if (lua_istable(L,1)) {
		lua_getfield(L,1,"alg");
		alg = luaL_optstring(L,-1,alg);
		lua_pop(L,1);
        if (strcasecmp(alg,"rsa")==0)
        {
            pkey = EVP_PKEY_new();
            if (pkey) {
                RSA *rsa = RSA_new();
                if (rsa) {
                    OPENSSL_PKEY_SET_BN(1, rsa, n);
                    OPENSSL_PKEY_SET_BN(1, rsa, e);
                    OPENSSL_PKEY_SET_BN(1, rsa, d);
                    OPENSSL_PKEY_SET_BN(1, rsa, p);
                    OPENSSL_PKEY_SET_BN(1, rsa, q);
                    OPENSSL_PKEY_SET_BN(1, rsa, dmp1);
                    OPENSSL_PKEY_SET_BN(1, rsa, dmq1);
                    OPENSSL_PKEY_SET_BN(1, rsa, iqmp);
                    if (rsa->n) {
                        if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
                            EVP_PKEY_free(pkey);
                            pkey = NULL;
                        }
                    }
                }
            }
        }else if(strcasecmp(alg,"dsa")==0)
        {
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
						if (!EVP_PKEY_set1_DSA(pkey, dsa)) {
							EVP_PKEY_free(pkey);
							pkey = NULL;
						}
					}
				}
			}
        }
        else if(strcasecmp(alg,"dh")==0){

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
						if (!EVP_PKEY_set1_DH(pkey, dh)) {
							EVP_PKEY_free(pkey);
							pkey = NULL;
						}
					}
				}
			}
        }
        else if(strcasecmp(alg,"ec")==0)
        {

			int ec_name = NID_undef;
			BIGNUM *d = NULL;
			BIGNUM *x = NULL;
			BIGNUM *y = NULL;
			BIGNUM *z = NULL;
			EC_GROUP *group = NULL;

			lua_getfield(L, -1, "ec_name");
			if (lua_isnumber(L, -1)) {
				ec_name = luaL_checkint(L, -1);
			} else if(lua_isstring(L, -1)) {
				const char* name = luaL_checkstring(L,-1);
				ec_name = OBJ_sn2nid(name);
			}else{
				luaL_error(L,"not support ec_name type:%s!!!!", lua_typename(L,lua_type(L,-1)));
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "D");
			if(!lua_isnil(L, -1)){
				BN_hex2bn(&d,luaL_checkstring(L, -1));
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "X");
			if(!lua_isnil(L, -1)){
				BN_hex2bn(&x,luaL_checkstring(L, -1));
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "Y");
			if(!lua_isnil(L, -1)){
				BN_hex2bn(&y,luaL_checkstring(L, -1));
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "Z");
			if(!lua_isnil(L, -1)){
				BN_hex2bn(&z,luaL_checkstring(L, -1));
			}
			lua_pop(L,1);

			if(ec_name!=NID_undef)
				group = EC_GROUP_new_by_curve_name(ec_name);

			if (!group) {
				luaL_error(L,"not support curve_name %d:%s!!!!", ec_name, OBJ_nid2sn(ec_name));
			}

			pkey = EVP_PKEY_new();
			if (pkey) {
				EC_KEY *ec = EC_KEY_new();
				if (ec) {
					EC_KEY_set_group(ec,group);
					if(d)
						EC_KEY_set_private_key(ec,d);
					if(x!=NULL && y!=NULL){
						EC_POINT *pnt = EC_POINT_new(group);
						if(z==NULL)
							EC_POINT_set_affine_coordinates_GFp(group,pnt,x,y,NULL);
						else
							EC_POINT_set_Jprojective_coordinates_GFp(group,pnt,x,y,z,NULL);

						EC_KEY_set_public_key(ec,pnt);
					}
					
					if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) {
						EC_KEY_free(ec);
						EVP_PKEY_free(pkey);
						pkey = NULL;
					}
					if(d && !EC_KEY_check_key(ec)){
						EC_KEY_generate_key_part(ec);
					}
				}
			}        
		}
    }

    if(pkey)
    {
        PUSH_OBJECT(pkey,"openssl.evp_pkey");
        return 1;
    }
    return 0;

}
/* }}} */

/* {{{ openssl.pkey_export(openss.evp_key key [,boolean onlypublic=false, [boolean rawformat, [, string passphrase]]) => data | bool
Gets an exportable representation of a key into a file or a var */

LUA_FUNCTION(openssl_pkey_export)
{
    EVP_PKEY * key;
    int expub = 0;
    int exraw = 0;
    int expem = 1;
    size_t passphrase_len = 0;
    BIO * bio_out = NULL;
    int ret = 0;
    const EVP_CIPHER * cipher;
    const char * passphrase = NULL;
    int is_priv;

    key = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    if(!lua_isnoneornil(L,2))
        expub = lua_toboolean(L,2);
    if(!lua_isnoneornil(L,3))
        exraw = lua_toboolean(L,3);
    if(!lua_isnoneornil(L,4))
	expem = lua_toboolean(L,4);
    passphrase = luaL_optlstring(L,5, NULL,&passphrase_len);

    is_priv = openssl_is_private_key(key);
    bio_out = BIO_new(BIO_s_mem());
    if(!is_priv)
        expub = 1;

    if (passphrase) {
        cipher = (EVP_CIPHER *) EVP_des_ede3_cbc();
    } else {
        cipher = NULL;
    }

    if(!exraw) {
        /* export with EVP format */
        if (expub)
        {
			if(expem)
				ret = PEM_write_bio_PUBKEY(bio_out,key);
			else{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
				ret = i2b_PublicKey_bio(bio_out,key);
#else
				unsigned char* p;
				int l;
				l = i2d_PublicKey(key,NULL);
				if(l>0){
					p = malloc(l);
					l = i2d_PublicKey(key,&p);
					if(l>0){
						BIO_write(bio_out,p,l);
						ret = 1;
					}else
						ret = 0;
				}else
					ret = 0;
#endif
			}
        } else {
			if(expem)
				ret = PEM_write_bio_PrivateKey(bio_out, key, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL);
			else{
				if(passphrase==NULL){
#if OPENSSL_VERSION_NUMBER > 0x10000000L
					ret = i2b_PrivateKey_bio(bio_out,key);
#else
					unsigned char* p;
					int l;
					l = i2d_PrivateKey(key,NULL);
					if(l>0){
						p = malloc(l);
						l = i2d_PrivateKey(key,&p);
						if(l>0){
							BIO_write(bio_out,p,l);
							ret = 1;
						}else
							ret = 0;
					}else
						ret = 0;
#endif
				}else{
					ret = i2d_PKCS8PrivateKey_bio(bio_out,key,cipher,(char *)passphrase, passphrase_len, NULL, NULL);
				}
			}
        }
    } else
    {
        /* export raw key format */
        switch (EVP_PKEY_type(key->type)) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA2:
		if(expem){
			ret = !expub ? PEM_write_bio_RSAPrivateKey(bio_out,key->pkey.rsa, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
				: PEM_write_bio_RSAPublicKey(bio_out,key->pkey.rsa);
		}else{
			ret = !expub ? i2d_RSAPrivateKey_bio(bio_out,key->pkey.rsa)
				: i2d_RSA_PUBKEY_bio(bio_out,key->pkey.rsa);
		}
            break;
        case EVP_PKEY_DSA:
        case EVP_PKEY_DSA2:
        case EVP_PKEY_DSA3:
        case EVP_PKEY_DSA4:
		if(expem){
			ret = !expub ? PEM_write_bio_DSAPrivateKey(bio_out,key->pkey.dsa, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
				:PEM_write_bio_DSA_PUBKEY(bio_out,key->pkey.dsa);
		}else{
			ret = !expub ? i2d_DSAPrivateKey_bio(bio_out,key->pkey.dsa)
				:i2d_DSA_PUBKEY_bio(bio_out,key->pkey.dsa);
		}
            break;
        case EVP_PKEY_DH:
		if(expem)
			ret = PEM_write_bio_DHparams(bio_out,key->pkey.dh);
		else
			ret = i2d_DHparams_bio(bio_out,key->pkey.dh);
            break;
#ifndef OPENSSL_NO_EC
        case EVP_PKEY_EC:
		if(expem)
			ret = !expub ? PEM_write_bio_ECPrivateKey(bio_out,key->pkey.ec, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
				:PEM_write_bio_EC_PUBKEY(bio_out,key->pkey.ec);
		else
			ret = !expub ? i2d_ECPrivateKey_bio(bio_out,key->pkey.ec)
				:i2d_EC_PUBKEY_bio(bio_out,key->pkey.ec);

            break;
#endif
        default:
            ret = 0;
            break;
        }
    }
    if(ret) {
        char * bio_mem_ptr;
        long bio_mem_len;

        bio_mem_len = BIO_get_mem_data(bio_out, &bio_mem_ptr);

        lua_pushlstring(L, bio_mem_ptr, bio_mem_len);
        ret  = 1;
    }

    if (bio_out) {
        BIO_free(bio_out);
    }
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

/* {{{  openssl.pkey_parse(resource key)
returns an array with the key details (bits, pkey, type)*/
LUA_FUNCTION(openssl_pkey_parse)
{
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    lua_newtable(L);

    lua_pushinteger(L,EVP_PKEY_bits(pkey));
    lua_setfield(L,-2,"bits");


    /*TODO: Use the real values once the openssl constants are used
    * See the enum at the top of this file
    */
    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        if (pkey->pkey.rsa != NULL) {
            RSA* rsa = pkey->pkey.rsa;
            lua_newtable(L);
            OPENSSL_PKEY_GET_BN(rsa->n, n);
            OPENSSL_PKEY_GET_BN(rsa->e, e);
            OPENSSL_PKEY_GET_BN(rsa->d, d);
            OPENSSL_PKEY_GET_BN(rsa->p, p);
            OPENSSL_PKEY_GET_BN(rsa->q, q);
            OPENSSL_PKEY_GET_BN(rsa->dmp1, dmp1);
            OPENSSL_PKEY_GET_BN(rsa->dmq1, dmq1);
            OPENSSL_PKEY_GET_BN(rsa->iqmp, iqmp);
			PUSH_OBJECT(rsa,"openssl.rsa");
			lua_rawseti(L,-2, 0);
            lua_setfield(L,-2, "rsa");

            lua_pushstring(L,"rsa");
            lua_setfield(L,-2,"type");

        }

        break;
    case EVP_PKEY_DSA:
    case EVP_PKEY_DSA2:
    case EVP_PKEY_DSA3:
    case EVP_PKEY_DSA4:
        if (pkey->pkey.dsa != NULL) {
            DSA* dsa = pkey->pkey.dsa;
            lua_newtable(L);
            OPENSSL_PKEY_GET_BN(dsa->p, p);
            OPENSSL_PKEY_GET_BN(dsa->q, q);
            OPENSSL_PKEY_GET_BN(dsa->g, g);
            OPENSSL_PKEY_GET_BN(dsa->priv_key, priv_key);
            OPENSSL_PKEY_GET_BN(dsa->pub_key, pub_key);
			PUSH_OBJECT(dsa,"openssl.dsa");
			lua_rawseti(L,-2, 0);

            lua_setfield(L,-2, "dsa");

            lua_pushstring(L,"dsa");
            lua_setfield(L,-2,"type");

        }
        break;
    case EVP_PKEY_DH:
        if (pkey->pkey.dh != NULL) {
            DH* dh = pkey->pkey.dh;
            lua_newtable(L);
            OPENSSL_PKEY_GET_BN(dh->p, p);
            OPENSSL_PKEY_GET_BN(dh->g, g);
            OPENSSL_PKEY_GET_BN(dh->priv_key, priv_key);
            OPENSSL_PKEY_GET_BN(dh->pub_key, pub_key);
			PUSH_OBJECT(dh,"openssl.dh");
			lua_rawseti(L,-2, 0);
            lua_setfield(L,-2, "dh");

            lua_pushstring(L,"dh");
            lua_setfield(L,-2,"type");

        }

        break;
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        if(pkey->pkey.ec != NULL)
        {
			const EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
            const EC_POINT* point = EC_KEY_get0_public_key(ec);
			const EC_GROUP* group = EC_KEY_get0_group(ec);
            lua_newtable(L);

			/*
            lua_pushinteger(L, pkey->pkey.ec->version);
            lua_setfield(L, -2, "version");
			*/

            lua_pushinteger(L, EC_KEY_get_enc_flags(ec));
            lua_setfield(L, -2, "enc_flag");

            lua_pushinteger(L, EC_KEY_get_conv_form(ec));
            lua_setfield(L, -2, "conv_form");

			PUSH_OBJECT(point,"openssl.ec_point");
            lua_setfield(L, -2, "pub_key");
			
			PUSH_OBJECT(group, "openssl.ec_group");
			lua_setfield(L, -2, "group");

			OPENSSL_PKEY_GET_BN(ec->priv_key, priv_key);


			PUSH_OBJECT(ec,"openssl.ec_key");
			lua_setfield(L,-2,"ec");


            lua_pushstring(L,"ec");
            lua_setfield(L,-2,"type");
        }

        break;
#endif
    default:
        break;
    };

    return 1;
};
/* }}} */

static int get_padding(const char* padding) {

    if(padding==NULL || strcasecmp(padding,"pkcs1")==0)
        return RSA_PKCS1_PADDING;
    else if(strcasecmp(padding,"sslv23")==0)
        return RSA_SSLV23_PADDING;
    else if(strcasecmp(padding,"no")==0)
        return RSA_NO_PADDING;
    else if(strcasecmp(padding,"oaep")==0)
        return RSA_PKCS1_OAEP_PADDING;
    else if(strcasecmp(padding,"x931")==0)
        return RSA_X931_PADDING;
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    else if(strcasecmp(padding,"pss")==0)
        return  RSA_PKCS1_PSS_PADDING;
#endif
    return 0;
}

/* {{{ evp_pkey:encrypt(string data, [string padding=])=>string
   Encrypts data with key */
LUA_FUNCTION(openssl_pkey_encrypt)
{
    size_t dlen = 0;
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    const char *data = luaL_checklstring(L,2,&dlen);
    int padding = get_padding(luaL_optstring(L,3,"pkcs1"));
    int clen = EVP_PKEY_size(pkey);
    int private = openssl_is_private_key(pkey);
    luaL_Buffer buf;

    luaL_buffinit(L, &buf);

    switch (pkey->type) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        if(private) {
            if((RSA_private_encrypt(dlen,
                                    (unsigned char *)data,
                                    (byte*)luaL_prepbuffer(&buf),
                                    pkey->pkey.rsa,
                                    padding) == clen))
            {
                luaL_addsize(&buf,clen);
                luaL_pushresult(&buf);
                return 1;
            };
        } else
        {
            if(RSA_public_encrypt(dlen,
                                  (unsigned char *)data,
                                  (byte*)luaL_prepbuffer(&buf),
                                  pkey->pkey.rsa,
                                  padding) == clen)
            {
                luaL_addsize(&buf,clen);
                luaL_pushresult(&buf);
                return 1;
            }
        }

        break;
    default:
        luaL_error(L,"key type not supported in this lua build!");
    }
    return 0;
}
/* }}} */

/* {{{ evp_pkey:decrypt(string data,[,string padding=pkcs1]) => string
   Decrypts data with private key */
LUA_FUNCTION(openssl_pkey_decrypt)
{
    size_t dlen = 0;
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    const char *data = luaL_checklstring(L,2,&dlen);
    int padding = get_padding(luaL_optstring(L,3,"pkcs1"));
    int private = openssl_is_private_key(pkey);
    luaL_Buffer buf;
    int ret = 0;
    luaL_buffinit(L, &buf);

    switch (pkey->type) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA2:
        if(private)
        {
            ret = RSA_private_decrypt(dlen,
                                      (unsigned char *)data,
                                      (byte*)luaL_prepbuffer(&buf),
                                      pkey->pkey.rsa,
                                      padding);
            if (ret != -1) {
                luaL_addsize(&buf,ret);
                luaL_pushresult(&buf);
                return 1;
            }
        } else
        {
            ret = RSA_public_decrypt(dlen,
                                     (unsigned char *)data,
                                     (byte*)luaL_prepbuffer(&buf),
                                     pkey->pkey.rsa,
                                     padding);
            if (ret != -1) {
                luaL_addsize(&buf,ret);
                luaL_pushresult(&buf);
                return 1;
            }
        }
        break;
    default:
        luaL_error(L,"key type not supported in this Lua build!");
    }

    return 0;
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

int openssl_register_pkey(lua_State*L) {
    auxiliar_newclass(L,"openssl.evp_pkey", pkey_funcs);
    return 0;
}
