/*=========================================================================*\
* pkey.c
* pkey module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME		"pkey"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"pkey"

#ifndef OPENSSL_NO_EC
#include "ec_lcl.h"
#endif

static int openssl_pkey_bits(lua_State *L) {
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	lua_Integer ret=EVP_PKEY_bits(pkey);
	lua_pushinteger(L,ret);
	return  1;
};


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

static int openssl_pkey_read(lua_State*L)
{
    EVP_PKEY * key = NULL;
	BIO* in = load_bio_object(L, 1);
	int pub = lua_isnoneornil(L,2) ? 0 : auxiliar_checkboolean(L, 2);
	int fmt = luaL_checkoption(L, 3, "auto", format);

	if(pub){
		if(fmt==FORMAT_AUTO || fmt==FORMAT_PEM){
			key = PEM_read_bio_PUBKEY(in, NULL,NULL, NULL);
			BIO_reset(in);
		}
		if((fmt==FORMAT_AUTO && key==NULL) || fmt==FORMAT_DER){
			key = d2i_PUBKEY_bio(in,NULL);
			BIO_reset(in);
		}
	}else{
		if(fmt==FORMAT_AUTO || fmt==FORMAT_PEM){
			const char* passphrase = luaL_optstring(L, 4, NULL);
			key = PEM_read_bio_PrivateKey(in, NULL,NULL, (void*)passphrase);
			BIO_reset(in);
		}
		if((fmt==FORMAT_AUTO && key==NULL) || fmt==FORMAT_DER){
			d2i_PrivateKey_bio(in, &key);
			BIO_reset(in);
		}
	}
	BIO_free(in);
    if (key)
        PUSH_OBJECT(key,"openssl.evp_pkey");
    else
        lua_pushnil(L);
    return 1;
}

#define OPENSSL_PKEY_GET_BN(bn, _name)	\
if (bn != NULL) {						\
	PUSH_OBJECT(bn,"openssl.bn");		\
	lua_setfield(L,-2,#_name);			\
}

#define OPENSSL_PKEY_SET_BN(n, _type, _name)	{		\
	lua_getfield(L,n,#_name);							\
	if(lua_isstring(L,-1)) {							\
	    size_t l = 0;									\
		const char* bn = luaL_checklstring(L,-1,&l);	\
		if(_type->_name==NULL)  _type->_name = BN_new();\
	    BN_bin2bn(bn,l,_type->_name);					\
	}else if(auxiliar_isclass(L,"openssl.bn",n)) {		\
		const BIGNUM* bn = CHECK_OBJECT(n,BIGNUM,"openssl.bn");	\
		if(_type->_name==NULL)  _type->_name = BN_new();\
		BN_copy(_type->_name, bn);						\
	}else if(!lua_isnil(L,-1))	\
		luaL_error(L,"arg #%d must be string or openssl.bn",n);	\
	lua_pop(L,1);										\
}


static int EC_KEY_generate_key_part(EC_KEY *eckey)
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

#define CHECK_BN(b,n)								\
	if(lua_isstring(L, n)){							\
	size_t l =0;								\
	const char* s = luaL_checklstring(L,n,&l);	\
	BN_bin2bn(s,l,b);							\
	}else {											\
	const BIGNUM* bn = CHECK_OBJECT(n, BIGNUM, "openssl.bn");	\
	BN_copy(b,bn);								\
	}

static LUA_FUNCTION(openssl_pkey_new)
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
			EVP_PKEY_assign_RSA(pkey,rsa);
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
            EVP_PKEY_assign_DSA(pkey, dsa);

        } else if(strcasecmp(alg,"dh")==0)
        {
            int bits = luaL_optint(L,2,512);
            int generator = luaL_optint(L,3,2);

            DH* dh = DH_new();
            if(!DH_generate_parameters_ex(dh, bits, generator, NULL))
            {
                DH_free(dh);
                luaL_error(L,"DH_generate_parameters_ex failed");
            }
            DH_generate_key(dh);
            pkey = EVP_PKEY_new();
            EVP_PKEY_assign_DH(pkey,dh);
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
            }else
				luaL_argerror(L, 2, "must be ec_name string or nid");

			flag = lua_isnoneornil(L, 3)? flag : lua_toboolean(L, 3);
            ec = EC_KEY_new();
			if(ec_name!=NID_undef){
				EC_GROUP *group = EC_GROUP_new_by_curve_name(ec_name);
				if (!group) {
					luaL_error(L,"not support curve_name %d:%s!!!!", ec_name, OBJ_nid2sn(ec_name));
				}
				EC_KEY_set_group(ec, group);
				EC_GROUP_free(group);
				if(!EC_KEY_generate_key(ec))
				{
					EC_KEY_free(ec);
					luaL_error(L,"EC_KEY_generate_key failed");
				}
			}

			EC_KEY_set_asn1_flag(ec, flag);

            pkey = EVP_PKEY_new();
			EVP_PKEY_assign_EC_KEY(pkey, ec);
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
                        if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
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
						if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
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
						if (!EVP_PKEY_assign_DH(pkey, dh)) {
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
				d = BN_new();
				CHECK_BN(d,-1);
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "X");
			if(!lua_isnil(L, -1)){
				x = BN_new();
				CHECK_BN(x,-1);
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "Y");
			if(!lua_isnil(L, -1)){
				y = BN_new();
				CHECK_BN(y,-1);
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "Z");
			if(!lua_isnil(L, -1)){
				z = BN_new();
				CHECK_BN(z,-1);
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
					
					if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
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

static LUA_FUNCTION(openssl_pkey_export)
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
					int l = i2d_PrivateKey(key,NULL);
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

static LUA_FUNCTION(openssl_pkey_free)
{
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    EVP_PKEY_free(pkey);
    return 0;
}

static LUA_FUNCTION(openssl_pkey_parse)
{
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	if(pkey->pkey.ptr){
		lua_newtable(L);

		AUXILIAR_SET(L, -1, "bits",EVP_PKEY_bits(pkey), integer);
		AUXILIAR_SET(L, -1, "size",EVP_PKEY_size(pkey), integer); 
		/*TODO: Use the real values once the openssl constants are used
		* See the enum at the top of this file
		*/

		switch (EVP_PKEY_type(pkey->type)) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA2:
			{
				RSA* rsa = EVP_PKEY_get1_RSA(pkey);
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
				AUXILIAR_SET(L,-1,"type","rsa",string);
			}

			break;
		case EVP_PKEY_DSA:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			{
				DSA* dsa = EVP_PKEY_get1_DSA(pkey);
				lua_newtable(L);
				OPENSSL_PKEY_GET_BN(dsa->p, p);
				OPENSSL_PKEY_GET_BN(dsa->q, q);
				OPENSSL_PKEY_GET_BN(dsa->g, g);
				OPENSSL_PKEY_GET_BN(dsa->priv_key, priv_key);
				OPENSSL_PKEY_GET_BN(dsa->pub_key, pub_key);

				PUSH_OBJECT(dsa,"openssl.dsa");
				lua_rawseti(L,-2, 0);

				lua_setfield(L,-2, "dsa");
				AUXILIAR_SET(L, -1, "type","dsa", string);
			}
			break;
		case EVP_PKEY_DH:
			{
				DH* dh = EVP_PKEY_get1_DH(pkey);
				lua_newtable(L);
				OPENSSL_PKEY_GET_BN(dh->p, p);
				OPENSSL_PKEY_GET_BN(dh->g, g);
				OPENSSL_PKEY_GET_BN(dh->priv_key, priv_key);
				OPENSSL_PKEY_GET_BN(dh->pub_key, pub_key);

				PUSH_OBJECT(dh,"openssl.dh");
				lua_rawseti(L,-2, 0);

				lua_setfield(L,-2, "dh");
				AUXILIAR_SET(L, -1, "type","dh", string);
			}

			break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			{
				const EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
				const EC_POINT* point = EC_KEY_get0_public_key(ec);
				const EC_GROUP* group = EC_KEY_get0_group(ec);
				const BIGNUM *priv = EC_KEY_get0_private_key(ec);
				lua_newtable(L);

				AUXILIAR_SET(L, -1, "enc_flag", EC_KEY_get_enc_flags(ec), integer);
				AUXILIAR_SET(L, -1, "conv_form", EC_KEY_get_conv_form(ec), integer);

				point = EC_POINT_dup(point,group);
				AUXILIAR_SETOBJECT(L,point,"openssl.ec_point",-1, "pub_key");
				group = EC_GROUP_dup(group);
				AUXILIAR_SETOBJECT(L,group, "openssl.ec_group",-1, "group");

				priv = BN_dup(priv);
				OPENSSL_PKEY_GET_BN(priv, priv_key);

				PUSH_OBJECT(ec,"openssl.ec_key");
				lua_rawseti(L,-2, 0);

				lua_setfield(L,-2, "ec");
				AUXILIAR_SET(L, -1, "type", "ec", string);
			}

			break;
#endif
		default:
			break;
		};
		return 1;
	}else
		luaL_argerror(L, 1, "not assign any keypair");
	return 0;
};
/* }}} */

static const char* sPadding[] = {
	"pkcs1",
	"sslv23",
	"no",
	"oaep",
	"x931",
#if OPENSSL_VERSION_NUMBER > 0x10000000L
	"pss",
#endif
	NULL,
};

static int iPadding[] = {
	RSA_PKCS1_PADDING,
	RSA_SSLV23_PADDING,
	RSA_NO_PADDING,
	RSA_PKCS1_OAEP_PADDING,
	RSA_X931_PADDING,
#if OPENSSL_VERSION_NUMBER > 0x10000000L
	RSA_PKCS1_PSS_PADDING
#endif
};

static LUA_FUNCTION(openssl_pkey_encrypt)
{
    size_t dlen = 0;
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    const char *data = luaL_checklstring(L,2,&dlen);
    int padding = auxiliar_checkoption(L,3,"pkcs1",sPadding,iPadding);
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

static LUA_FUNCTION(openssl_pkey_decrypt)
{
    size_t dlen = 0;
    EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
    const char *data = luaL_checklstring(L,2,&dlen);
    int padding = auxiliar_checkoption(L,3,"pkcs1",sPadding,iPadding);
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

static LUA_FUNCTION(openssl_pkey_is_private)
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

static LUA_FUNCTION(openssl_pkey_get_public)
{
	EVP_PKEY *pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	int private = openssl_is_private_key(pkey);
	int ret = 0;
	if (private==0)
		luaL_argerror(L,1,"alreay public key");
	else{
		BIO* bio = BIO_new(BIO_s_mem());
		if(i2d_PUBKEY_bio(bio,pkey)){
			EVP_PKEY *pub = d2i_PUBKEY_bio(bio,NULL);
			PUSH_OBJECT(pub,"openssl.evp_pkey");
			ret = 1;
		}
		BIO_free(bio);
	}
	return ret;
}

static LUA_FUNCTION(openssl_dh_compute_key)
{
    const char *pub_str;
    size_t pub_len;
    EVP_PKEY *pkey;
    BIGNUM *pub;
    char *data;
    int len;
    int ret = 0;

    pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	pub_str = luaL_checklstring(L,1,&pub_len);
    
    if (!pkey || EVP_PKEY_type(pkey->type) != EVP_PKEY_DH || !pkey->pkey.dh) {
		luaL_argerror(L, 1, "only support DH private key");
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

static LUA_FUNCTION(openssl_sign)
{
    size_t data_len;
	EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
    const char * data = luaL_checklstring(L,2,&data_len);
    int top = lua_gettop(L);

    const EVP_MD *mdtype = NULL;
    if(top>2) {
        if(lua_isstring(L,3)){
            mdtype = EVP_get_digestbyname(lua_tostring(L,3));
		}else if(lua_isuserdata(L,3))
            mdtype = CHECK_OBJECT(3,EVP_MD,"openssl.evp_digest");
        else
			luaL_argerror(L, 3, "must be string for digest alg name, or openssl.evp_digest object,default use 'sha1'");
    }else
        mdtype = EVP_get_digestbyname("sha1");
	if(mdtype){
		int ret = 0;
		EVP_MD_CTX md_ctx;
		unsigned int siglen = EVP_PKEY_size(pkey);
		unsigned char *sigbuf = malloc(siglen + 1);

		EVP_SignInit(&md_ctx, mdtype);
		EVP_SignUpdate(&md_ctx, data, data_len);
		if (EVP_SignFinal (&md_ctx, sigbuf, &siglen, pkey)) {
			lua_pushlstring(L,(char *)sigbuf, siglen);
			ret = 1;
		}
		free(sigbuf);
		EVP_MD_CTX_cleanup(&md_ctx);
		return ret;
	}else
		luaL_argerror(L, 3, "Not support digest alg");

	return 0;
}

static LUA_FUNCTION(openssl_verify)
{
    size_t data_len, signature_len;
    EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
	const char* data = luaL_checklstring(L,2, &data_len);
    const char* signature = luaL_checklstring(L,3, &signature_len);
    
	const EVP_MD *mdtype = NULL;
    int top = lua_gettop(L);
	if(top>3) {
		if(lua_isstring(L,4))
			mdtype = EVP_get_digestbyname(lua_tostring(L,4));
		else if(lua_isuserdata(L,4))
			mdtype = CHECK_OBJECT(4,EVP_MD,"openssl.evp_digest");
		else
			luaL_error(L, "#4 must be nil, string, or openssl.evp_digest object");
	}else
		mdtype = EVP_get_digestbyname("sha1");
	if(mdtype){
		int result;
		EVP_MD_CTX     md_ctx;

		EVP_VerifyInit   (&md_ctx, mdtype);
		EVP_VerifyUpdate (&md_ctx, data, data_len);
		result = EVP_VerifyFinal (&md_ctx, (unsigned char *)signature, signature_len, pkey);
		EVP_MD_CTX_cleanup(&md_ctx);
		lua_pushboolean(L,result);

		return 1;
	}else
		luaL_argerror(L, 4, "Not support digest alg");

	return 0;
}

static LUA_FUNCTION(openssl_seal)
{
	size_t data_len;
	const char *data = NULL;
	int nkeys = 0;
	const EVP_CIPHER *cipher = NULL;
	int top = lua_gettop(L);

	if(lua_istable(L,1))
	{
		nkeys = lua_objlen(L,1);
		if (!nkeys) {
			luaL_argerror(L, 1, "empty array");
		}
	}else if(auxiliar_isclass(L, "openssl.evp_pkey", 1)){
		nkeys = 1;
	}else
		luaL_argerror(L, 1, "must be openssl.evp_pkey or unemtpy table");

	data = luaL_checklstring(L,2, &data_len);

	if(top>2) {
		if(lua_isstring(L,3))
			cipher = EVP_get_cipherbyname(lua_tostring(L,3));
		else if(lua_isuserdata(L,3))
			cipher = CHECK_OBJECT(3,EVP_CIPHER,"openssl.evp_cipher");
		else
			luaL_argerror(L, 3, "only accept string, or openssl.evp_cipher object");
	}else
		cipher = EVP_get_cipherbyname("rc4");

	if(cipher){
		EVP_CIPHER_CTX ctx;
		int ret = 0;
		EVP_PKEY **pkeys;
		unsigned char **eks;
		int *eksl;
		int i;
		int len1, len2;
		unsigned char *buf;

		pkeys = malloc(nkeys*sizeof(*pkeys));
		eksl = malloc(nkeys*sizeof(*eksl));
		eks = malloc(nkeys*sizeof(*eks));

		memset(eks, 0, sizeof(*eks) * nkeys);

		/* get the public keys we are using to seal this data */
		if(lua_istable(L,1)){
			for(i=0; i<nkeys; i++) {
				lua_rawgeti(L,1,i+1);

				pkeys[i] =  CHECK_OBJECT(-1,EVP_PKEY, "openssl.evp_pkey");
				if (pkeys[i] == NULL) {
					luaL_argerror(L, 1, "table with gap");
				}
				eksl[i] = EVP_PKEY_size(pkeys[i]);
				eks[i] = malloc(eksl[i]);

				lua_pop(L,1);
			}
		}else{
			pkeys[0] = CHECK_OBJECT(1,EVP_PKEY, "openssl.evp_pkey");
			eksl[0] = EVP_PKEY_size(pkeys[0]);
			eks[0] = malloc(eksl[0]);
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
			lua_pushlstring(L,(const char*)buf,len1 + len2);

			if(lua_istable(L,1)){
				lua_newtable(L);
				for (i=0; i<nkeys; i++) {
					lua_pushlstring(L, (const char*)eks[i], eksl[i]);
					free(eks[i]);
					lua_rawseti(L,-2, i+1);
				}
			}else{
				lua_pushlstring(L, (const char*)eks[0], eksl[0]);
				free(eks[0]);
			}

			ret = 2;
		}

		free(buf);
		free(eks);
		free(eksl);
		free(pkeys);
		return ret;
	}else
		luaL_argerror(L, 3, "Not support cipher alg");
	return 0;
}

static LUA_FUNCTION(openssl_open)
{
	EVP_PKEY *pkey =  CHECK_OBJECT(1,EVP_PKEY, "openssl.evp_pkey");
	size_t data_len, ekey_len;
	const char * data = luaL_checklstring(L, 2, &data_len);
	const char * ekey = luaL_checklstring(L, 3, &ekey_len);
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
	}else
		cipher = EVP_get_cipherbyname("rc4");
	if(cipher){
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

		lua_pushlstring(L, (const char*)buf, len1 + len2);
		free(buf);
		return 1;
	}else
		luaL_argerror(L, 4, "Not support cipher alg");
	return 0;
}

static luaL_Reg pkey_funcs[] = {
	{"is_private",		openssl_pkey_is_private},
	{"get_public",		openssl_pkey_get_public},

	{"export",			openssl_pkey_export},
	{"parse",			openssl_pkey_parse},
	{"bits",			openssl_pkey_bits},

	{"encrypt",			openssl_pkey_encrypt},
	{"decrypt",			openssl_pkey_decrypt},
	{"sign",			openssl_sign},
	{"verify",			openssl_verify},

	{"seal",		openssl_seal},
	{"open",		openssl_open},

	{"compute_key",		openssl_dh_compute_key},
	
	{"__gc",			openssl_pkey_free},
	{"__tostring",		auxiliar_tostring},

	{NULL,			NULL},
};

static const luaL_Reg R[] =
{
	{"read",		openssl_pkey_read},
	{"new",			openssl_pkey_new},

	{"seal",		openssl_seal},
	{"open",		openssl_open},

	{"get_public",		openssl_pkey_get_public},
	{"is_private",		openssl_pkey_is_private},
	{"export",			openssl_pkey_export},
	{"parse",			openssl_pkey_parse},
	{"bits",			openssl_pkey_bits},

	{"encrypt",			openssl_pkey_encrypt},
	{"decrypt",			openssl_pkey_decrypt},
	{"sign",			openssl_sign},
	{"verify",			openssl_verify},

	{"compute_key",		openssl_dh_compute_key},

	{NULL,	NULL}
};

LUALIB_API int luaopen_pkey(lua_State *L)
{
	auxiliar_newclass(L,"openssl.evp_pkey", pkey_funcs);

	luaL_newmetatable(L,MYTYPE);
	lua_setglobal(L,MYNAME);
	luaL_register(L,MYNAME,R);
	lua_pushvalue(L, -1);
	lua_setmetatable(L, -2);
	lua_pushliteral(L,"version");			/** version */
	lua_pushliteral(L,MYVERSION);
	lua_settable(L,-3);
	lua_pushliteral(L,"__index");
	lua_pushvalue(L,-2);
	lua_settable(L,-3);
	return 1;
}


