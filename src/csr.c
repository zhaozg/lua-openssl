/*=========================================================================*\
* csr.c
* X509 certificate sign request routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

#define MYNAME		"csr"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"openssl.csr"

static int openssl_make_REQ(lua_State*L,
                            X509_REQ * csr,
                            EVP_PKEY *pkey,
                            int dn,
                            int attribs,
                            int extensions)
{
    /* setup the version number: version 1 */
    if (X509_REQ_set_version(csr, 0L)) 
	{
        X509_NAME * subj = X509_REQ_get_subject_name(csr);
        /* apply values from the dn table */
        XNAME_from_ltable(L,subj,dn);

        if (attribs) {
            XATTRS_from_ltable(L, &csr->req_info->attributes, attribs);
        }

        if(extensions) {
            /* Check syntax of file */
            X509V3_CTX ctx;
            STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
            X509V3_set_ctx_test(&ctx);
            XEXTS_from_ltable(L,exts,&ctx,extensions);
            X509_REQ_add_extensions(csr, exts);
            sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
        }
    }

    return X509_REQ_set_pubkey(csr, pkey);
}

static LUA_FUNCTION(openssl_csr_read)
{
    BIO * in = load_bio_object(L, 1);
	int fmt = luaL_checkoption(L, 2, "auto", format);
	X509_REQ * csr = NULL;
	
	if( fmt==FORMAT_AUTO || fmt==FORMAT_PEM){
		PEM_read_bio_X509_REQ(in, NULL,NULL,NULL);
		BIO_reset(in);
	}
	if ((fmt==FORMAT_AUTO && in==NULL) || fmt==FORMAT_DER)
    {
        csr = d2i_X509_REQ_bio(in,NULL);
		BIO_reset(in);
    }

    BIO_free(in);

    if(csr)
    {
        PUSH_OBJECT(csr,"openssl.x509_req");
        return 1;
    }else
		luaL_error(L,"read openssl.x509_req content fail");

    return 0;
}

static LUA_FUNCTION(openssl_csr_export)
{
    X509_REQ * csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
	int fmt = luaL_checkoption(L, 2, "auto", format); 
	int notext = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L,3);

    BIO *out  = BIO_new(BIO_s_mem());
    if(fmt==FORMAT_PEM)
    {
        if (!notext) {
            X509_REQ_print(out, csr);
        }

        if (PEM_write_bio_X509_REQ(out, csr)) {
            BUF_MEM *bio_buf;

            BIO_get_mem_ptr(out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
        {
            lua_pushnil(L);
        }
    } else
    {
        if(i2d_X509_REQ_bio(out, csr)) {
            BUF_MEM *bio_buf;

            BIO_get_mem_ptr(out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
        {
            lua_pushnil(L);
        }
    }
    BIO_free(out);
    return 1;
}

/* TODO:clean */
static LUA_FUNCTION(openssl_csr_sign)
{
    X509 * cert = NULL, *new_cert = NULL;
    X509_REQ * csr;
    BIGNUM *bn = NULL;
    const EVP_MD* md = NULL;
    EVP_PKEY * key = NULL, *priv_key = NULL;
    int i;
    int ret = 0;
    int digest, num_days,version,extension;
 
    digest = extension = 0;
    version = 2;
    num_days = 365;

    csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    cert = lua_isnil(L,2) ? NULL: CHECK_OBJECT(2,X509,"openssl.x509");
    priv_key = CHECK_OBJECT(3,EVP_PKEY,"openssl.evp_pkey");
    luaL_checktype(L,4,LUA_TTABLE);

    {
	    lua_getfield(L, 4, "serialNumber");
	    if(lua_isnil(L,-1))
		    luaL_error(L,"paramater #4 as table must have serialNumber key and value must be string or number type");

	    BN_dec2bn(&bn,lua_tostring(L,-1));
	    BN_set_negative(bn,0);
	    lua_pop(L, 1);

	    lua_getfield(L, 4, "digest");
	    if(lua_isstring(L, -1) || auxiliar_isclass(L,"openssl.evp_digest", -1))
	    {
		    digest = lua_gettop(L);
	    } else if(!lua_isnoneornil(L, -1))
		    luaL_error(L, "paramater #4 if have digest key, it's value must be string type or openssl.evp_digest object");

	    lua_getfield(L,4, "num_days");
	    if(!lua_isnoneornil(L,-1))
		    num_days = luaL_checkint(L, -1);

	    lua_getfield(L, 4,"version");
	    if (lua_isnil(L,-1)) {
		    version = 2;
	    } else {
		    version = lua_tointeger(L,-1);
	    }
	    lua_pop(L,1);

	    lua_getfield(L, 4, "extensions");
	    if ( !lua_isnil (L, -1) ) {
		    luaL_checktype(L,-1,LUA_TTABLE);
		    extension = lua_gettop(L);
	    }
	    else 
		    lua_pop(L,1);
    }

    if (cert && !X509_check_private_key(cert, priv_key)) {
        luaL_error(L,"private key does not correspond to signing cert");
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
    /* 1) */
    new_cert = X509_new();
    if (new_cert == NULL) {
        luaL_error(L, "No memory");
        goto cleanup;
    }

    /* Version 3 cert */
    if (!X509_set_version(new_cert, version))
	    goto cleanup;

    /* 3) */
    X509_set_serialNumber(new_cert, BN_to_ASN1_INTEGER(bn,X509_get_serialNumber(new_cert)));
    X509_set_subject_name(new_cert, X509_REQ_get_subject_name(csr));

    /* 4) */
    if (cert == NULL) {
        cert = new_cert;
    }
    if (!X509_set_issuer_name(new_cert, X509_get_subject_name(cert))) {
        goto cleanup;
    }

    /* 5 */
    X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
#if OPENSSL_VERSION_NUMBER > 0x10000002L
    if (!X509_time_adj_ex(X509_get_notAfter(new_cert), num_days, 0, NULL))
        goto cleanup;
#else
    X509_gmtime_adj(X509_get_notAfter(new_cert), (long)60*60*24*num_days);
#endif

    /* 6 */
    if (!X509_set_pubkey(new_cert, key)) {
        goto cleanup;
    }

    new_cert->cert_info->extensions = X509_REQ_get_extensions(csr);
    if(extension)
    {
        X509V3_CTX ctx;
        STACK_OF(X509_EXTENSION)* exts = new_cert->cert_info->extensions;
        if(exts==NULL)
            exts = sk_X509_EXTENSION_new_null();

        X509V3_set_ctx_test(&ctx);
        XEXTS_from_ltable(L,exts,&ctx,extension);
        new_cert->cert_info->extensions = exts;
    }       

    /* Now sign it */
    if(digest)
    {
	    if (lua_isuserdata(L,digest)) {
		    md = CHECK_OBJECT(digest,EVP_MD,"openssl.evp_digest");
	    }
	    else if(lua_isstring(L,digest)) {
		    md = EVP_get_digestbyname(luaL_checkstring(L,digest));
		    if(!md) luaL_error(L,"EVP_get_digestbyname(%s) failed",luaL_checkstring(L,digest));
	    }
    }
    if(!md)
            md = EVP_get_digestbyname("sha1WithRSAEncryption");

    if (!X509_sign(new_cert, priv_key, md)) {
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

    return ret;
}
/* TODO:clean */
static LUA_FUNCTION(openssl_csr_new)
{
    X509_REQ *csr = NULL;

    EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
    int dn, attribs, extensions , digest;

    luaL_checktype(L, 2, LUA_TTABLE);
    dn = 2;
    attribs = extensions  = digest = 0;
    if(!lua_isnoneornil(L,3))
    {
	    luaL_checktype(L, 3, LUA_TTABLE);
	    lua_getfield(L,3, "digest");
	    if(lua_isstring(L, -1) || auxiliar_isclass(L,"openssl.evp_digest", -1))
	    {
		    digest = lua_gettop(L);
	    } else if(!lua_isnoneornil(L, -1))
		    luaL_error(L, "paramater #3 if have digest key, it's value must be string type or openssl.evp_digest object");

	    lua_getfield(L,3,"attribs");
	    if (lua_isnil(L,-1)) {
		    lua_pop(L,1);
	    } else {
		    luaL_checktype(L, -1, LUA_TTABLE);
		    attribs = lua_gettop(L);
	    }

	    lua_getfield(L,3, "extensions");
	    if (lua_isnil(L, -1)) {;
		    lua_pop(L,1);
	    } else {
		    luaL_checktype(L, -1, LUA_TTABLE);
		    extensions = lua_gettop(L);
	    }
    }
    csr = X509_REQ_new();
    if(!csr) luaL_error(L,"out of memory!");

    if (openssl_make_REQ(L, csr, pkey, dn, attribs, extensions)) {
        const EVP_MD* md = NULL;
		if(digest) {
			if (lua_isuserdata(L,digest)) {
				md = CHECK_OBJECT(digest,EVP_MD,"openssl.evp_digest");
			}else{
				md = EVP_get_digestbyname(luaL_checkstring(L,digest));
			} 
		}
		else
			md = EVP_get_digestbyname("sha1WithRSAEncryption");

		if(!md) 
			luaL_error(L,"get_digest with(%s) failed",lua_tostring(L,digest));

        if (X509_REQ_sign(csr, pkey, md)) {
            PUSH_OBJECT(csr,"openssl.x509_req");
        } else {
            luaL_error(L,"Error signing cert request");
        }
    }else{
		luaL_error(L,"Error make cert request");
	}

    return 1;
}

static LUA_FUNCTION(openssl_csr_parse)
{
    X509_REQ * csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    int  shortnames = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L,2);

    X509_NAME * subject = X509_REQ_get_subject_name(csr);
    STACK_OF(X509_EXTENSION) *exts  = X509_REQ_get_extensions(csr);
	

    lua_newtable(L);
    
	AUXILIAR_SETOBJECT(L, csr->signature, "openssl.asn1_string",-1,"signature");
	AUXILIAR_SETOBJECT(L, csr->sig_alg, "openssl.x509_algor",-1,"sig_alg");

	lua_newtable(L);
	AUXILIAR_SET(L,-1,"version",ASN1_INTEGER_get(csr->req_info->version),integer);
    add_assoc_name_entry(L, "subject", subject, shortnames);
	add_assoc_x509_extension(L, "extensions", exts);

	{
		X509_REQ_INFO* ri=csr->req_info;
		STACK_OF(X509_ATTRIBUTE) *attrs = ri->attributes;
		lua_newtable(L);

		AUXILIAR_SETOBJECT(L, ri->pubkey->algor->algorithm, "openssl.asn1_object", -1, "algorithm");
		AUXILIAR_SETOBJECT(L, X509_REQ_get_pubkey(csr), "openssl.evp_pkey",-1,"pubkey");
		lua_setfield(L,-2,"pubkey");

		if(attrs && X509at_get_attr_count(attrs))
		{
			int i;

			lua_newtable(L);

			for (i=0; i< X509at_get_attr_count(attrs); i++) {
				X509_ATTRIBUTE *attr = X509at_get_attr(attrs,i);
				lua_newtable(L);
				AUXILIAR_SET(L,-1,"single",attr->single,boolean);

				if(attr->single)
				{
					AUXILIAR_SETOBJECT(L, attr->object, "openssl.asn1_object", -1, "object");
					PUSH_OBJECT(attr->value.single,"openssl.asn1_type");
				} else
				{
					AUXILIAR_SETOBJECT(L, attr->object, "openssl.asn1_object", -1, "object");

					if(sk_ASN1_TYPE_num(attr->value.set)) {
						int j;
						lua_newtable(L);
						for(j=0;j<sk_ASN1_TYPE_num(attr->value.set);j++)
						{
							ASN1_TYPE *av = sk_ASN1_TYPE_value(attr->value.set, 0);
							PUSH_OBJECT(av,"openssl.asn1_type");
							lua_rawseti(L,-2, j+1);
						}
						lua_setfield(L, -2, "set");
					}
				}

				lua_rawseti(L,-2,i+1);
			}
			lua_setfield(L,-2,"attributes");
		}
	}

	lua_setfield(L,-2,"req_info");

    return 1;
}

static LUA_FUNCTION(openssl_csr_free) {
    X509_REQ *csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    X509_REQ_free(csr);
    return 0;
}

static LUA_FUNCTION(openssl_csr_get_public) {
    X509_REQ *csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    PUSH_OBJECT(csr->req_info->pubkey,"openssl.evp_pkey");
    return 1;
}

static luaL_reg csr_cfuns[] = {
	{"export",			openssl_csr_export	},
	{"parse",			openssl_csr_parse	},
	{"sign",			openssl_csr_sign	},
	{"get_public",		openssl_csr_get_public	},

	{"__tostring",		auxiliar_tostring	},
	{"__gc",			openssl_csr_free	},

	{NULL,				NULL	}
};


static luaL_reg R[] = {
	{"new",				openssl_csr_new	},
	{"read",			openssl_csr_read	},

	{NULL,		NULL}
};

LUALIB_API int luaopen_csr(lua_State *L)
{
	auxiliar_newclass(L,"openssl.x509_req", csr_cfuns);

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
