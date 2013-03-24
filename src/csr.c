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
* X509 certificate sign request routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

static int openssl_csr_tostring(lua_State*L);
static int openssl_csr_free(lua_State*L);
static int openssl_csr_get_public(lua_State*L);


LUA_FUNCTION(openssl_csr_parse);
LUA_FUNCTION(openssl_csr_export);
LUA_FUNCTION(openssl_csr_sign);

static luaL_reg csr_cfuns[] = {
    {"export",			openssl_csr_export	},
    {"parse",			openssl_csr_parse	},
    {"sign",			openssl_csr_sign	},
    {"get_public",		openssl_csr_get_public	},

    {"__tostring",		openssl_csr_tostring	},
    {"__gc",			openssl_csr_free	},

    {NULL,				NULL	}
};







/* {{{ x509 CSR functions */

/* {{{ openssl_make_REQ */
static int openssl_make_REQ(lua_State*L,
                            X509_REQ * csr,
                            EVP_PKEY *pkey,
                            int dn,
                            int attribs,
                            int extensions)
{
    /* setup the version number: version 1 */
    if (X509_REQ_set_version(csr, 0L)) {
        X509_NAME * subj;

        subj = X509_REQ_get_subject_name(csr);
        /* apply values from the dn table */
        lo_lt2name(L,subj,dn);

        if (attribs) {
            lo_lt2attrs(L, &csr->req_info->attributes, attribs);
        }

        if(extensions) {
            /* Check syntax of file */
            X509V3_CTX ctx;
            STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
            X509V3_set_ctx_test(&ctx);
            lo_lt2extensions(L,exts,&ctx,extensions);
            X509_REQ_add_extensions(csr, exts);
            sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
        }
    }

    return X509_REQ_set_pubkey(csr, pkey);
}

/* }}} */

/* {{{ openssl.csr_read(string data)->openssl.x509_req */


LUA_FUNCTION(openssl_csr_read)
{
    X509_REQ * csr = NULL;
    BIO * in = NULL;
    size_t dlen;
    const char*data;

    data = luaL_checklstring(L,1,&dlen);

    in = BIO_new_mem_buf((void*)data, dlen);
    if (in == NULL) {
        return 0;
    }
    csr = PEM_read_bio_X509_REQ(in, NULL,NULL,NULL);
    if(!csr)
    {
        BIO_reset(in);
        csr = d2i_X509_REQ_bio(in,NULL);
    }
    BIO_free(in);

    if(csr)
    {
        PUSH_OBJECT(csr,"openssl.x509_req");
        return 1;
    }

    return 0;
}
/* }}} */

/* {{{ proto string openssl_csr_export(resource csr [, boolean pem [,bool notext=true]])
   Exports a CSR to a var */
LUA_FUNCTION(openssl_csr_export)
{
    X509_REQ * csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    int pem, notext;
    BIO * bio_out;
    int top = lua_gettop(L);

    pem = lua_gettop(L)>1 ? lua_toboolean(L,2) : 1;
    notext = (pem && top>2) ? lua_toboolean(L,3) : 1;

    bio_out = BIO_new(BIO_s_mem());
    if(pem)
    {
        if (!notext) {
            X509_REQ_print(bio_out, csr);
        }

        if (PEM_write_bio_X509_REQ(bio_out, csr)) {
            BUF_MEM *bio_buf;

            BIO_get_mem_ptr(bio_out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
        {
            lua_pushnil(L);
        }
    } else
    {
        if(i2d_X509_REQ_bio(bio_out, csr)) {
            BUF_MEM *bio_buf;

            BIO_get_mem_ptr(bio_out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
        {
            lua_pushnil(L);
        }
    }
    BIO_free(bio_out);
    return 1;
}
/* }}} */

int openssl_conf_load_idx(lua_State*L, int idx);
/* {{{ proto resource openssl_csr_sign(obj csr, obj x509, obj priv_key [,table args = {serialNumber=...,num_days=...,...}][,string group])
   Signs a cert with another CERT */
LUA_FUNCTION(openssl_csr_sign)
{
    X509 * cert = NULL, *new_cert = NULL;
    X509_REQ * csr;
    BIGNUM *bn = NULL;
    const EVP_MD* md = NULL;
    EVP_PKEY * key = NULL, *priv_key = NULL;
    int i;
    int ret = 0;
    int dn, digest, num_days,version,extension;
    const char* group;

    dn = digest = extension = 0;
    version = 2;
    num_days = 365;

    csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    cert = lua_isnil(L,2) ? NULL: CHECK_OBJECT(2,X509,"openssl.x509");
    priv_key = CHECK_OBJECT(3,EVP_PKEY,"openssl.evp_pkey");
    luaL_checktype(L,4,LUA_TTABLE);
    group = luaL_optstring(L, 5, NULL);

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
        lo_lt2extensions(L,exts,&ctx,extension);
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
/* }}} */

/* {{{openssl.csr_new(openssl.evp_pkey pkey, table dn, [ arg = {[, table extraattribs, [table config [,string md|openssl.evp_digest md]] }]  ) = >openssl.x509_req
   Generates CSR with gived private key, dn, and extraattribs */
LUA_FUNCTION(openssl_csr_new)
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
/* }}} */

/* {{{ csr.parse(openssl.x509_req csr, boolean shortname)=>table
   Returns the table that contains all infomration about x509_req */
LUA_FUNCTION(openssl_csr_parse)
{
    X509_REQ * csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    int  shortnames = lua_gettop(L)==1?1:lua_toboolean(L,2);

    X509_NAME * subject = X509_REQ_get_subject_name(csr);
    EVP_PKEY* pubkey=X509_REQ_get_pubkey(csr);
    STACK_OF(X509_EXTENSION) *exts  = X509_REQ_get_extensions(csr);
    STACK_OF(X509_ATTRIBUTE) *attrs = csr->req_info->attributes;
    BIO* out = BIO_new(BIO_s_mem());
    char *name = NULL;

    lua_newtable(L);
    add_assoc_int(L,"version",ASN1_INTEGER_get(csr->req_info->version));
    add_assoc_name_entry(L, "subject", subject, shortnames);


    {
        X509_REQ_INFO* ri=csr->req_info;
        lua_newtable(L);


        ADD_ASSOC_ASN1(ASN1_OBJECT, out,ri->pubkey->algor->algorithm, "algorithm");

        /*
        i2a_ASN1_OBJECT(out,ri->pubkey->algor->algorithm);
        ASSOC_BIO("algorithm");
        */

        PUSH_OBJECT(pubkey,"openssl.evp_pkey");
        lua_insert(L,1);
        openssl_pkey_parse(L);
        lua_setfield(L,-2,"pubkey");
        lua_remove(L,1);

        lua_setfield(L,-2,"pubkey");
    }

    if(attrs && X509at_get_attr_count(attrs))
    {
        int i, attr_nid;

        lua_newtable(L);

        for (i=0; i< X509at_get_attr_count(attrs); i++) {
            X509_ATTRIBUTE *attr = X509at_get_attr(attrs,i);
            ASN1_TYPE *av;
#if 0
            {
                char* dat = NULL;
                int i = i2d_X509_ATTRIBUTE(attr,&dat);
                if(i>0) {
                    lua_pushlstring(L,dat,i);
                    OPENSSL_free(dat);
                } else
                    lua_pushnil(L);

                lua_rawseti(L,-2,i+1);

            }
#else
            lua_newtable(L);

            if(attr->single)
            {
                lua_pushinteger(L,attr->value.single->type);
                lua_setfield(L,-2,"type");
                lua_pushlstring(L,(const char *)attr->value.single->value.bit_string->data,attr->value.single->value.bit_string->length);
                lua_setfield(L,-2,"bit_string");
            } else
            {
                attr_nid = OBJ_obj2nid(attr->object);
                if(attr_nid == NID_undef) {
                    ADD_ASSOC_ASN1(ASN1_OBJECT, out,attr->object, "object");
                    name = NULL;
                } else
                    name  = shortnames ? (char*)OBJ_nid2sn(attr_nid) : (char*)OBJ_nid2ln(attr_nid) ;

                if(sk_ASN1_TYPE_num(attr->value.set)) {
                    av = sk_ASN1_TYPE_value(attr->value.set, 0);
                    switch(av->type) {
                    case V_ASN1_BMPSTRING:
                    {
#if OPENSSL_VERSION_NUMBER > 0x10000000L
                        char *value = OPENSSL_uni2asc(av->value.bmpstring->data,av->value.bmpstring->length);
                        add_assoc_string(L, name?name:"bmpstring", value);
                        OPENSSL_free(value);
#else
                        lua_pushlstring(L,(const char*)av->value.bmpstring->data,av->value.bmpstring->length);
                        lua_setfield(L,-2, name?name:"bmpstring");
#endif
                    }
                    break;

                    case V_ASN1_OCTET_STRING:
                        lua_pushlstring(L, (const char *)av->value.octet_string->data, av->value.octet_string->length);
                        lua_setfield(L, -2, name?name:"octet_string");
                        break;

                    case V_ASN1_BIT_STRING:
                        lua_pushlstring(L, (const char *)av->value.bit_string->data, av->value.bit_string->length);
                        lua_setfield(L, -2, name?name:"bit_string");
                        break;

                    default:
                        if(name)
                            lua_pushstring(L,name);
                        else
                            lua_pushfstring(L,"tag:%d",av->type);

                        {
                            unsigned char* dat = NULL;
                            int i = i2d_ASN1_TYPE(av,&dat);
                            if(i>0) {
                                lua_pushlstring(L,(const char *)dat,i);
                                OPENSSL_free(dat);
                            } else
                                lua_pushnil(L);

                        }
                        lua_settable(L,-3);
                        break;
                    }
                }
            }

            lua_rawseti(L,-2,i+1);
#endif
        }
        lua_setfield(L,-2,"attributes");

    }
    add_assoc_x509_extension(L, "extensions", exts, out);
    BIO_free(out);

    return 1;
}
/* }}} */

/* }}} */

static LUA_FUNCTION(openssl_csr_tostring) {
    X509_REQ *csr = CHECK_OBJECT(1,X509_REQ,"openssl.x509_req");
    lua_pushfstring(L,"openssl.x509_req:%p",csr);
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

LUA_FUNCTION(openssl_register_csr) {
    auxiliar_newclass(L,"openssl.x509_req", csr_cfuns);
    return 0;
}
