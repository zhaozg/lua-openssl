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
* x509 routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "sk.h"

void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* exts, BIO* bio)
{
    const char*extname;
    char buf[256];
    int n = exts ? sk_X509_EXTENSION_num(exts) : 0 ;
    int i;

    if( n > 0 )
    {
        lua_newtable(L);

        for (i = 0; i < n; i++) {
            X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts,i);

            if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_undef) {
                extname = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            } else {
                OBJ_obj2txt(buf, sizeof(buf)-1, X509_EXTENSION_get_object(ext), 1);
                extname = buf;
            }
            if (X509V3_EXT_print(bio, ext, 0, 0)) {
                BUF_MEM *mem;
                BIO_get_mem_ptr(bio, &mem);
                lua_pushlstring(L,mem->data, mem->length);
                lua_setfield(L,-2,extname);
            } else {
                ADD_ASSOC_ASN1_STRING(ASN1_OCTET_STRING, bio, X509_EXTENSION_get_data(ext), extname);
            }
            BIO_reset(bio);
        }

        lua_setfield(L,-2,key);
    }
}

/* X509 module for the Lua/OpenSSL binding.
 *
 * The functions in this module can be used to load, parse, export, verify... functions.
 * parse()
 * export()
 * check_private_key()
 * checkpurpose()
 * public_key()
 */


static luaL_Reg x509_funcs[] = {
    {"parse",		openssl_x509_parse},
    {"export",		openssl_x509_export},
    {"check",		openssl_x509_check},
    {"get_public",	openssl_x509_public_key},
    {"__gc",		openssl_x509_free},
    {"__tostring",	openssl_x509_tostring},

    {NULL,			NULL},
};


/* {{{ check_cert */
static int check_cert(X509_STORE *ca, X509 *x, STACK_OF(X509) *untrustedchain, int purpose)
{
    int ret=0;
    X509_STORE_CTX *csc;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        printf("memory allocation -1");
        return 0;
    }
    X509_STORE_CTX_init(csc, ca, x, untrustedchain);
    if(purpose > 0) {
        X509_STORE_CTX_set_purpose(csc, purpose);
    }
    ret = X509_verify_cert(csc);
    X509_STORE_CTX_free(csc);

    return ret;
}
/* }}} */



/* {{{ setup_verify
 * calist is an array containing file and directory names.  create a
 * certificate store and add those certs to it for use in verification.
*/

X509_STORE * setup_verify(STACK_OF(X509)* calist)
{
    X509_STORE *store;
    X509_LOOKUP * dir_lookup, * file_lookup;
    int ndirs = 0, nfiles = 0;
    X509 *x;
    int i;

    store = X509_STORE_new();

    if (store == NULL) {
        return NULL;
    }

    for (i=0; i<sk_X509_num(calist); i++)
    {
        x=sk_X509_value(calist,i);
        X509_STORE_add_cert(store,x);
    }

    if (nfiles == 0) {
        file_lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (file_lookup) {
            X509_LOOKUP_load_file(file_lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }
    if (ndirs == 0) {
        dir_lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (dir_lookup) {
            X509_LOOKUP_add_dir(dir_lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }
    return store;
}
/* }}} */


/*  openssl.x509_read(string val) -> openssl.x509 {{{1

	Read string val into an X509 object and returned, otherwise a nil
	The val can be:
	. it will be interpreted as the cert data
*/
LUA_FUNCTION(openssl_x509_read)
{
    X509 *cert = NULL;
    size_t data_len;
    const char *data = luaL_checklstring(L, 1, &data_len);

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

    if (cert)
    {
        PUSH_OBJECT(cert,"openssl.x509");
        return 1;
    }
    return 0;
}
/* }}} */

/*  openssl.x509_export(openssl.x509 x509 [, boolean pem=true [, boolean notext=true]] ) -> string{{{1

	export an X509 object to var

	x509 object is openssl.x509 object.
	option pem and true
	if outfilename not gived, encoded cert content is return, or save to gived filename.
	if noext not gived or value is true, will not export extend detail.
*/

LUA_FUNCTION(openssl_x509_export)
{
    int pem, notext;
    X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
    int top = lua_gettop(L);
    BIO* bio_out = NULL;

    pem = top > 1 ? lua_toboolean(L, 2) : 1;
    notext = (pem && top>2) ? lua_toboolean(L,3):1;

    bio_out	 = BIO_new(BIO_s_mem());
    if (pem) {
        if (!notext) {
            X509_print(bio_out, cert);
        }

        if (PEM_write_bio_X509(bio_out, cert))  {
            BUF_MEM *bio_buf;
            BIO_get_mem_ptr(bio_out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
            lua_pushnil(L);
    } else
    {
        if(i2d_X509_bio(bio_out, cert)) {
            BUF_MEM *bio_buf;
            BIO_get_mem_ptr(bio_out, &bio_buf);
            lua_pushlstring(L,bio_buf->data, bio_buf->length);
        } else
            lua_pushnil(L);
    }

    BIO_free(bio_out);
    return 1;
}
/* }}} */


/*  openssl.x509_parse(openssl.x509 x509 [,bool shortnames=true]) -> table{{{1
	parse an X509 object and return parsed information as a fields/values table.
*/

LUA_FUNCTION(openssl_x509_parse)
{
    X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
    int useshortnames = lua_isnoneornil(L,2)?1:lua_toboolean(L,2);

    int i;
    char * tmpstr;
    BIO  *bio;

    bio = BIO_new(BIO_s_mem());

    lua_newtable(L);
    if (cert->name) {
        lua_pushstring(L,cert->name);
        lua_setfield(L,-2,"name");
    }

    lua_pushboolean(L,cert->valid);
    lua_setfield(L,-2,"valid");

    add_assoc_name_entry(L, "subject", 		X509_get_subject_name(cert), useshortnames);
    /* hash as used in CA directories to lookup cert by subject name */
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "%08lx", X509_subject_name_hash(cert));
        lua_pushstring(L,buf);
        lua_setfield(L,-2,"hash");
    }

    add_assoc_name_entry(L, "issuer", 		X509_get_issuer_name(cert), useshortnames);

    lua_pushinteger(L,X509_get_version(cert));
    lua_setfield(L,-2,"version");

    ADD_ASSOC_ASN1(ASN1_INTEGER, bio, cert->cert_info->serialNumber, "serialNumber");

    ADD_ASSOC_ASN1_TIME(bio, X509_get_notBefore(cert), "notBefore");
    ADD_ASSOC_ASN1_TIME(bio, X509_get_notAfter(cert), "notAfter");

    tmpstr = (char *)X509_alias_get0(cert, NULL);
    if (tmpstr) {
        add_assoc_string(L, "alias",tmpstr);
    }
    /*
    	add_assoc_long(return_value, "signaturetypeLONG", X509_get_signature_type(cert));
    	add_assoc_string(return_value, "signaturetype", OBJ_nid2sn(X509_get_signature_type(cert)), 1);
    	add_assoc_string(return_value, "signaturetypeLN", OBJ_nid2ln(X509_get_signature_type(cert)), 1);
    */

    lua_newtable(L);
    /* NOTE: the purposes are added as integer keys - the keys match up to the X509_PURPOSE_SSL_XXX defines
       in x509v3.h */
    for (i = 0; i < 2*X509_PURPOSE_get_count(); i++) {
        int id, ca, set;
        X509_PURPOSE * purp;

        ca = i%2;
        purp = X509_PURPOSE_get0(i/2);
        id = X509_PURPOSE_get_id(purp);
        set = X509_check_purpose(cert, id, ca);
        if(set)
        {
           char * pname = useshortnames ? X509_PURPOSE_get0_sname(purp) : X509_PURPOSE_get0_name(purp);
           if(ca){
               lua_pushfstring(L,"%s CA",pname);
           }else
               lua_pushstring(L,pname);

            lua_pushboolean(L,1);
            lua_settable(L,-3);
        }
        /* NOTE: if purpset > 1 then it's a warning - we should mention it ? */
    }
    lua_setfield(L,-2,"purposes");

    add_assoc_x509_extension(L, "extensions", cert->cert_info->extensions, bio);
    lua_pushboolean(L,X509_check_ca(cert));
    lua_setfield(L, -2, "ca");

    BIO_free(bio);
    return 1;
}
/* }}} */


static int get_cert_purpose(const char* purpose) {
    if(strcasecmp(purpose,"ssl_client")==0)
        return X509_PURPOSE_SSL_CLIENT;
    else if(strcasecmp(purpose,"ssl_server")==0)
        return X509_PURPOSE_SSL_SERVER;
    else if(strcasecmp(purpose,"ns_ssl_server")==0)
        return X509_PURPOSE_NS_SSL_SERVER;
    else if(strcasecmp(purpose,"smime_sign")==0)
        return X509_PURPOSE_SMIME_SIGN;
    else if(strcasecmp(purpose,"smime_encrypt")==0)
        return X509_PURPOSE_SMIME_ENCRYPT;
    else if(strcasecmp(purpose,"crl_sign")==0)
        return X509_PURPOSE_CRL_SIGN;
    else if(strcasecmp(purpose,"any")==0)
        return X509_PURPOSE_ANY;
    else if(strcasecmp(purpose,"ocsp_helper")==0)
        return X509_PURPOSE_OCSP_HELPER;
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    else if(strcasecmp(purpose,"timestamp_sign")==0)
        return X509_PURPOSE_TIMESTAMP_SIGN;
#endif

    return 0;
}

/*  openssl.check(openssl.x509 x509, (openssl.evp_pkey pkey)|(
	openssl.stack_of_x509 ca=nil,openssl.stack_of_x509 untrustechains=nil,string purpose=nil])  -> boolean{{{1
    if #2 is EVP_PKEY, check an X509 object whether match with an EVP_PKEY, and return match result.
    if #2 is a stack_of_x509, that include all trusted ca certificates
    if #3 is a stack_of_x509, that include all certificate chains
    if #4 is string, that is purpose
*/

LUA_FUNCTION(openssl_x509_check)
{
    X509 * cert = CHECK_OBJECT(1,X509,"openssl.x509");
    if (auxiliar_isclass(L, "openssl.evp_pkey", 2)){
	EVP_PKEY * key = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
	lua_pushboolean(L,X509_check_private_key(cert, key));
	return 1;
    }else{
	STACK_OF(X509)* cert_stack = lua_isnoneornil(L,2) ? 
		NULL : CHECK_OBJECT(2,STACK_OF(X509),"openssl.stack_of_x509");
	STACK_OF(X509)* untrustedchain = lua_isnoneornil(L,3) ? 
		NULL : CHECK_OBJECT(3,STACK_OF(X509),"openssl.stack_of_x509");
	const char* spurpose = luaL_optstring(L,4, NULL);
	int purpose = spurpose==NULL?0:get_cert_purpose(spurpose);

	X509_STORE * cainfo = setup_verify(cert_stack);
	int ret = check_cert(cainfo, cert, untrustedchain, purpose);
	if (ret != 0 && ret != 1) {
		lua_pushnil(L);
		lua_pushinteger(L,ret);
		ret = 2;
	} else {
		lua_pushboolean(L,ret);
		ret = 1;
	}
	X509_STORE_free(cainfo);
	return ret;
    }
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

int openssl_register_x509(lua_State*L) {
    auxiliar_newclass(L,"openssl.x509", x509_funcs);
    return 0;
}

IMP_LUA_SK(X509, x509)

static STACK_OF(X509) * load_all_certs_from_file(const char *certfile)
{
    STACK_OF(X509_INFO) *sk=NULL;
    STACK_OF(X509) *stack=NULL, *ret=NULL;
    BIO *in=NULL;
    X509_INFO *xi;

    if((stack = sk_X509_new_null())==NULL) {
        printf("memory allocation -1");
        goto end;
    }

    if((in=BIO_new_file(certfile, "r"))==NULL) {
        printf("error opening the file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if((sk=PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))==NULL) {
        printf("error reading the file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
        xi=sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack,xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }
    if(!sk_X509_num(stack)) {
        printf("no certificates in file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }
    ret=stack;
end:
    BIO_free(in);
    sk_X509_INFO_free(sk);

    return ret;
}


int openssl_sk_x509_read(lua_State*L) {
    const char* file = luaL_checkstring(L,1);
    STACK_OF(X509) * certs = load_all_certs_from_file(file);
    if (certs) {
        PUSH_OBJECT(certs, "openssl.stack_of_x509");
    } else
        lua_pushnil(L);
    return 1;
}

