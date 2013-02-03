/*=========================================================================*\
* x509 name routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"


static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method, int ext_nid,
    int crit, void *ext_struc)
{
    unsigned char *ext_der;
    int ext_len = 0;
    ASN1_OCTET_STRING *ext_oct;
    X509_EXTENSION *ext;
    /* Convert internal representation to DER */
    if (method->it)
    {
        ext_der = NULL;
        ext_len = ASN1_item_i2d(ext_struc, &ext_der, ASN1_ITEM_ptr(method->it));
        if (ext_len < 0) goto merr;
    }
    else
    {
        unsigned char *p;
        ext_len = method->i2d(ext_struc, NULL);
        if((ext_der = OPENSSL_malloc(ext_len))==NULL) goto merr;
        p = ext_der;
        method->i2d(ext_struc, &p);
    }
    if ((ext_oct = M_ASN1_OCTET_STRING_new())==NULL) goto merr;
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;

    ext = X509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
    if (!ext) goto merr;
    M_ASN1_OCTET_STRING_free(ext_oct);

    return ext;
merr:
    X509V3err(X509V3_F_DO_EXT_I2D,ERR_R_MALLOC_FAILURE);
    return NULL;

}

/* Check the extension string for critical flag */
static int v3_check_critical(char **value)
{
    char *p = *value;
    if ((strlen(p) < 9) || strncmp(p, "critical,", 9)) return 0;
    p+=9;
    while(isspace((unsigned char)*p)) p++;
    *value = p;
    return 1;
}

static int v3_check_generic(char **value)
{
    int gen_type = 0;
    char *p = *value;
    if ((strlen(p) >= 4) && !strncmp(p, "DER:", 4))
    {
        p+=4;
        gen_type = 1;
    }
    else if ((strlen(p) >= 5) && !strncmp(p, "ASN1:", 5))
    {
        p+=5;
        gen_type = 2;
    }
    else
        return 0;

    while (isspace((unsigned char)*p)) p++;
    *value = p;
    return gen_type;
}


static unsigned char *generic_asn1(char *value, X509V3_CTX *ctx, long *ext_len)
{
    ASN1_TYPE *typ;
    unsigned char *ext_der = NULL;
    typ = ASN1_generate_v3(value, ctx);
    if (typ == NULL)
        return NULL;
    *ext_len = i2d_ASN1_TYPE(typ, &ext_der);
    ASN1_TYPE_free(typ);
    return ext_der;
}

/* Create a generic extension: for now just handle DER type */
static X509_EXTENSION *v3_generic_extension(ASN1_OBJECT *obj, char *value,
    int crit, int gen_type,
    X509V3_CTX *ctx)
{
    unsigned char *ext_der=NULL;
    long ext_len = 0;
    ASN1_OCTET_STRING *oct=NULL;
    X509_EXTENSION *extension=NULL;

    if (gen_type == 1)
        ext_der = string_to_hex(value, &ext_len);
    else if (gen_type == 2)
        ext_der = generic_asn1(value, ctx, &ext_len);

    if (ext_der == NULL)
    {
        X509V3err(X509V3_F_V3_GENERIC_EXTENSION,X509V3_R_EXTENSION_VALUE_ERROR);
        ERR_add_error_data(2, "value=", value);
        goto err;
    }

    if ((oct = M_ASN1_OCTET_STRING_new())==NULL)
    {
        X509V3err(X509V3_F_V3_GENERIC_EXTENSION,ERR_R_MALLOC_FAILURE);
        goto err;
    }

    oct->data = ext_der;
    oct->length = ext_len;
    ext_der = NULL;

    extension = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, oct);

err:
    ASN1_OBJECT_free(obj);
    M_ASN1_OCTET_STRING_free(oct);
    if(ext_der) OPENSSL_free(ext_der);
    return extension;
}



static X509_EXTENSION *do_ext_nconf(X509V3_CTX *ctx, int ext_nid,
    int crit, char *value)
{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    const X509V3_EXT_METHOD *method;
#else
    X509V3_EXT_METHOD *method;
#endif
    X509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    void *ext_struc;
    if (ext_nid == NID_undef)
    {
        X509V3err(X509V3_F_DO_EXT_NCONF,X509V3_R_UNKNOWN_EXTENSION_NAME);
        return NULL;
    }
    if ((method = X509V3_EXT_get_nid(ext_nid))==NULL)
    {
        X509V3err(X509V3_F_DO_EXT_NCONF,X509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    /* Now get internal extension representation based on type */
    if (method->v2i)
    {
        nval = X509V3_parse_list(value);
        if(sk_CONF_VALUE_num(nval) <= 0)
        {
            X509V3err(X509V3_F_DO_EXT_NCONF,X509V3_R_INVALID_EXTENSION_STRING);
            ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=", value);
            return NULL;
        }
        ext_struc = method->v2i(method, ctx, nval);
        sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
        if(!ext_struc) return NULL;
    }
    else if(method->s2i)
    {
        if((ext_struc = method->s2i(method, ctx, value))==NULL) return NULL;
    }
    else if(method->r2i)
    {
        if(!ctx->db || !ctx->db_meth)
        {
            X509V3err(X509V3_F_DO_EXT_NCONF,X509V3_R_NO_CONFIG_DATABASE);
            return NULL;
        }
        if((ext_struc = method->r2i(method, ctx, value))==NULL) return NULL;
    }
    else
    {
        X509V3err(X509V3_F_DO_EXT_NCONF,X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
        ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
        return NULL;
    }

    ext  = do_ext_i2d(method, ext_nid, crit, ext_struc);
    if(method->it) ASN1_item_free(ext_struc, ASN1_ITEM_ptr(method->it));
    else method->ext_free(ext_struc);
    return ext;
}

int lo_lt2extensions(lua_State*L,
    STACK_OF(X509_EXTENSION) *exts,
    X509V3_CTX* ctx,
    int extensions)
{
    lua_pushnil(L);  /* first key */
    while (lua_next(L, extensions) != 0) {
        /* uses 'key' (at index -2) and 'value' (at index -1) */
        const char * key = lua_tostring(L,-2);
        char* val = (char*)lua_tostring(L,-1);
        int nid = OBJ_txt2nid(key);

        if (nid != NID_undef) {
            int crit = v3_check_critical(&val);
            int ext_type = v3_check_generic(&val);
            X509_EXTENSION *ret;
            ASN1_OBJECT * obj = OBJ_nid2obj(nid);
            if (!obj)
            {
                X509V3err(X509V3_F_V3_GENERIC_EXTENSION,X509V3_R_EXTENSION_NAME_ERROR);
                luaL_error(L, "OBJ_nid2obj(%s) failed");
            }

            if (ext_type)
                ret = v3_generic_extension(obj, val, crit, ext_type, ctx);
            else
                ret = do_ext_nconf(ctx, nid, crit, val);
            if (!ret)
            {
                X509V3err(X509V3_F_X509V3_EXT_NCONF,X509V3_R_ERROR_IN_EXTENSION);
                ERR_add_error_data(4,"name=", key, ", value=", val);
            }
            else
                X509v3_add_ext(&exts, ret, -1);
        } else {
            luaL_error(L, "extensions: %s is not a recognized name", key);
        }

        /* removes 'value'; keeps 'key' for next iteration */
        lua_pop(L, 1);
    }
    return 0;
}