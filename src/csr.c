/*=========================================================================*\
* csr.c
* X509 certificate sign request routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

#define MYNAME    "csr"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE      "csr"

static int openssl_make_REQ(lua_State*L,
                            X509_REQ *csr,
                            EVP_PKEY *pkey,
                            int dn,
                            int attribs,
                            int extensions,
                            int utf8)
{
  /* setup the version number: version 1 */
  if (X509_REQ_set_version(csr, 0L))
  {
    X509_NAME * subj = X509_REQ_get_subject_name(csr);
    /* apply values from the dn table */
    if (dn)
      openssl_new_xname(L, subj, dn, 1);

    if (attribs)
    {
      if(csr->req_info->attributes==NULL)
        csr->req_info->attributes = sk_X509_ATTRIBUTE_new_null();
      openssl_new_xattrs(L, csr->req_info->attributes, attribs, utf8);
    }

    if (extensions)
    {
      STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
      openssl_new_xexts(L, exts, extensions, utf8);
      X509_REQ_add_extensions(csr, exts);
      sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
  }

  return X509_REQ_set_pubkey(csr, pkey);
}

static LUA_FUNCTION(openssl_csr_read)
{
  BIO * in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  X509_REQ * csr = NULL;

  if ( fmt == FORMAT_AUTO || fmt == FORMAT_PEM)
  {
    csr = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    BIO_reset(in);
  }
  if ((fmt == FORMAT_AUTO && in == NULL) || fmt == FORMAT_DER)
  {
    csr = d2i_X509_REQ_bio(in, NULL);
    BIO_reset(in);
  }

  BIO_free(in);

  if (csr)
  {
    PUSH_OBJECT(csr, "openssl.x509_req");
    return 1;
  }
  else
    luaL_error(L, "read openssl.x509_req content fail");

  return 0;
}

static LUA_FUNCTION(openssl_csr_export)
{
  X509_REQ * csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  int fmt = luaL_checkoption(L, 2, "pem", format);
  int notext = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L, 3);
  BIO *out  = NULL;

  luaL_argcheck(L, fmt == FORMAT_DER || fmt == FORMAT_PEM, 2,
                "only accept der or pem");
  out = BIO_new(BIO_s_mem());
  if (fmt == FORMAT_PEM)
  {
    if (!notext)
    {
      X509_REQ_print(out, csr);
    }

    if (PEM_write_bio_X509_REQ(out, csr))
    {
      BUF_MEM *bio_buf;

      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
    {
      lua_pushnil(L);
    }
  }
  else
  {
    if (i2d_X509_REQ_bio(out, csr))
    {
      BUF_MEM *bio_buf;

      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
    {
      lua_pushnil(L);
    }
  }
  BIO_free(out);
  return 1;
}


static int copy_extensions(X509 *x, X509_REQ *req, int all)
{
  STACK_OF(X509_EXTENSION) *exts = NULL;
  X509_EXTENSION *ext, *tmpext;
  ASN1_OBJECT *obj;
  int i, idx, ret = 0;

  exts = X509_REQ_get_extensions(req);
  if (exts == NULL)
    return 0;
  for (i = 0; i < sk_X509_EXTENSION_num(exts); i++)
  {
    ext = sk_X509_EXTENSION_value(exts, i);
    obj = X509_EXTENSION_get_object(ext);
    idx = X509_get_ext_by_OBJ(x, obj, -1);
    /* Does extension exist? */
    if (idx != -1)
    {
      /* If normal copy don't override existing extension */
      if (!all)
        continue;
      /* Delete all extensions of same type */
      do
      {
        tmpext = X509_get_ext(x, idx);
        X509_delete_ext(x, idx);
        X509_EXTENSION_free(tmpext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
      }
      while (idx != -1);
    }
    if (!X509_add_ext(x, ext, -1))
      goto end;
  }

  ret = 1;

end:

  sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

  return ret;
}

static LUA_FUNCTION(openssl_csr_verify)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY * self_key = X509_REQ_get_pubkey(csr);
  lua_pushboolean(L, X509_REQ_verify(csr, self_key));
  EVP_PKEY_free(self_key);
  return 1;
};

static LUA_FUNCTION(openssl_csr_sign)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY *self_key = X509_REQ_get_pubkey(csr);

  X509 *cacert = lua_isnil(L, 2) ? NULL : CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *priv_key = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");

  X509 *new_cert = NULL;
  const EVP_MD *md = NULL;
  int num_days = 365;


  if (X509_REQ_verify(csr, self_key) == 0)
    luaL_error(L, "CSR Signature verification fail");

  if (cacert && !X509_check_private_key(cacert, priv_key))
    luaL_error(L, "private key does not correspond to signing cert");

  /* Now we go on make it */
  /* 1) */
  luaL_checktype(L, 4, LUA_TTABLE);
  {
    BIGNUM *bn = NULL;

    int version = 2;
    lua_getfield(L, 4, "serialNumber");
    bn = BN_get(L, -1);
    if (bn == NULL)
      luaL_argerror(L, 4, "must have serialNumber key and value is string or number type");
    lua_pop(L, 1);
    BN_set_negative(bn, 0);

    lua_getfield(L, 4, "digest");
    md = lua_isnil(L, -1) ? EVP_get_digestbyname("sha1WithRSAEncryption") : get_digest(L, -1);
    if (md == NULL)
      luaL_argerror(L, 4, "must have digest key and value can convert to evp_digest");
    lua_pop(L, 1);

    lua_getfield(L, 4, "num_days");
    num_days = luaL_optint(L, -1, num_days);
    lua_pop(L, 1);

    lua_getfield(L, 4, "version");
    version = luaL_optint(L, -1, version);
    lua_pop(L, 1);

    new_cert = X509_new();

    if (new_cert == NULL)
    {
      luaL_error(L, "out of memory");
    }

    /* Version 2 cert */
    if (!X509_set_version(new_cert, version))
      luaL_error(L, "fail X509_set_version");

    /* 3) */
    X509_set_serialNumber(new_cert, BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(new_cert)));
    X509_set_subject_name(new_cert, X509_REQ_get_subject_name(csr));
  }


  /* 4) */
  cacert = cacert ? cacert : new_cert;

  if (!X509_set_issuer_name(new_cert, X509_get_subject_name(cacert)))
    luaL_error(L, "fail X509_set_issuer_name");

  /* 5 */
  X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
#if OPENSSL_VERSION_NUMBER > 0x10000002L
  if (!X509_time_adj_ex(X509_get_notAfter(new_cert), num_days, 0, NULL))
    luaL_error(L, "fail X509_time_adj_ex");
#else
  X509_gmtime_adj(X509_get_notAfter(new_cert), (long)60 * 60 * 24 * num_days);
#endif

  /* 6 */
  if (!X509_set_pubkey(new_cert, self_key))
    luaL_error(L, "fail X509_set_pubkey");
  EVP_PKEY_free(self_key);

  copy_extensions(new_cert, csr, 1);
  if (!lua_isnoneornil(L, 5))
  {
    int utf8 = lua_isnoneornil(L, 6) ? 1 : lua_toboolean(L, 6);
    luaL_checktable(L, 5);

    if (new_cert->cert_info->extensions == NULL)
      new_cert->cert_info->extensions = sk_X509_EXTENSION_new_null();

    openssl_new_xexts(L, new_cert->cert_info->extensions, 5, utf8);  
  }

  /* Now sign it */
  if (!md)
    md = EVP_get_digestbyname("sha1WithRSAEncryption");

  if (!X509_sign(new_cert, priv_key, md))
  {
    luaL_error(L, "failed to sign it");
  }

  /* Succeeded; lets return the cert */
  PUSH_OBJECT(new_cert, "openssl.x509");
  return 1;
}

static LUA_FUNCTION(openssl_csr_new)
{
  X509_REQ *csr = NULL;

  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int dn = 2, attribs = 3, extensions = 4, digest = 5;
  int utf8 = 1;

  luaL_checktable(L, dn);

  if (lua_isnoneornil(L, attribs))
    attribs = 0;
  else
    luaL_checktable(L, attribs);

  if (lua_isnoneornil(L, extensions))
    extensions = 0;
  else
    luaL_checktable(L, extensions);

  if (!lua_isnoneornil(L, digest))
  {
    luaL_argcheck(L,
                  lua_isstring(L, digest) || auxiliar_isclass(L, "openssl.evp_digest", digest),
                  digest,
                  "only accept string or openssl.evp_digest"
                 );
  }
  else
    digest = 0;

  csr = X509_REQ_new();
  if (csr)
  {
    if (openssl_make_REQ(L, csr, pkey, dn, attribs, extensions, utf8))
    {
      const EVP_MD*  md = digest
                          ? get_digest(L, digest)
                          : EVP_get_digestbyname("sha1WithRSAEncryption");

      if (X509_REQ_sign(csr, pkey, md))
      {
        PUSH_OBJECT(csr, "openssl.x509_req");
        return 1;
      }
      else
      {
        luaL_error(L, "Error sign cert request");
      }
    }
    else
      luaL_error(L, "Error create cert request");
  }
  else
    luaL_error(L, "out of memory");

  return 0;
}

static LUA_FUNCTION(openssl_csr_parse)
{
  X509_REQ * csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  int utf8 = lua_isnoneornil(L, 3) ? 0 : lua_toboolean(L, 3);
  int  shortnames = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);

  X509_NAME * subject = X509_REQ_get_subject_name(csr);
  STACK_OF(X509_EXTENSION) *exts  = X509_REQ_get_extensions(csr);

  lua_newtable(L);

  PUSH_ASN1_BIT_STRING(L, csr->signature);
  lua_setfield(L,-2, "signature");

  openssl_push_x509_algor(L, csr->sig_alg);
  lua_setfield(L, -2, "sig_alg");

  lua_newtable(L);
  AUXILIAR_SET(L, -1, "version", ASN1_INTEGER_get(csr->req_info->version), integer);
  openssl_push_xname(L, subject);
  lua_setfield(L, -2, "subject");
  if(exts){
    openssl_push_x509_exts(L, exts, utf8);
    lua_setfield(L, -2, "extensions");
  }

  {
    X509_REQ_INFO* ri = csr->req_info;
    STACK_OF(X509_ATTRIBUTE) *attrs = ri->attributes;

    lua_newtable(L);
    if(attrs) {
      openssl_push_x509_attrs(L, attrs, utf8);
      lua_setfield(L, -2, "attributes");
    }

    lua_newtable(L);
    openssl_push_asn1object(L, ri->pubkey->algor->algorithm);
    lua_setfield(L, -2, "algorithm");

    AUXILIAR_SETOBJECT(L, X509_REQ_get_pubkey(csr), "openssl.evp_pkey", -1, "pubkey");
    lua_setfield(L, -2, "pubkey");

    lua_setfield(L, -2, "req_info");
  }

  return 1;
}

static LUA_FUNCTION(openssl_csr_free)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  X509_REQ_free(csr);
  return 0;
}

static LUA_FUNCTION(openssl_csr_get_public)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY *pkey = X509_REQ_get_pubkey(csr);
  PUSH_OBJECT(pkey, "openssl.evp_pkey");
  return 1;
}

static luaL_reg csr_cfuns[] =
{
  {"export",      openssl_csr_export  },
  {"parse",     openssl_csr_parse },
  {"sign",      openssl_csr_sign  },
  {"verify",      openssl_csr_verify },
  {"get_public",    openssl_csr_get_public  },

  {"__tostring",    auxiliar_tostring },
  {"__gc",      openssl_csr_free  },

  {NULL,        NULL  }
};


static luaL_reg R[] =
{
  {"new",       openssl_csr_new },
  {"read",      openssl_csr_read  },

  {NULL,    NULL}
};

LUALIB_API int luaopen_csr(lua_State *L)
{
  auxiliar_newclass(L, "openssl.x509_req", csr_cfuns);

  luaL_newmetatable(L, MYTYPE);
  lua_setglobal(L, MYNAME);
  luaL_register(L, MYNAME, R);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  return 1;
}
