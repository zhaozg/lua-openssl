/*=========================================================================*\
* pkcs7.c
* PKCS7 module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME    "pkcs7"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static LUA_FUNCTION(openssl_pkcs7_read)
{
  BIO* bio = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  PKCS7 *p7 = NULL;
  BIO* ctx = NULL;

  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(bio) ? FORMAT_DER : FORMAT_PEM;
  }

  if (fmt == FORMAT_DER)
  {
    p7 = d2i_PKCS7_bio(bio, NULL);
    BIO_reset(bio);
  }else
  if (fmt == FORMAT_PEM)
  {
    p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
    BIO_reset(bio);
  }else
  if (fmt == FORMAT_SMIME)
  {
    p7 = SMIME_read_PKCS7(bio, &ctx);
  }

  BIO_free(bio);
  if (p7)
  {
    PUSH_OBJECT(p7, "openssl.pkcs7");
    if (ctx)
    {
      BUF_MEM* mem;
      BIO_get_mem_ptr(ctx, &mem);
      lua_pushlstring(L, mem->data, mem->length);
      BIO_free(ctx);
      return 2;
    }
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static LUA_FUNCTION(openssl_pkcs7_sign)
{
  BIO *in  = load_bio_object(L, 1);
  X509 *cert = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *privkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509) *others = lua_isnoneornil(L, 4) ? 0 : CHECK_OBJECT(4, STACK_OF(X509), "openssl.stack_of_x509");
  long flags =  luaL_optinteger(L, 5, 0);

  PKCS7 *p7 = NULL;
  luaL_argcheck(L, openssl_pkey_is_private(privkey), 3, "must be private key");

  if (!X509_check_private_key(cert, privkey))
    luaL_error(L, "sigcert and private key not match");

  p7 = PKCS7_sign(cert, privkey, others, in, flags);
  BIO_free(in);
  if (p7)
  {
    PUSH_OBJECT(p7, "openssl.pkcs7");
    return 1;
  }
  else
  {
    luaL_error(L, "error creating PKCS7 structure!");
  }

  return 0;
}

static LUA_FUNCTION(openssl_pkcs7_verify)
{
  int ret = 0;
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  STACK_OF(X509) *signers = lua_isnoneornil(L, 2) ? NULL : CHECK_OBJECT(2, STACK_OF(X509), "openssl.stack_of_x509");
  X509_STORE *store = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, X509_STORE, "openssl.x509_store");
  BIO* in = lua_isnoneornil(L, 4) ? NULL : load_bio_object(L, 4);
  long flags = luaL_optinteger(L, 5, 0);
  BIO* out = BIO_new(BIO_s_mem());

  if (!store)
  {
    luaL_error(L, "can't setup veirfy cainfo");
  }

  if (PKCS7_verify(p7, signers, store, in, out, flags) == 1)
  {
    STACK_OF(X509) *signers1 = PKCS7_get0_signers(p7, NULL, flags);
    if (out)
    {
      BUF_MEM *bio_buf;

      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
      ret = 1;
    }
    else
      ret = 0;

    if (signers1)
    {
      signers1 = openssl_sk_x509_dup(signers1);
      PUSH_OBJECT(signers1, "openssl.sk_x509");
      ret += 1;
    }
  }
  else
  {
    lua_pushnil(L);
    ret = 1;
  }

  if (out)
    BIO_free(out);
  if (in)
    BIO_free(in);
  return ret;
}

static LUA_FUNCTION(openssl_pkcs7_encrypt)
{
  PKCS7 * p7 = NULL;
  BIO *infile = load_bio_object(L, 1);
  STACK_OF(X509) *recipcerts = CHECK_OBJECT(2, STACK_OF(X509), "openssl.stack_of_x509");
  const EVP_CIPHER *cipher = get_cipher(L, 3, "des3");
  long flags = luaL_optinteger(L, 4, 0);

  if (cipher == NULL)
  {
    luaL_error(L, "Failed to get cipher");
  }

  p7 = PKCS7_encrypt(recipcerts, infile, cipher, flags);
  BIO_free(infile);

  if (p7 == NULL)
  {
    lua_pushnil(L);
  }
  else
  {
    PUSH_OBJECT(p7, "openssl.pkcs7");
  }

  return 1;
}

static LUA_FUNCTION(openssl_pkcs7_decrypt)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  X509 *cert = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *key = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  long flags = luaL_optinteger(L, 4, 0);
  BIO *out = BIO_new(BIO_s_mem());

  if (PKCS7_decrypt(p7, key, cert, out, flags))
  {
    BUF_MEM* mem;
    BIO_get_mem_ptr(out, &mem);
    lua_pushlstring(L, mem->data, mem->length);
  }
  else
    lua_pushnil(L);
  BIO_free(out);
  return 1;
}

/*** pkcs7 object method ***/
static LUA_FUNCTION(openssl_pkcs7_gc)
{
  PKCS7* p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  PKCS7_free(p7);
  return 0;
}

static LUA_FUNCTION(openssl_pkcs7_export)
{
  int pem;
  PKCS7 * p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  int top = lua_gettop(L);
  BIO* bio_out = NULL;

  pem = top > 1 ? lua_toboolean(L, 2) : 1;

  bio_out  = BIO_new(BIO_s_mem());
  if (pem)
  {

    if (PEM_write_bio_PKCS7(bio_out, p7))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(bio_out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }
  else
  {
    if (i2d_PKCS7_bio(bio_out, p7))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(bio_out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }

  BIO_free(bio_out);
  return 1;
}

static int PKCS7_type_is_other(PKCS7* p7)
{
  int isOther = 1;

  int nid = OBJ_obj2nid(p7->type);

  switch ( nid )
  {
  case NID_pkcs7_data:
  case NID_pkcs7_signed:
  case NID_pkcs7_enveloped:
  case NID_pkcs7_signedAndEnveloped:
  case NID_pkcs7_digest:
  case NID_pkcs7_encrypted:
    isOther = 0;
    break;
  default:
    isOther = 1;
  }

  return isOther;

}
static ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7)
{
  if ( PKCS7_type_is_data(p7))
    return p7->d.data;
  if ( PKCS7_type_is_other(p7) && p7->d.other
       && (p7->d.other->type == V_ASN1_OCTET_STRING))
    return p7->d.other->value.octet_string;
  return NULL;
}

/*
int openssl_signerinfo_parse(lua_State*L)
{
  PKCS7_SIGNER_INFO * si = CHECK_OBJECT(1,PKCS7_SIGNER_INFO,"openssl.pkcs7_signer_info");
  si->

}
*/
static LUA_FUNCTION(openssl_pkcs7_parse)
{
  PKCS7 * p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  STACK_OF(X509) *certs = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  int i = OBJ_obj2nid(p7->type);

  lua_newtable(L);
  AUXILIAR_SET(L, -1, "type", OBJ_nid2ln(i), string);
  switch (i)
  {
  case NID_pkcs7_signed:
  {
    PKCS7_SIGNED *sign = p7->d.sign;
    PKCS7* c = sign->contents;
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(sign->signer_info, 0);
    (void*)si;
    certs = sign->cert ? sign->cert : NULL;
    crls = sign->crl ? sign->crl : NULL;
#if 0

    typedef struct pkcs7_signed_st
    {
      ASN1_INTEGER      *version; /* version 1 */
      STACK_OF(X509_ALGOR)    *md_algs; /* md used */
      STACK_OF(X509)      *cert;    /* [ 0 ] */
      STACK_OF(X509_CRL)    *crl;   /* [ 1 ] */
      STACK_OF(PKCS7_SIGNER_INFO) *signer_info;

      struct pkcs7_st     *contents;
    } PKCS7_SIGNED;
#endif
    AUXILIAR_SETOBJECT(L, sk_X509_ALGOR_dup(sign->md_algs), "openssl.stack_of_x509_algor", -1, "md_algs");
    AUXILIAR_SETOBJECT(L, sk_PKCS7_SIGNER_INFO_dup(sign->signer_info), "openssl.stack_of_pkcs7_signer_info", -1, "signer_info");
    AUXILIAR_SET(L, -1, "detached", PKCS7_is_detached(p7), boolean);

    if (c)
    {
      AUXILIAR_SETOBJECT(L, PKCS7_dup(c), "openssl.pkcs7", -1, "contents");
    }
    if (!PKCS7_is_detached(p7))
    {
      AUXILIAR_SETOBJECT(L, p7->d.sign->contents, "openssl.pkcs7", -1, "content");
    }
  }
  break;
  case NID_pkcs7_signedAndEnveloped:
    certs = p7->d.signed_and_enveloped->cert;
    crls = p7->d.signed_and_enveloped->crl;
    break;
  case NID_pkcs7_enveloped:
  {
    /*
    BIO * mem = BIO_new(BIO_s_mem());
    BIO * v_p7bio = PKCS7_dataDecode(p7,pkey,NULL,NULL);
    BUF_MEM *bptr = NULL;
    unsigned char src[4096];
    int len;

    while((len = BIO_read(v_p7bio,src,4096))>0){
     BIO_write(mem, src, len);
    }
    BIO_free(v_p7bio);
    BIO_get_mem_ptr(mem, &bptr);
    if((int)*puiDataLen < bptr->length)
    {
     *puiDataLen = bptr->length;
     ret = SAR_MemoryErr;
    }else{
     *puiDataLen =  bptr->length;
     memcpy(pucData,bptr->data, bptr->length);
    }
    */
  }
  break;
  case NID_pkcs7_digest:
  {
    PKCS7_DIGEST* d = p7->d.digest;
    PKCS7* c = d->contents;
    ASN1_OCTET_STRING *data = d->digest;
    (void*)c;

    AUXILIAR_SET(L, -1, "type", "digest", string);

    if (data)
    {
      int dlen = ASN1_STRING_length(data);
      unsigned char* dptr = ASN1_STRING_data(data);
      AUXILIAR_SETLSTR(L, -1, "digest", (const char*)dptr, dlen);
    }
  }
  break;
  case NID_pkcs7_data:
  {
    ASN1_OCTET_STRING *data = p7->d.data;
    int dlen = ASN1_STRING_length(data);
    unsigned char* dptr = ASN1_STRING_data(data);

    AUXILIAR_SET(L, -1, "type", "data", string);
    AUXILIAR_SETLSTR(L, -1, "data", (const char*)dptr, dlen);
  }
  break;
  default:
    break;
  }

  if (certs != NULL)
  {
    AUXILIAR_SETOBJECT(L, openssl_sk_x509_dup(certs), "openssl.stack_of_x509", -1, "certs");
  }
  if (crls != NULL)
  {
    AUXILIAR_SETOBJECT(L, openssl_sk_x509_crl_dup(crls), "openssl.stack_of_crl", -1, "crls");
  }

  return 1;
}

#if 0

int headers = 5;
, * outfile = NULL
              outfile = CHECK_OBJECT(2, BIO, "openssl.bio");
lua_pushnil(L);  /* first key */
while (lua_next(L, headers) != 0)
{
  /* uses 'key' (at index -2) and 'value' (at index -1) */
  //printf("%s - %s\n",lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
  const char *idx = lua_tostring(L, -2);
  const char *val = luaL_checkstring(L, -1);

  BIO_printf(outfile, "%s: %s\n", idx, val);

  /* removes 'value'; keeps 'key' for next iteration */
  lua_pop(L, 1);
}

/* write the signed data */
ret = SMIME_write_PKCS7(outfile, p7, infile, flags);

/* tack on extra headers */
/* table is in the stack at index 't' */
lua_pushnil(L);  /* first key */
while (lua_next(L, headers) != 0)
{
  /* uses 'key' (at index -2) and 'value' (at index -1) */
  //printf("%s - %s\n",lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
  const char *idx = lua_tostring(L, -2);
  const char *val = luaL_checkstring(L, -1);

  BIO_printf(outfile, "%s: %s\n", idx, val);

  /* removes 'value'; keeps 'key' for next iteration */
  lua_pop(L, 1);
}

#endif

static luaL_Reg pkcs7_funcs[] =
{
  {"parse",         openssl_pkcs7_parse},
  {"export",        openssl_pkcs7_export},
  {"decrypt",       openssl_pkcs7_decrypt},
  {"verify",        openssl_pkcs7_verify},

  {"__gc",          openssl_pkcs7_gc       },
  {"__tostring",    auxiliar_tostring },

  {NULL,      NULL}
};

static const luaL_Reg R[] =
{
  {"read",        openssl_pkcs7_read},
  {"sign",        openssl_pkcs7_sign},
  {"verify",      openssl_pkcs7_verify},
  {"encrypt",     openssl_pkcs7_encrypt},
  {"decrypt",     openssl_pkcs7_decrypt},

  {NULL,  NULL}
};

int luaopen_pkcs7(lua_State *L)
{
  auxiliar_newclass(L, "openssl.pkcs7", pkcs7_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
