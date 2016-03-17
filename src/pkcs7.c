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
  }
  else if (fmt == FORMAT_PEM)
  {
    p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
    BIO_reset(bio);
  }
  else if (fmt == FORMAT_SMIME)
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

#if OPENSSL_VERSION_NUMBER > 0x10000000L

static LUA_FUNCTION(openssl_pkcs7_new)
{
  int type = luaL_optint(L, 1, NID_pkcs7_signed);
  int content_nid = luaL_optint(L, 2, NID_pkcs7_data);

  PKCS7 *p7 = PKCS7_new();
  if (p7)
  {
    int ret = 1;
    ret = PKCS7_set_type(p7, type);
    if (ret)
      ret = PKCS7_content_new(p7, content_nid);
    if (ret)
    {
      PUSH_OBJECT(p7, "openssl.pkcs7");
      return 1;
    }
    else
      PKCS7_free(p7);
  }
  return 0;
}

static LUA_FUNCTION(openssl_pkcs7_sign_add_signer)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  X509 *signcert = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  const EVP_MD* md = get_digest(L, 4);
  long flags = luaL_optint(L, 5, 0);
  PKCS7_SIGNER_INFO *signer = 0;

  luaL_argcheck(L, X509_check_private_key(signcert, pkey), 3,
                "sigcert and private key not match");

  signer = PKCS7_sign_add_signer(p7, signcert, pkey, md, flags);
  (void) signer;
  return openssl_pushresult(L, signcert != NULL ? 1 : 0);
}

static LUA_FUNCTION(openssl_pkcs7_add)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  int n = lua_gettop(L);
  int i, ret;
  ret = 1;
  luaL_argcheck(L, lua_isuserdata(L, 2), 2, "must supply certificate or crl object");
  for (i = 2; i <= n; i++)
  {
    luaL_argcheck(L, auxiliar_isclass(L, "openssl.x509", i) || auxiliar_isclass(L, "openssl.x509_crl", i),
                  i, "must supply certificate or crl object");

    if (auxiliar_isclass(L, "openssl.x509", i))
    {
      X509* x = CHECK_OBJECT(i, X509, "openssl.x509");
      ret = PKCS7_add_certificate(p7, x);
    }
    else
    {
      X509_CRL *crl = CHECK_OBJECT(i, X509_CRL, "openssl.x509_crl");
      ret = PKCS7_add_crl(p7, crl);
    }
    luaL_argcheck(L, ret, i, "add to pkcs7 fail");
  }
  return openssl_pushresult(L, ret);
}

static int PKCS7_type_is_other(PKCS7* p7)
{
  int isOther = 1;

  int nid = OBJ_obj2nid(p7->type);

  switch (nid)
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
  if (PKCS7_type_is_data(p7))
    return p7->d.data;
  if (PKCS7_type_is_other(p7) && p7->d.other
      && (p7->d.other->type == V_ASN1_OCTET_STRING))
    return p7->d.other->value.octet_string;
  return NULL;
}

static BIO *PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid)
{
  for (;;)
  {
    bio = BIO_find_type(bio, BIO_TYPE_MD);
    if (bio == NULL)
    {
      PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST,
               PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
      return NULL;
    }
    BIO_get_md_ctx(bio, pmd);
    if (*pmd == NULL)
    {
      PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST, ERR_R_INTERNAL_ERROR);
      return NULL;
    }
    if (EVP_MD_CTX_type(*pmd) == nid)
      return bio;
    bio = BIO_next(bio);
  }
  return NULL;
}

static int PKCS7_SIGNER_INFO_sign_0(PKCS7_SIGNER_INFO *si)
{
  EVP_MD_CTX mctx;
  EVP_PKEY_CTX *pctx;
  unsigned char *abuf = NULL;
  int alen;
  size_t siglen;
  const EVP_MD *md = NULL;

  md = EVP_get_digestbyobj(si->digest_alg->algorithm);
  if (md == NULL)
    return 0;

  EVP_MD_CTX_init(&mctx);
  if (EVP_DigestSignInit(&mctx, &pctx, md, NULL, si->pkey) <= 0)
    goto err;

  if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                        EVP_PKEY_CTRL_PKCS7_SIGN, 0, si) <= 0)
  {
    PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SIGN, PKCS7_R_CTRL_ERROR);
    goto err;
  }

  alen = ASN1_item_i2d((ASN1_VALUE *) si->auth_attr, &abuf,
                       ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
  if (!abuf)
    goto err;
  if (EVP_DigestSignUpdate(&mctx, abuf, alen) <= 0)
    goto err;
  OPENSSL_free(abuf);
  abuf = NULL;
  if (EVP_DigestSignFinal(&mctx, NULL, &siglen) <= 0)
    goto err;
  abuf = OPENSSL_malloc(siglen);
  if (!abuf)
    goto err;

  if (EVP_DigestSignFinal(&mctx, abuf, &siglen) <= 0)
    goto err;
  if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                        EVP_PKEY_CTRL_PKCS7_SIGN, 1, si) <= 0)
  {
    PKCS7err(PKCS7_F_PKCS7_SIGNER_INFO_SIGN, PKCS7_R_CTRL_ERROR);
    goto err;
  }

  EVP_MD_CTX_cleanup(&mctx);

  ASN1_STRING_set0(si->enc_digest, abuf, siglen);

  return 1;

err:
  if (abuf)
    OPENSSL_free(abuf);
  EVP_MD_CTX_cleanup(&mctx);
  return 0;

}

static int do_pkcs7_signed_attrib(PKCS7_SIGNER_INFO *si, EVP_MD_CTX *mctx)
{
  unsigned char md_data[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  /* Add signing time if not already present */
  if (!PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime))
  {
    if (!PKCS7_add0_attrib_signing_time(si, NULL))
    {
      PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }

  /* Add digest */
  if (!EVP_DigestFinal_ex(mctx, md_data, &md_len))
  {
    PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_EVP_LIB);
    return 0;
  }
  if (!PKCS7_add1_attrib_digest(si, md_data, md_len))
  {
    PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  /* Now sign the attributes */
  if (!PKCS7_SIGNER_INFO_sign_0(si))
    return 0;

  return 1;
}

static char *memdup(const char *src, size_t buffer_length)
{
  size_t length;
  int add = 0;
  char *buffer;

  if (buffer_length)
    length = buffer_length;
  else if (src)
  {
    length = strlen(src);
    add = 1;
  }
  else
    /* no length and a NULL src pointer! */
    return strdup("");

  buffer = malloc(length + add);
  if (!buffer)
    return NULL; /* fail */

  memcpy(buffer, src, length);

  /* if length unknown do null termination */
  if (add)
    buffer[length] = '\0';

  return buffer;
}


static int openssl_pkcs7_dataFinal(PKCS7 *p7, BIO *bio)
{
  int ret = 0;
  int i, j;
  BIO *btmp;
  PKCS7_SIGNER_INFO *si;
  EVP_MD_CTX *mdc, ctx_tmp;
  STACK_OF(X509_ATTRIBUTE) *sk;
  STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
  ASN1_OCTET_STRING *os = NULL;

  if (p7 == NULL)
  {
    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_INVALID_NULL_POINTER);
    return 0;
  }

  if (p7->d.ptr == NULL)
  {
    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_NO_CONTENT);
    return 0;
  }

  EVP_MD_CTX_init(&ctx_tmp);
  i = OBJ_obj2nid(p7->type);
  p7->state = PKCS7_S_HEADER;

  switch (i)
  {
  case NID_pkcs7_data:
    os = p7->d.data;
    break;
  case NID_pkcs7_signedAndEnveloped:
    /* XXXXXXXXXXXXXXXX */
    si_sk = p7->d.signed_and_enveloped->signer_info;
    os = p7->d.signed_and_enveloped->enc_data->enc_data;
    if (!os)
    {
      os = M_ASN1_OCTET_STRING_new();
      if (!os)
      {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
      p7->d.signed_and_enveloped->enc_data->enc_data = os;
    }
    break;
  case NID_pkcs7_enveloped:
    /* XXXXXXXXXXXXXXXX */
    os = p7->d.enveloped->enc_data->enc_data;
    if (!os)
    {
      os = M_ASN1_OCTET_STRING_new();
      if (!os)
      {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
      p7->d.enveloped->enc_data->enc_data = os;
    }
    break;
  case NID_pkcs7_signed:
    si_sk = p7->d.sign->signer_info;
    os = PKCS7_get_octet_string(p7->d.sign->contents);
    /* If detached data then the content is excluded */
    if (PKCS7_type_is_data(p7->d.sign->contents) && p7->detached)
    {
      M_ASN1_OCTET_STRING_free(os);
      os = NULL;
      p7->d.sign->contents->d.data = NULL;
    }
    break;

  case NID_pkcs7_digest:
    os = PKCS7_get_octet_string(p7->d.digest->contents);
    /* If detached data then the content is excluded */
    if (PKCS7_type_is_data(p7->d.digest->contents) && p7->detached)
    {
      M_ASN1_OCTET_STRING_free(os);
      os = NULL;
      p7->d.digest->contents->d.data = NULL;
    }
    break;

  default:
    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
    goto err;
  }

  if (si_sk != NULL)
  {
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++)
    {
      si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
      if (si->pkey == NULL)
        continue;

      j = OBJ_obj2nid(si->digest_alg->algorithm);

      btmp = bio;

      btmp = PKCS7_find_digest(&mdc, btmp, j);

      if (btmp == NULL)
        goto err;

      /*
      * We now have the EVP_MD_CTX, lets do the signing.
      */
      if (!EVP_MD_CTX_copy_ex(&ctx_tmp, mdc))
        goto err;

      sk = si->auth_attr;

      /*
      * If there are attributes, we add the digest attribute and only
      * sign the attributes
      */
      if (sk_X509_ATTRIBUTE_num(sk) > 0)
      {
        if (!do_pkcs7_signed_attrib(si, &ctx_tmp))
          goto err;
      }
      else
      {
        unsigned char *abuf = NULL;
        unsigned int abuflen;
        abuflen = EVP_PKEY_size(si->pkey);
        abuf = OPENSSL_malloc(abuflen);
        if (!abuf)
          goto err;

        if (!EVP_SignFinal(&ctx_tmp, abuf, &abuflen, si->pkey))
        {
          PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_EVP_LIB);
          goto err;
        }
        ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
      }
    }
  }
  else if (i == NID_pkcs7_digest)
  {
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (!PKCS7_find_digest(&mdc, bio,
                           OBJ_obj2nid(p7->d.digest->md->algorithm)))
      goto err;
    if (!EVP_DigestFinal_ex(mdc, md_data, &md_len))
      goto err;
    M_ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len);
  }

  if (!PKCS7_is_detached(p7))
  {
    /*
    * NOTE(emilia): I think we only reach os == NULL here because detached
    * digested data support is broken.
    */
    if (os == NULL)
      goto err;
    if (!(os->flags & ASN1_STRING_FLAG_NDEF))
    {
      char *cont;
      long contlen;
      btmp = BIO_find_type(bio, BIO_TYPE_MEM);
      if (btmp == NULL)
      {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
        goto err;
      }
      contlen = BIO_get_mem_data(btmp, &cont);
      /*
      * Mark the BIO read only then we can use its copy of the data
      * instead of making an extra copy.
      */
      BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
      BIO_set_mem_eof_return(btmp, 0);
      ASN1_STRING_set0(os, (unsigned char *)cont, contlen);
    }
  }
  ret = 1;
err:
  EVP_MD_CTX_cleanup(&ctx_tmp);
  return (ret);
}


static int openssl_pkcs7_final(lua_State *L)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  BIO *data = load_bio_object(L, 2);
  int flags = luaL_optint(L, 3, 0);

  BIO *p7bio = PKCS7_dataInit(p7, NULL);
  int ret = 0;

  if (p7bio == NULL)
  {
    lua_pushnil(L);
    lua_pushstring(L, "PKCS7_dataInit fail");
    ret = 2;
  }
  else
  {
    SMIME_crlf_copy(data, p7bio, flags);

    (void)BIO_flush(p7bio);

    if (!openssl_pkcs7_dataFinal(p7, p7bio))
    {
      lua_pushnil(L);
      lua_pushstring(L, "PKCS7_dataFinal fail");
      ret = 2;
    }
    else
    {
      ret = 1;
      lua_pushboolean(L, 1);
    }
    BIO_free_all(p7bio);
  }

  return ret;
}


static LUA_FUNCTION(openssl_pkcs7_sign_digest)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  size_t l;
  const char* data = luaL_checklstring(L, 2, &l);
  long flags = luaL_optint(L, 3, 0);
  int hash = lua_isnoneornil(L, 4) ? 0 : lua_toboolean(L, 4);

  int ret = 0;
  int i, j;

  const EVP_MD* md;
  PKCS7_SIGNER_INFO *si;
  EVP_MD_CTX mdc;
  STACK_OF(X509_ATTRIBUTE) *sk;
  STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
  ASN1_OCTET_STRING *os = NULL;

  if (p7->d.ptr == NULL)
  {
    luaL_error(L, "pkcs7 without content");
    return 0;
  }

  flags |= PKCS7_DETACHED;
  PKCS7_set_detached(p7, 1);

  EVP_MD_CTX_init(&mdc);
  i = OBJ_obj2nid(p7->type);
  p7->state = PKCS7_S_HEADER;

  switch (i)
  {
  case NID_pkcs7_data:
    os = p7->d.data;
    break;
  case NID_pkcs7_signedAndEnveloped:
    /* XXXXXXXXXXXXXXXX */
    si_sk = p7->d.signed_and_enveloped->signer_info;
    os = p7->d.signed_and_enveloped->enc_data->enc_data;
    if (!os)
    {
      os = M_ASN1_OCTET_STRING_new();
      if (!os)
      {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
      p7->d.signed_and_enveloped->enc_data->enc_data = os;
    }
    break;
  case NID_pkcs7_enveloped:
    /* XXXXXXXXXXXXXXXX */
    os = p7->d.enveloped->enc_data->enc_data;
    if (!os)
    {
      os = M_ASN1_OCTET_STRING_new();
      if (!os)
      {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
      p7->d.enveloped->enc_data->enc_data = os;
    }
    break;
  case NID_pkcs7_signed:
    si_sk = p7->d.sign->signer_info;
    os = PKCS7_get_octet_string(p7->d.sign->contents);
    /* If detached data then the content is excluded */
    if (PKCS7_type_is_data(p7->d.sign->contents) && p7->detached)
    {
      M_ASN1_OCTET_STRING_free(os);
      os = NULL;
      p7->d.sign->contents->d.data = NULL;
    }
    break;

  case NID_pkcs7_digest:
    os = PKCS7_get_octet_string(p7->d.digest->contents);
    /* If detached data then the content is excluded */
    if (PKCS7_type_is_data(p7->d.digest->contents) && p7->detached)
    {
      M_ASN1_OCTET_STRING_free(os);
      os = NULL;
      p7->d.digest->contents->d.data = NULL;
    }
    break;

  default:
    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
    goto err;
  }

  if (si_sk != NULL)
  {
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++)
    {
      si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
      if (si->pkey == NULL)
        continue;
      j = OBJ_obj2nid(si->digest_alg->algorithm);
      md = EVP_get_digestbynid(j);
      EVP_DigestInit_ex(&mdc, md, NULL);

      if (hash)
      {
        if (l == (size_t) mdc.digest->ctx_size)
        {
          memcpy(mdc.md_data, data, l);
        }
        else
        {
          EVP_MD_CTX_cleanup(&mdc);
          luaL_argerror(L, 2, "data with wrong length");
        }
      }
      else
        EVP_DigestUpdate(&mdc, data, l);

      sk = si->auth_attr;

      /*
      * If there are attributes, we add the digest attribute and only
      * sign the attributes
      */
      if (sk_X509_ATTRIBUTE_num(sk) > 0)
      {
        if (!do_pkcs7_signed_attrib(si, &mdc))
          goto err;
      }
      else
      {
        unsigned char *abuf = NULL;
        unsigned int abuflen;
        abuflen = EVP_PKEY_size(si->pkey);
        abuf = OPENSSL_malloc(abuflen);
        if (!abuf)
          goto err;

        if (!EVP_SignFinal(&mdc, abuf, &abuflen, si->pkey))
        {
          PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_EVP_LIB);
          goto err;
        }
        ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
      }
    }
  }
  else if (i == NID_pkcs7_digest)
  {
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    md = EVP_get_digestbynid(OBJ_obj2nid(p7->d.digest->md->algorithm));
    EVP_DigestInit_ex(&mdc, md, NULL);
    if (l == (size_t) mdc.digest->ctx_size)
    {
      memcpy(mdc.md_data, data, l);
    }
    else
    {
      EVP_MD_CTX_cleanup(&mdc);
      luaL_error(L, "data with wrong data");
    }
    if (!EVP_DigestFinal_ex(&mdc, md_data, &md_len))
      goto err;
    M_ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len);
  }

  if (!PKCS7_is_detached(p7))
  {
    /*
    * NOTE(emilia): I think we only reach os == NULL here because detached
    * digested data support is broken.
    */
    if (os == NULL)
      goto err;
    if (!(os->flags & ASN1_STRING_FLAG_NDEF))
    {
      char *cont = memdup(data, l);
      long contlen = l;
      ASN1_STRING_set0(os, (unsigned char *) cont, contlen);
    }
  }

  ret = 1;
err:
  EVP_MD_CTX_cleanup(&mdc);
  return openssl_pushresult(L, ret);
}

int PKCS7_signatureVerify_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si, X509 *x509,
                                 const unsigned char* data, size_t len, int hash)
{
  ASN1_OCTET_STRING *os;
  const EVP_MD* md;
  EVP_MD_CTX mdc, mdc_tmp;
  int ret = 0, i;
  int md_type;
  STACK_OF(X509_ATTRIBUTE) *sk;
  EVP_PKEY *pkey = NULL;

  EVP_MD_CTX_init(&mdc);
  EVP_MD_CTX_init(&mdc_tmp);
  if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7))
  {
    PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_WRONG_PKCS7_TYPE);
    goto err;
  }

  md_type = OBJ_obj2nid(si->digest_alg->algorithm);
  md = EVP_get_digestbynid(md_type);
  if (!md || !data || (hash && len != (size_t) md->ctx_size) )
    goto err;

  if (!EVP_DigestInit_ex(&mdc, md, NULL))
    goto err;
  if (hash)
    memcpy(mdc.md_data, data, len);
  else
    EVP_DigestUpdate(&mdc, data, len);

  pkey = X509_get_pubkey(x509);
  if (!pkey)
  {
    ret = -1;
    goto err;
  }
  /*
  * mdc is the digest ctx that we want, unless there are attributes, in
  * which case the digest is the signed attributes
  */
  if (!EVP_MD_CTX_copy_ex(&mdc_tmp, &mdc))
    goto err;
  sk = si->auth_attr;
  if ((sk != NULL) && (sk_X509_ATTRIBUTE_num(sk) != 0))
  {
    unsigned char md_dat[EVP_MAX_MD_SIZE], *abuf = NULL;
    unsigned int md_len;
    int alen;
    ASN1_OCTET_STRING *message_digest;

    if (!EVP_DigestFinal_ex(&mdc_tmp, md_dat, &md_len))
      goto err;
    message_digest = PKCS7_digest_from_attributes(sk);
    if (!message_digest)
    {
      PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY,
               PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
      goto err;
    }
    if ((message_digest->length != (int) md_len) ||
        (memcmp(message_digest->data, md_dat, md_len)))
    {
      PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_DIGEST_FAILURE);
      ret = -1;
      goto err;
    }
    if (!EVP_DigestVerifyInit(&mdc_tmp, NULL, EVP_get_digestbynid(md_type), NULL, pkey))
      goto err;

    alen = ASN1_item_i2d((ASN1_VALUE *) sk, &abuf,
                         ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
    if (alen <= 0)
    {
      PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, ERR_R_ASN1_LIB);
      ret = -1;
      goto err;
    }
    if (!EVP_VerifyUpdate(&mdc_tmp, abuf, alen))
      goto err;

    OPENSSL_free(abuf);
  }

  os = si->enc_digest;
  i = EVP_VerifyFinal(&mdc_tmp, os->data, os->length, pkey);
  if (i <= 0)
  {
    PKCS7err(PKCS7_F_PKCS7_SIGNATUREVERIFY, PKCS7_R_SIGNATURE_FAILURE);
    ret = -1;
    goto err;
  }
  else
    ret = 1;
err:
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_cleanup(&mdc);
  EVP_MD_CTX_cleanup(&mdc_tmp);

  return (ret);
}

static LUA_FUNCTION(openssl_pkcs7_verify_digest)
{
  PKCS7 *p7 = CHECK_OBJECT(1, PKCS7, "openssl.pkcs7");
  STACK_OF(X509) *certs = lua_isnoneornil(L, 2) ? NULL : openssl_sk_x509_fromtable(L, 2);
  X509_STORE *store = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, X509_STORE, "openssl.x509_store");
  size_t len;
  const char* data = luaL_checklstring(L, 4, &len);
  long flags = luaL_optint(L, 5, 0);
  int hash = lua_isnoneornil(L, 6) ? 0 : lua_toboolean(L, 6);

  STACK_OF(X509) *signers;
  X509 *signer;
  STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
  PKCS7_SIGNER_INFO *si;
  X509_STORE_CTX cert_ctx;

  int i, j = 0, k, ret = 0;

  if (!PKCS7_type_is_signed(p7))
  {
    luaL_error(L, "pkcs7 must be signedData");
  }

  /* Check for no data and no content: no data to verify signature */
  if (!PKCS7_get_detached(p7))
  {
    luaL_error(L, "pkcs7 must be detached signedData");
  }


  sinfos = PKCS7_get_signer_info(p7);
  if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos))
  {
    luaL_error(L, "pkcs7 signedData without signature");
  }

  signers = PKCS7_get0_signers(p7, certs, flags);
  if (!signers)
  {
    luaL_error(L, "pkcs7 signedData without signers");
  }

  if (!store)
    flags |= PKCS7_NOVERIFY;

  /* Now verify the certificates */
  if (!(flags & PKCS7_NOVERIFY))
    for (k = 0; k < sk_X509_num(signers); k++)
    {
      signer = sk_X509_value(signers, k);
      if (!(flags & PKCS7_NOCHAIN))
      {
        if (!X509_STORE_CTX_init(&cert_ctx, store, signer,
                                 p7->d.sign->cert))
        {
          PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
          goto err;
        }
        X509_STORE_CTX_set_default(&cert_ctx, "smime_sign");
      }
      else if (!X509_STORE_CTX_init(&cert_ctx, store, signer, NULL))
      {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
        goto err;
      }
      if (!(flags & PKCS7_NOCRL))
        X509_STORE_CTX_set0_crls(&cert_ctx, p7->d.sign->crl);
      i = X509_verify_cert(&cert_ctx);
      if (i <= 0)
        j = X509_STORE_CTX_get_error(&cert_ctx);
      X509_STORE_CTX_cleanup(&cert_ctx);
      if (i <= 0)
      {
        PKCS7err(PKCS7_F_PKCS7_VERIFY,
                 PKCS7_R_CERTIFICATE_VERIFY_ERROR);
        ERR_add_error_data(2, "Verify error:",
                           X509_verify_cert_error_string(j));
        goto err;
      }
      /* Check for revocation status here */
    }

  /* Now Verify All Signatures */
  if (!(flags & PKCS7_NOSIGS))
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++)
    {
      si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
      signer = sk_X509_value(signers, i);
      j = PKCS7_signatureVerify_digest(p7, si, signer,
                                       (const unsigned char*) data, len, hash);
      if (j <= 0)
      {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_SIGNATURE_FAILURE);
        goto err;
      }
    }
  ret = 1;

err:
  if (certs)
    sk_X509_pop_free(certs, X509_free);
  sk_X509_free(signers);
  return openssl_pushresult(L, ret);
}
#endif

static LUA_FUNCTION(openssl_pkcs7_sign)
{
  BIO *in  = load_bio_object(L, 1);
  X509 *cert = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *privkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509) *others = lua_isnoneornil(L, 4) ? 0 : openssl_sk_x509_fromtable(L, 4);
  long flags =  luaL_optint(L, 5, 0);
  PKCS7 *p7 = NULL;

  if (!X509_check_private_key(cert, privkey))
    luaL_error(L, "sigcert and private key not match");
  p7 = PKCS7_sign(cert, privkey, others, in, flags);
  BIO_free(in);
  if (others)
    sk_X509_pop_free(others, X509_free);
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
  STACK_OF(X509) *signers = lua_isnoneornil(L, 2) ? NULL : openssl_sk_x509_fromtable(L, 2);
  X509_STORE *store = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, X509_STORE, "openssl.x509_store");
  BIO* in = lua_isnoneornil(L, 4) ? NULL : load_bio_object(L, 4);
  long flags = luaL_optint(L, 5, 0);
  BIO* out = BIO_new(BIO_s_mem());
  if (!store)
    flags |= PKCS7_NOVERIFY;
  if (PKCS7_verify(p7, signers, store, in, out, flags) == 1)
  {
    if (out && (flags & PKCS7_DETACHED) == 0)
    {
      BUF_MEM *bio_buf;

      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
    {
      lua_pushboolean(L, 1);
    }
    ret += 1;
  }
  else
  {
    ret = openssl_pushresult(L, 0);
  }
  if (signers)
    sk_X509_pop_free(signers, X509_free);
  if (out)
    BIO_free(out);
  if (in)
    BIO_free(in);
  return ret;
}

static LUA_FUNCTION(openssl_pkcs7_encrypt)
{
  PKCS7 * p7 = NULL;
  BIO *in = load_bio_object(L, 1);
  STACK_OF(X509) *recipcerts = openssl_sk_x509_fromtable(L, 2);
  const EVP_CIPHER *cipher = get_cipher(L, 3, "des3");
  long flags = luaL_optint(L, 4, 0);

  if (cipher == NULL)
  {
    luaL_error(L, "Failed to get cipher");
  }

  p7 = PKCS7_encrypt(recipcerts, in, cipher, flags);
  BIO_free(in);
  sk_X509_pop_free(recipcerts, X509_free);
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
  long flags = luaL_optint(L, 4, 0);
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

static int openssl_push_pkcs7_signer_info(lua_State *L, PKCS7_SIGNER_INFO *info)
{
  lua_newtable(L);
  AUXILIAR_SET(L, -1, "version", ASN1_INTEGER_get(info->version), integer);

  if (info->issuer_and_serial != NULL)
  {
    X509_NAME *i = X509_NAME_dup(info->issuer_and_serial->issuer);
    ASN1_INTEGER *s = ASN1_INTEGER_dup(info->issuer_and_serial->serial);
    if (info->issuer_and_serial->issuer)
      AUXILIAR_SETOBJECT(L, i, "openssl.x509_name", -1, "issuer");

    if (info->issuer_and_serial->serial)
      AUXILIAR_SETOBJECT(L, s, "openssl.asn1_integer", -1, "serial");
  }

  if (info->digest_alg)
  {
    X509_ALGOR *dup = X509_ALGOR_dup(info->digest_alg);
    AUXILIAR_SETOBJECT(L, dup, "openssl.x509_algor", -1, "digest_alg");
  }
  if (info->digest_enc_alg)
  {
    X509_ALGOR *dup = X509_ALGOR_dup(info->digest_alg);
    AUXILIAR_SETOBJECT(L, dup, "openssl.x509_algor", -1, "digest_enc_alg");
  }
  if (info->enc_digest)
  {
    ASN1_STRING *dup = ASN1_STRING_dup(info->enc_digest);
    AUXILIAR_SETOBJECT(L, dup, "openssl.asn1_string", -1, "enc_digest");
  }

  if (info->pkey)
  {
    CRYPTO_add(&info->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    AUXILIAR_SETOBJECT(L, info->pkey, "openssl.evp_pkey", -1, "pkey");
  }
  return 1;
}

static LUA_FUNCTION(openssl_pkcs7_signer_info_gc)
{
  PKCS7_SIGNER_INFO *info = CHECK_OBJECT(1, PKCS7_SIGNER_INFO, "openssl.pkcs7_signer_info");
  PKCS7_SIGNER_INFO_free(info);
  return 0;
}

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
    certs = sign->cert ? sign->cert : NULL;
    crls = sign->crl ? sign->crl : NULL;

    AUXILIAR_SET(L, -1, "version", ASN1_INTEGER_get(sign->version), integer);
    AUXILIAR_SET(L, -1, "detached", PKCS7_is_detached(p7), boolean);
    lua_pushstring(L, "md_algs");
    openssl_sk_x509_algor_totable(L, sign->md_algs);
    lua_rawset(L, -3);

    if (sign->signer_info)
    {
      int j, n;
      n = sk_PKCS7_SIGNER_INFO_num(sign->signer_info);
      lua_pushstring(L, "signer_info");
      lua_newtable(L);
      for (j = 0; j < n; j++)
      {
        PKCS7_SIGNER_INFO *info = sk_PKCS7_SIGNER_INFO_value(sign->signer_info, j);
        lua_pushinteger(L, j + 1);
        openssl_push_pkcs7_signer_info(L, info);
        lua_rawset(L, -3);
      }
      lua_rawset(L, -3);
    }

    if (!PKCS7_is_detached(p7))
    {
      PKCS7* c = sign->contents;
      c = PKCS7_dup(c);
      AUXILIAR_SETOBJECT(L, c, "openssl.pkcs7", -1, "contents");
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

    ASN1_OCTET_STRING *as = ASN1_STRING_dup(d->digest);
    PUSH_OBJECT(as, "openssl.asn1_string");
    lua_setfield(L, -2, "digest");
  }
  break;
  case NID_pkcs7_data:
  {
    ASN1_OCTET_STRING *as = ASN1_STRING_dup(p7->d.data);
    PUSH_OBJECT(as, "openssl.asn1_string");
    lua_setfield(L, -2, "data");
  }
  break;
  default:
    break;
  }

  /* NID_pkcs7_signed or NID_pkcs7_signedAndEnveloped */
  if (certs != NULL)
  {
    lua_pushstring(L, "certs");
    openssl_sk_x509_totable(L, certs);
    lua_rawset(L, -3);
  }
  if (crls != NULL)
  {
    lua_pushstring(L, "crls");
    openssl_sk_x509_crl_totable(L, crls);
    lua_rawset(L, -3);
  }
  return 1;
}

static luaL_Reg pkcs7_funcs[] =
{
  {"parse",         openssl_pkcs7_parse},
  {"export",        openssl_pkcs7_export},
  {"decrypt",       openssl_pkcs7_decrypt},
  {"verify",        openssl_pkcs7_verify},
  {"final",         openssl_pkcs7_final},
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  {"add_signer",    openssl_pkcs7_sign_add_signer},
  {"add",           openssl_pkcs7_add},
  {"sign_digest",   openssl_pkcs7_sign_digest},
  {"verify_digest", openssl_pkcs7_verify_digest},
#endif

  {"__gc",          openssl_pkcs7_gc},
  {"__tostring",    auxiliar_tostring},

  {NULL,      NULL}
};

static const luaL_Reg R[] =
{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  {"new",         openssl_pkcs7_new},
#endif
  {"read",        openssl_pkcs7_read},
  {"sign",        openssl_pkcs7_sign},
  {"verify",      openssl_pkcs7_verify},
  {"encrypt",     openssl_pkcs7_encrypt},
  {"decrypt",     openssl_pkcs7_decrypt},

  {NULL,  NULL}
};

static LuaL_Enum pkcs7_const[] =
{
  {"TEXT",         PKCS7_TEXT},
  {"NOCERTS",      PKCS7_NOCERTS},
  {"NOSIGS",       PKCS7_NOSIGS},
  {"NOCHAIN",      PKCS7_NOCHAIN},
  {"NOINTERN",     PKCS7_NOINTERN},
  {"NOVERIFY",     PKCS7_NOVERIFY},
  {"DETACHED",     PKCS7_DETACHED},
  {"BINARY",       PKCS7_BINARY},
  {"NOATTR",       PKCS7_NOATTR},
  {"NOSMIMECAP",   PKCS7_NOSMIMECAP},
  {"NOOLDMIMETYPE", PKCS7_NOOLDMIMETYPE},
  {"CRLFEOL",      PKCS7_CRLFEOL},
  {"STREAM",       PKCS7_STREAM},
  {"NOCRL",        PKCS7_NOCRL},
  {"PARTIAL",      PKCS7_PARTIAL},
  {"REUSE_DIGEST", PKCS7_REUSE_DIGEST},

  {NULL,           0}
};

int luaopen_pkcs7(lua_State *L)
{
  int i;
  auxiliar_newclass(L, "openssl.pkcs7", pkcs7_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  for (i = 0; i < sizeof(pkcs7_const) / sizeof(LuaL_Enum) - 1; i++)
  {
    LuaL_Enum e = pkcs7_const[i];
    lua_pushinteger(L, e.val);
    lua_setfield(L, -2, e.name);
  }
  return 1;
}
