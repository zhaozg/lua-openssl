/*=========================================================================*\
* hamc.c
* hamc module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#if OPENSSL_VERSION_NUMBER > 0x00909000L && !defined (LIBRESSL_VERSION_NUMBER)
#include <openssl/cms.h>

#define MYNAME    "cms"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static LuaL_Enum cms_flags[] =
{
  {"text",    0x1},
  {"nocerts",   0x2},
  {"no_content_verify", 0x04},
  {"no_attr_verify",    0x8},
  {"nosigs",        (CMS_NO_CONTENT_VERIFY | CMS_NO_ATTR_VERIFY)},
  {"nointern",    0x10},
  {"no_signer_cert_verify", 0x20},
  {"noverify",    0x20},
  {"detached",    0x40},
  {"binary",      0x80},
  {"noattr",      0x100},
  {"nosmimecap",    0x200},
  {"nooldmimetype", 0x400},
  {"crlfeol",     0x800},
  {"stream",      0x1000},
  {"nocrl",     0x2000},
  {"partial",     0x4000},
  {"reuse_digest",  0x8000},
  {"use_keyid",   0x10000},
  {"debug_decrypt", 0x20000},
  {NULL,        -1}
};

static int openssl_cms_read(lua_State *L)
{
  BIO* in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  CMS_ContentInfo *cms = NULL;
  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }
  if (fmt == FORMAT_DER)
  {
    cms = d2i_CMS_bio(in, NULL);
    //CMS_ContentInfo *cms = CMS_ContentInfo_new();
    //int ret = i2d_CMS_bio(bio, cms);
  }
  else if (fmt == FORMAT_PEM)
  {
    cms = PEM_read_bio_CMS(in, NULL, NULL, NULL);
  }
  else if (fmt == FORMAT_SMIME)
  {
    BIO *indata = load_bio_object(L, 3);
    cms = SMIME_read_CMS(in, &indata);
  }

  if (cms)
  {
    PUSH_OBJECT(cms, "openssl.cms");
    return 1;
  }
  return openssl_pushresult(L, 0);
}


static int openssl_cms_write(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO *out = load_bio_object(L, 2);
  BIO *in = load_bio_object(L, 3);
  int flags = luaL_optint(L, 4, 0);
  int fmt = luaL_checkoption(L, 5, "smime", format);
  int ret = 0;

  if (fmt == FORMAT_SMIME)
    ret = SMIME_write_CMS(out, cms, in, flags);
  else if (fmt == FORMAT_PEM)
    ret = PEM_write_bio_CMS_stream(out, cms, in, flags);
  else if (fmt == FORMAT_DER)
  {
    ret = i2d_CMS_bio_stream(out, cms, in, flags);
    //i2d_CMS_bio
  }
  else
    luaL_argerror(L, 5, "only accept smime, pem or der");
  return openssl_pushresult(L, ret);
}

static int openssl_cms_create(lua_State*L)
{
  CMS_ContentInfo *cms = NULL;

  if (lua_gettop(L) == 1)
  {
    cms = CMS_ContentInfo_new();
  }
  else
  {
    BIO* in = load_bio_object(L, 1);
    if (lua_isuserdata(L, 2))
    {
      const EVP_MD* md = get_digest(L, 2);
      int flags = luaL_optint(L, 3, 0);
      cms = CMS_digest_create(in, md, flags);
    }
    else
    {
      int flags = luaL_optint(L, 2, 0);
      cms = CMS_data_create(in, flags);
    }
  }

  PUSH_OBJECT(cms, "openssl.cms");
  return 1;
}


static int openssl_cms_compress(lua_State *L)
{
  BIO* in = load_bio_object(L, 1);
  int nid = NID_undef;
  unsigned int flags = 0;
  const char* compress_options[] =
  {
    "zlib",
    "rle",
    NULL
  };
  CMS_ContentInfo *cms;
  nid = luaL_checkoption(L, 2, "zlib", compress_options);
  flags = luaL_optint(L, 3, 0);

  cms = CMS_compress(in, nid, flags);

  if (cms)
  {
    PUSH_OBJECT(cms, "openssl.cms");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int openssl_cms_uncompress(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO *in = load_bio_object(L, 2);
  BIO *out = load_bio_object(L, 3);
  int flags = luaL_optint(L, 4, 0);

  int ret = CMS_uncompress(cms, in, out, flags);
  return openssl_pushresult(L, ret);
}

static int openssl_cms_sign(lua_State *L)
{
  X509* signcert = CHECK_OBJECT(1, X509, "openssl.x509");
  EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509)* certs = (STACK_OF(X509)*)openssl_sk_x509_fromtable(L, 3);
  BIO* data = load_bio_object(L, 4);
  unsigned int flags = luaL_optint(L, 5, 0);
  CMS_ContentInfo *cms;

  cms = CMS_sign(signcert, pkey, certs, data, flags);
  if (cms)
  {
    PUSH_OBJECT(cms, "openssl.cms");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int openssl_cms_verify(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  static const char* verify_mode[] =
  {
    "verify",  /* 0 */
    "digest",  /* 1 */
    "receipt",   /* 2 */
    NULL
  };
  int mode = luaL_checkoption(L, 2, NULL, verify_mode);
  if (mode == 1)
  {
    BIO* in = load_bio_object(L, 3);
    BIO* out = load_bio_object(L, 4);
    unsigned int flags = luaL_optint(L, 5, 0);

    int ret = CMS_digest_verify(cms, in, out, flags);
    return openssl_pushresult(L, ret);
  }
  if (mode == 2)
  {
    CMS_ContentInfo *src = CHECK_OBJECT(3, CMS_ContentInfo, "openssl.cms");
    STACK_OF(X509) *other = (STACK_OF(X509)*)openssl_sk_x509_fromtable(L, 4);
    X509_STORE* store = CHECK_OBJECT(5, X509_STORE, "openssl.x509_store");
    unsigned int flags = luaL_optint(L, 6, 0);
    int ret = CMS_verify_receipt(cms, src, other, store, flags);
    return openssl_pushresult(L, ret);
  }
  if (mode == 0)
  {
    STACK_OF(X509) *other = (STACK_OF(X509) *)openssl_sk_x509_fromtable(L, 3);
    X509_STORE* store = CHECK_OBJECT(4, X509_STORE, "openssl.x509_store");
    BIO* in = load_bio_object(L, 5);
    BIO* out = load_bio_object(L, 6);
    unsigned int flags = luaL_optint(L, 7, 0);
    int ret = CMS_verify(cms, other, store, in, out, flags);
    return openssl_pushresult(L, ret);
  }

  return 0;
}


static int openssl_cms_EncryptedData_encrypt(lua_State*L)
{
  BIO* in = load_bio_object(L, 1);
  const EVP_CIPHER* ciphers = get_cipher(L, 2, NULL);
  size_t klen;
  const char* key = luaL_checklstring(L, 3, &klen);
  unsigned int flags = luaL_optint(L, 4, 0);

  CMS_ContentInfo *cms = CMS_EncryptedData_encrypt(in, ciphers, (const unsigned char*) key, klen, flags);
  if (cms)
  {
    PUSH_OBJECT(cms, "openssl.cms");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int openssl_cms_EncryptedData_decrypt(lua_State*L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  size_t klen;
  const char* key = luaL_checklstring(L, 2, &klen);
  BIO* dcont = load_bio_object(L, 3);
  BIO* out = load_bio_object(L, 4);
  unsigned int flags = luaL_optint(L, 5, 0);

  int ret = CMS_EncryptedData_decrypt(cms, (const unsigned char*)key, klen, dcont, out, flags);

  return openssl_pushresult(L, ret);
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

static int openssl_cms_encrypt(lua_State *L)
{
  STACK_OF(X509)* encerts = (STACK_OF(X509)*)openssl_sk_x509_fromtable(L, 1);
  BIO* in = load_bio_object(L, 2);
  const EVP_CIPHER* ciphers = get_cipher(L, 3, NULL);
  unsigned int flags = luaL_optint(L, 4, 0);
  int ret = 0;
  CMS_ContentInfo *cms = CMS_encrypt(encerts, in, ciphers, flags);
  CMS_RecipientInfo *recipient;
  if (cms)
  {
    if (lua_istable(L, 5))
    {
      lua_getfield(L, 5, "key");
      lua_getfield(L, 5, "keyid");
      if (lua_isstring(L, -1) && lua_isstring(L, -2))
      {
        size_t keylen, keyidlen;

        const char* key = luaL_checklstring(L, -2, &keylen);
        const char* keyid = luaL_checklstring(L, -1, &keyidlen);

        key = memdup(key, keylen);
        keyid =  memdup(keyid, keyidlen);

        recipient = CMS_add0_recipient_key(cms, NID_undef,
                                           (unsigned char*)key, keylen,
                                           (unsigned char*)keyid, keyidlen,
                                           NULL, NULL, NULL);
        if (!recipient)
          ret = 0;
      }
      else if (!lua_isnil(L, -1) || !lua_isnil(L, -2))
      {
        luaL_argerror(L, 5, "key and keyid field must be string");
      }
      else
        ret = 1;
      lua_pop(L, 2);

      if (ret)
      {
        lua_getfield(L, 5, "password");
        if (lua_isstring(L, -1))
        {
          unsigned char*passwd = (unsigned char*)lua_tostring(L, -1);
          recipient = CMS_add0_recipient_password(cms,
                                                  -1, NID_undef, NID_undef,
                                                  passwd, -1, NULL);
          if (!recipient)
            ret = 0;
        }
        else if (!lua_isnil(L, -1))
        {
          luaL_argerror(L, 5, "password field must be string");
        }
        lua_pop(L, 1);
      }
    }

    if (ret)
    {
      if (flags & CMS_STREAM)
        ret = CMS_final(cms, in, NULL, flags);
    }
  }
  if (ret)
  {
    PUSH_OBJECT(cms, "openssl.cms");
    return 1;
  }
  return openssl_pushresult(L, ret);
}

static int openssl_cms_decrypt(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  X509* x509 = CHECK_OBJECT(3, X509, "openssl.x509");
  BIO* dcont = load_bio_object(L, 4);
  BIO* out = load_bio_object(L, 5);
  unsigned int flags = luaL_optint(L, 6, 0);
  int ret = 1;

  if (lua_istable(L, 7))
  {
    lua_getfield(L, 7, "password");
    if (lua_isstring(L, -1))
    {
      unsigned char*passwd = (unsigned char*)lua_tostring(L, -1);
      ret = CMS_decrypt_set1_password(cms, passwd, -1);
    }
    else if (!lua_isnil(L, -1))
    {
      luaL_argerror(L, 7, "password field must be string");
    }
    lua_pop(L, 1);
    if (ret)
    {
      lua_getfield(L, 7, "key");
      lua_getfield(L, 7, "keyid");
      if (lua_isstring(L, -1) && lua_isstring(L, -2))
      {
        size_t keylen, keyidlen;
        unsigned char*key = (unsigned char*)lua_tolstring(L, -2, &keylen);
        unsigned char*keyid = (unsigned char*)lua_tolstring(L, -1, &keyidlen);
        ret = CMS_decrypt_set1_key(cms, key, keylen, keyid, keyidlen);
      }
      else if (!lua_isnil(L, -1) || !lua_isnil(L, -2))
      {
        luaL_argerror(L, 7, "key and keyid field must be string");
      }
      lua_pop(L, 2);
    }
  }

  if (ret)
  {
    ret = CMS_decrypt_set1_pkey(cms, pkey, x509);
  }

  if (ret == 1)
    ret = CMS_decrypt(cms, NULL, NULL, dcont, out, flags);
  return openssl_pushresult(L, ret);
}


/************************************************************************/
static int openssl_cms_type(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  const ASN1_OBJECT *obj = CMS_get0_type(cms);
  PUSH_OBJECT(obj, "openssl.object");

  return 1;
}

static int openssl_cms_bio_new(lua_State*L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO* out = lua_isnoneornil(L, 2) ? NULL : load_bio_object(L, 2);
  out = BIO_new_CMS(out, cms);
  PUSH_OBJECT(out, "openssl.bio");
  return 1;
}

static int openssl_cms_datainit(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO* icont = load_bio_object(L, 2);
  icont = CMS_dataInit(cms, icont);
  PUSH_OBJECT(icont, "openssl.bio");
  return 1;
}

static int openssl_cms_datafinal(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO* bio = load_bio_object(L, 2);
  int ret = CMS_dataFinal(cms, bio);
  lua_pushboolean(L, ret);
  return 1;
}

static int openssl_cms_detached(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  int ret = 0;
  if (lua_isnone(L, 2))
  {
    ret = CMS_is_detached(cms);
  }
  else
  {
    int detached = auxiliar_checkboolean(L, 2);
    ret = CMS_set_detached(cms, detached);
  }
  lua_pushboolean(L, ret);
  return 1;
}

static int openssl_cms_content(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  ASN1_OCTET_STRING** content = CMS_get0_content(cms);
  if (content && *content)
  {

    lua_pushnil(L);
    return 1;
  }
  lua_pushnil(L);
  return 1;
}
static int openssl_cms_get_signers(lua_State*L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  STACK_OF(X509) *signers = CMS_get0_signers(cms);
  if (signers)
  {
    openssl_sk_x509_totable(L, signers);
    return 1;
  }
  return 0;
}
static int openssl_cms_data(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO *out = load_bio_object(L, 2);
  unsigned int flags = luaL_optint(L, 3, 0);
  int ret = CMS_data(cms, out, flags);
  return openssl_pushresult(L, ret);
}


static int openssl_cms_final(lua_State*L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  BIO* in = load_bio_object(L, 2);
  int flags = luaL_optint(L, 3, 0);

  int ret = CMS_final(cms, in, NULL, flags);
  return openssl_pushresult(L, ret);
}

static int openssl_cms_sign_receipt(lua_State*L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  X509 *signcert = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY* pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509) *other = (STACK_OF(X509)*)openssl_sk_x509_fromtable(L, 4);
  unsigned int flags = luaL_optint(L, 5, 0);

  STACK_OF(CMS_SignerInfo) *sis = CMS_get0_SignerInfos(cms);
  if (sis)
  {
    CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sis, 0);
    CMS_ContentInfo *srcms = CMS_sign_receipt(si, signcert, pkey, other, flags);
    if (srcms)
    {
      PUSH_OBJECT(srcms, "openssl.cms");
      return 1;
    }
  }
  return openssl_pushresult(L, 0);
}

static int openssl_cms_free(lua_State *L)
{
  CMS_ContentInfo *cms = CHECK_OBJECT(1, CMS_ContentInfo, "openssl.cms");
  CMS_ContentInfo_free(cms);

  return 0;
}

static luaL_Reg cms_ctx_funs[] =
{
  {"type",  openssl_cms_type},
  {"datainit",  openssl_cms_datainit},
  {"datafinal", openssl_cms_datafinal},
  {"content", openssl_cms_content},
  {"data",  openssl_cms_data},
  {"signers", openssl_cms_get_signers},

  {"detached",  openssl_cms_detached},

  { "sign_receipt",  openssl_cms_sign_receipt},
  { "get_signers",   openssl_cms_get_signers},

  { "bio_new",   openssl_cms_bio_new},

  {"final", openssl_cms_final},
  {"__tostring",  auxiliar_tostring},
  {"__gc",    openssl_cms_free},
  {NULL, NULL}
};

/* int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms); */
static const luaL_Reg R[] =
{
  { "read",  openssl_cms_read},
  { "write",   openssl_cms_write},

  { "bio_new", openssl_cms_bio_new},
  { "create", openssl_cms_create},

  { "sign",  openssl_cms_sign},
  { "verify",  openssl_cms_verify},
  { "encrypt",   openssl_cms_encrypt},
  { "decrypt",   openssl_cms_decrypt},

  { "EncryptedData_encrypt",   openssl_cms_EncryptedData_encrypt},
  { "EncryptedData_decrypt",   openssl_cms_EncryptedData_decrypt},
  { "compress",  openssl_cms_compress},
  { "uncompress",  openssl_cms_uncompress},

  {NULL,  NULL}
};
#endif

int luaopen_cms(lua_State *L)
{
#if OPENSSL_VERSION_NUMBER > 0x00909000L && !defined (LIBRESSL_VERSION_NUMBER)
  ERR_load_CMS_strings();

  auxiliar_newclass(L, "openssl.cms",  cms_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
#else
  lua_pushnil(L);
#endif
  return 1;
}
