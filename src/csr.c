/*=========================================================================*\
* csr.c
* X509 certificate sign request routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

static LUA_FUNCTION(openssl_csr_read)
{
  BIO * in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  X509_REQ * csr = NULL;

  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }

  if (fmt == FORMAT_PEM)
  {
    csr = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    BIO_reset(in);
  }
  else if (fmt == FORMAT_DER)
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
  return openssl_pushresult(L, 0);
}


static X509 *X509_REQ_to_X509_a(X509_REQ *r, int days, EVP_PKEY *pkey)
{
  X509 *ret = NULL;
  X509_CINF *xi = NULL;
  X509_NAME *xn;
  EVP_PKEY* pubkey;

  if ((ret = X509_new()) == NULL)
  {
    X509err(X509_F_X509_REQ_TO_X509, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* duplicate the request */
  xi = ret->cert_info;

  if (sk_X509_ATTRIBUTE_num(r->req_info->attributes) != 0)
  {
    if ((xi->version = M_ASN1_INTEGER_new()) == NULL) goto err;
    if (!ASN1_INTEGER_set(xi->version, 2)) goto err;
    /*    xi->extensions=ri->attributes; <- bad, should not ever be done
        ri->attributes=NULL; */
  }

  xn = X509_REQ_get_subject_name(r);
  if (X509_set_subject_name(ret, xn) == 0)
    goto err;
  if (X509_set_issuer_name(ret, xn) == 0)
    goto err;

  if (X509_gmtime_adj(xi->validity->notBefore, 0) == NULL)
    goto err;
  if (X509_gmtime_adj(xi->validity->notAfter, (long)60 * 60 * 24 * days) == NULL)
    goto err;
  pubkey = X509_REQ_get_pubkey(r);
  X509_set_pubkey(ret, pubkey);
  EVP_PKEY_free(pubkey);
  if (!X509_sign(ret, pkey, EVP_get_digestbyobj(r->sig_alg->algorithm)))
    goto err;
  if (0)
  {
err:
    X509_free(ret);
    ret = NULL;
  }
  return (ret);
}

static LUA_FUNCTION(openssl_csr_to_x509)
{
  X509_REQ * csr  = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY * pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  int days = luaL_optint(L, 3, 365);
  X509* cert = X509_REQ_to_X509_a(csr, days, pkey);
  if (cert)
  {
    PUSH_OBJECT(cert, "openssl.x509");
    return 1;
  }
  return openssl_pushresult(L, 0);
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

static LUA_FUNCTION(openssl_csr_digest)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  const EVP_MD *md = NULL;
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int len = sizeof(buf);
  int ret;
  if (lua_isnoneornil(L, 2))
    md = EVP_get_digestbyname("SHA1");
  else
    md = get_digest(L, 2);

  ret = X509_REQ_digest(csr, md, buf, &len);
  if (ret == 1)
  {
    lua_pushlstring(L, (const char*)buf, len);
    return 1;
  }
  return openssl_pushresult(L, ret);
};

static LUA_FUNCTION(openssl_csr_check)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  int ret = X509_REQ_check_private_key(csr, pkey);
  return openssl_pushresult(L, ret);
};

static LUA_FUNCTION(openssl_csr_dup)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  csr = X509_REQ_dup(csr);
  PUSH_OBJECT(csr, "openssl.x509_req");
  return 1;
};

static LUA_FUNCTION(openssl_csr_verify)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  EVP_PKEY * self_key = X509_REQ_get_pubkey(csr);
  if (self_key)
  {
    lua_pushboolean(L, X509_REQ_verify(csr, self_key) == 1);
    EVP_PKEY_free(self_key);
  }
  else
    lua_pushboolean(L, 0);
  return 1;
};

static LUA_FUNCTION(openssl_csr_new)
{
  X509_REQ *csr = X509_REQ_new();
  int i;
  int n = lua_gettop(L);
  int ret = X509_REQ_set_version(csr, 0L);

  for (i = 1; ret == 1 && i <= n; i++)
  {
    luaL_argcheck(L,
                  auxiliar_isclass(L, "openssl.x509_name", i) ||
                  auxiliar_isclass(L, "openssl.evp_pkey", i),
                  i, "must be x509_name");
    if (auxiliar_isclass(L, "openssl.x509_name", i))
    {
      X509_NAME * subject = CHECK_OBJECT(i, X509_NAME, "openssl.x509_name");
      ret = X509_REQ_set_subject_name(csr, subject);
    }
    if (auxiliar_isclass(L, "openssl.evp_pkey", i))
    {
      EVP_PKEY *pkey;
      const EVP_MD *md;
      luaL_argcheck(L, i == n || i == n - 1, i, "must is evp_pkey object");

      pkey = CHECK_OBJECT(i, EVP_PKEY, "openssl.evp_pkey");

      if (i == n - 1)
        md = get_digest(L, n);
      else
        md = EVP_get_digestbyname("sha1");

      ret = X509_REQ_set_pubkey(csr, pkey);
      if (ret == 1)
      {
        ret = X509_REQ_sign(csr, pkey, md);
        if (ret > 0)
          ret = 1;
      }
      break;
    }
  };

  if (ret == 1)
    PUSH_OBJECT(csr, "openssl.x509_req");
  else
  {
    X509_REQ_free(csr);
    return openssl_pushresult(L, ret);
  }
  return 1;
}

static LUA_FUNCTION(openssl_csr_sign)
{
  X509_REQ * csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  luaL_argcheck(L, csr->req_info->pubkey, 1, "has not set public key!!!");
  if (auxiliar_isclass(L, "openssl.evp_pkey", 2))
  {
    EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    const EVP_MD* md = lua_isnone(L, 3) ? EVP_get_digestbyname("sha1") : get_digest(L, 3);
    int ret = X509_REQ_sign(csr, pkey, md);
    if (ret > 0)
      ret = 1;
    return openssl_pushresult(L, ret);
  }
  else if (lua_isstring(L, 2))
  {
    size_t siglen;
    const unsigned char* sigdata = (const unsigned char*)luaL_checklstring(L, 2, &siglen);
    const EVP_MD* md = get_digest(L, 3);

    /* (pkey->ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL) ? V_ASN1_NULL : V_ASN1_UNDEF, */
    X509_ALGOR_set0(csr->sig_alg, OBJ_nid2obj(md->pkey_type), V_ASN1_NULL, NULL);

    if (csr->signature->data != NULL)
      OPENSSL_free(csr->signature->data);
    csr->signature->data = OPENSSL_malloc(siglen);
    memcpy(csr->signature->data, sigdata, siglen);
    csr->signature->length = siglen;
    /*
    * In the interests of compatibility, I'll make sure that the bit string
    * has a 'not-used bits' value of 0
    */
    csr->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    csr->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    lua_pushboolean(L, 1);
    return 1;
  }
  else
  {
    unsigned char* tosign = NULL;
    const ASN1_ITEM *it = ASN1_ITEM_rptr(X509_REQ_INFO);
    int inl = ASN1_item_i2d((void*)csr->req_info, &tosign, it);
    if (inl > 0 && tosign)
    {
      lua_pushlstring(L, (const char*)tosign, inl);
      OPENSSL_free(tosign);
      return 1;
    }
    return openssl_pushresult(L, 0);
  }
}

static LUA_FUNCTION(openssl_csr_parse)
{
  X509_REQ * csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");

  X509_NAME * subject = X509_REQ_get_subject_name(csr);
  STACK_OF(X509_EXTENSION) *exts  = X509_REQ_get_extensions(csr);

  lua_newtable(L);

  openssl_push_asn1(L, csr->signature, V_ASN1_BIT_STRING);
  lua_setfield(L, -2, "signature");

  openssl_push_x509_algor(L, csr->sig_alg);
  lua_setfield(L, -2, "sig_alg");

  lua_newtable(L);
  AUXILIAR_SET(L, -1, "version", X509_REQ_get_version(csr), integer);
  openssl_push_xname_asobject(L, subject);
  lua_setfield(L, -2, "subject");
  if (exts)
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, exts);
    lua_rawset(L, -3);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  }

  {
    X509_REQ_INFO* ri = csr->req_info;
    int i, c;
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(csr);

    lua_newtable(L);
    c = X509_REQ_get_attr_count(csr);
    if (c > 0)
    {
      lua_newtable(L);
      for (i = 0; i < c ; i++)
      {
        X509_ATTRIBUTE *attr = X509_REQ_get_attr(csr, i);
        attr = X509_ATTRIBUTE_dup(attr);
        PUSH_OBJECT(attr, "openssl.x509_attribute");
        lua_rawseti(L, -2, i + 1);
      }
      lua_setfield(L, -2, "attributes");
    }

    lua_newtable(L);
    openssl_push_asn1object(L, ri->pubkey->algor->algorithm);
    lua_setfield(L, -2, "algorithm");

    AUXILIAR_SETOBJECT(L, pubkey , "openssl.evp_pkey", -1, "pubkey");
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

static LUA_FUNCTION(openssl_csr_public)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  if (lua_isnone(L, 2))
  {
    EVP_PKEY *pkey = X509_REQ_get_pubkey(csr);
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
    return 1;
  }
  else
  {
    EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    int ret = X509_REQ_set_pubkey(csr, pkey);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_csr_version)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, X509_REQ_get_version(csr));
    return 1;
  }
  else
  {
    long version = luaL_checkint(L, 2);
    int ret = X509_REQ_set_version(csr, version);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_csr_subject)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  if (lua_isnone(L, 2))
  {
    X509_NAME *xn = X509_REQ_get_subject_name(csr);
    if (xn)
      openssl_push_xname_asobject(L, xn);
    else
      lua_pushnil(L);
    return 1;
  }
  else
  {
    X509_NAME* xn = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
    int ret = X509_REQ_set_subject_name(csr, xn);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_csr_extensions)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  if (lua_isnone(L, 2))
  {
    STACK_OF(X509_EXTENSION) *sk = X509_REQ_get_extensions(csr);
    if (sk)
    {
      openssl_sk_x509_extension_totable(L, sk);
      sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else
  {
    STACK_OF(X509_EXTENSION) *sk = openssl_sk_x509_extension_fromtable(L, 2);
    int ret = X509_REQ_add_extensions(csr, sk);
    sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_csr_attribute)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  if (auxiliar_isclass(L, "openssl.x509_attribute", 2))
  {
    X509_ATTRIBUTE *attr = CHECK_OBJECT(2, X509_ATTRIBUTE, "openssl.x509_attribute");
    int ret = X509_REQ_add1_attr(csr, attr);
    return openssl_pushresult(L, ret);
  }
  else if (lua_isnumber(L, 2))
  {
    int loc = luaL_checkint(L, 2);
    X509_ATTRIBUTE *attr = NULL;
    if (lua_isnone(L, 3))
    {
      attr = X509_REQ_get_attr(csr, loc);
      attr = X509_ATTRIBUTE_dup(attr);
    }
    else if (lua_isnil(L, 3))
    {
      attr = X509_REQ_delete_attr(csr, loc);
    }
    if (attr)
    {
      PUSH_OBJECT(attr, "openssl.x509_attribute");
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else if (lua_istable(L, 2))
  {
    int i;
    int ret = 1;
    int n = lua_rawlen(L, 2);
    for (i = 1; ret == 1 && i <= n; i++)
    {
      X509_ATTRIBUTE *attr;
      lua_rawgeti(L, 2, i);
      attr = NULL;
      if (lua_istable(L, -1))
      {
        attr = openssl_new_xattribute(L, &attr, -1, NULL);
        ret = X509_REQ_add1_attr(csr, attr);
        X509_ATTRIBUTE_free(attr);
      }
      else
      {
        attr = CHECK_OBJECT(-1, X509_ATTRIBUTE, "openssl.x509_attribute");
        ret = X509_REQ_add1_attr(csr, attr);
      }
      lua_pop(L, 1);
    }
    openssl_pushresult(L, ret);
    return 1;
  }

  return 0;
}

static LUA_FUNCTION(openssl_csr_attr_count)
{
  X509_REQ *csr = CHECK_OBJECT(1, X509_REQ, "openssl.x509_req");
  lua_pushinteger(L, X509_REQ_get_attr_count(csr));
  return 1;
}

static luaL_Reg csr_cfuns[] =
{
  {"to_x509",           openssl_csr_to_x509},
  {"export",            openssl_csr_export},
  {"parse",             openssl_csr_parse},
  {"digest",            openssl_csr_digest},
  {"verify",            openssl_csr_verify},
  {"check",             openssl_csr_check},
  {"dup",               openssl_csr_dup},
  {"sign",              openssl_csr_sign},

  /* get or set */
  {"public",            openssl_csr_public},
  {"version",           openssl_csr_version},
  {"subject",           openssl_csr_subject},

  /* get or add */
  {"extensions",        openssl_csr_extensions},

  /* get,add or delete */
  {"attribute",         openssl_csr_attribute},
  {"attr_count",        openssl_csr_attr_count},

  {"__tostring",    auxiliar_tostring },
  {"__gc",          openssl_csr_free  },

  {NULL,        NULL  }
};

static luaL_Reg R[] =
{
  {"new",       openssl_csr_new },
  {"read",      openssl_csr_read  },

  {NULL,    NULL}
};

int luaopen_x509_req(lua_State *L)
{
  auxiliar_newclass(L, "openssl.x509_req", csr_cfuns);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  return 1;
}
