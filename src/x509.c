/*=========================================================================*\
* x509.c
* x509 modules for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#define CRYPTO_LOCK_REF
#include "sk.h"

#define MYNAME    "x509"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

int openssl_push_general_name(lua_State*L, const GENERAL_NAME* general_name)
{
  lua_newtable(L);

  switch (general_name->type)
  {
  case GEN_OTHERNAME:
  {
    OTHERNAME *otherName = general_name->d.otherName;
    lua_newtable(L);
    openssl_push_asn1object(L, otherName->type_id);
    PUSH_ASN1_STRING(L, otherName->value->value.asn1_string);
    lua_settable(L, -3);
    lua_setfield(L, -2, "otherName");

    lua_pushstring(L, "otherName");
    lua_setfield(L, -2, "type");
    break;
  }
  case GEN_EMAIL:
    PUSH_ASN1_STRING(L, general_name->d.rfc822Name);
    lua_setfield(L, -2, "rfc822Name");

    lua_pushstring(L, "rfc822Name");
    lua_setfield(L, -2, "type");
    break;
  case GEN_DNS:
    PUSH_ASN1_STRING(L, general_name->d.dNSName);
    lua_setfield(L, -2, "dNSName");
    lua_pushstring(L, "dNSName");
    lua_setfield(L, -2, "type");
    break;
  case GEN_X400:
    openssl_push_asn1type(L, general_name->d.x400Address);
    lua_setfield(L, -2, "x400Address");
    lua_pushstring(L, "x400Address");
    lua_setfield(L, -2, "type");
    break;
  case GEN_DIRNAME:
  {
    X509_NAME* xn = general_name->d.directoryName;
    openssl_push_xname_asobject(L, xn);
    lua_setfield(L, -2, "directoryName");
    lua_pushstring(L, "directoryName");
    lua_setfield(L, -2, "type");
  }
  break;
  case GEN_URI:
    PUSH_ASN1_STRING(L, general_name->d.uniformResourceIdentifier);
    lua_setfield(L, -2, "uniformResourceIdentifier");
    lua_pushstring(L, "uniformResourceIdentifier");
    lua_setfield(L, -2, "type");
    break;
  case GEN_IPADD:
    lua_newtable(L);
    PUSH_ASN1_OCTET_STRING(L, general_name->d.iPAddress);
    lua_setfield(L, -2, "iPAddress");
    lua_pushstring(L, "iPAddress");
    lua_setfield(L, -2, "type");
    break;
  case GEN_EDIPARTY:
    lua_newtable(L);
    PUSH_ASN1_STRING(L, general_name->d.ediPartyName->nameAssigner);
    lua_setfield(L, -2, "nameAssigner");
    PUSH_ASN1_STRING(L, general_name->d.ediPartyName->partyName);
    lua_setfield(L, -2, "partyName");
    lua_setfield(L, -2, "ediPartyName");

    lua_pushstring(L, "ediPartyName");
    lua_setfield(L, -2, "type");
    break;
  case GEN_RID:
    lua_newtable(L);
    openssl_push_asn1object(L, general_name->d.registeredID);
    lua_setfield(L, -2, "registeredID");
    lua_pushstring(L, "registeredID");
    lua_setfield(L, -2, "type");
    break;
  default:
    lua_pushstring(L, "unsupport");
    lua_setfield(L, -2, "type");
  }
  return 1;
};

static int check_cert(X509_STORE *ca, X509 *x, STACK_OF(X509) *untrustedchain, int purpose)
{
  int ret = 0;
  X509_STORE_CTX *csc = X509_STORE_CTX_new();
  if (csc)
  {
    X509_STORE_set_flags(ca, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (X509_STORE_CTX_init(csc, ca, x, untrustedchain) == 1)
    {
      if (purpose > 0)
      {
        X509_STORE_CTX_set_purpose(csc, purpose);
      }
      ret = X509_verify_cert(csc);
      if (ret == 1)
        ret = X509_V_OK;
      else
        ret = X509_STORE_CTX_get_error(csc);
    }
    X509_STORE_CTX_free(csc);
    return ret;
  }

  return X509_V_ERR_OUT_OF_MEM;
}

static LUA_FUNCTION(openssl_x509_read)
{
  X509 *cert = NULL;
  BIO *in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }

  if (fmt == FORMAT_DER)
  {
    cert = d2i_X509_bio(in, NULL);
  }
  else if (fmt == FORMAT_PEM)
  {
    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
  }

  BIO_free(in);

  if (cert)
  {
    PUSH_OBJECT(cert, "openssl.x509");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static LUA_FUNCTION(openssl_x509_export)
{
  X509 *cert = CHECK_OBJECT(1, X509, "openssl.x509");
  int fmt = luaL_checkoption(L, 2, "pem", format);
  int notext = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L, 3);
  BIO* out = NULL;

  if (fmt != FORMAT_DER && fmt != FORMAT_PEM)
  {
    luaL_argerror(L, 2, "format only accept pem or der");
  }

  out  = BIO_new(BIO_s_mem());
  if (fmt == FORMAT_PEM)
  {
    if (!notext)
    {
      X509_print(out, cert);
    }

    if (PEM_write_bio_X509(out, cert))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }
  else
  {
    if (i2d_X509_bio(out, cert))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }

  BIO_free(out);
  return 1;
};


static LUA_FUNCTION(openssl_x509_parse)
{
  int i;
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  X509_ALGOR* alg = 0;
  lua_newtable(L);

  if (cert->name)
  {
    AUXILIAR_SET(L, -1, "name", cert->name, string);
  }
  AUXILIAR_SET(L, -1, "valid", cert->valid, boolean);
  AUXILIAR_SET(L, -1, "version", X509_get_version(cert), integer);

  openssl_push_xname_asobject(L, X509_get_subject_name(cert));
  lua_setfield(L, -2, "subject");
  openssl_push_xname_asobject(L, X509_get_issuer_name(cert));
  lua_setfield(L, -2, "issuer");
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%08lx", X509_subject_name_hash(cert));
    AUXILIAR_SET(L, -1, "hash", buf, string);
  }

  PUSH_ASN1_INTEGER(L, cert->cert_info->serialNumber);
  lua_setfield(L, -2, "serialNumber");
  PUSH_ASN1_TIME(L, X509_get_notBefore(cert));
  lua_setfield(L, -2, "notBefore");
  PUSH_ASN1_TIME(L, X509_get_notAfter(cert));
  lua_setfield(L, -2, "notAfter");

  alg = X509_ALGOR_dup(cert->sig_alg);
  PUSH_OBJECT(alg, "openssl.x509_algor");
  lua_setfield(L, -2, "sig_alg");

  {
    int l = 0;
    char* tmpstr = (char *)X509_alias_get0(cert, &l);
    if (tmpstr)
    {
      AUXILIAR_SETLSTR(L, -1, "alias", tmpstr, l);
    }
  }

  AUXILIAR_SET(L, -1, "ca", X509_check_ca(cert), boolean);

  lua_newtable(L);
  for (i = 0; i < X509_PURPOSE_get_count(); i++)
  {
    int set;
    X509_PURPOSE *purp = X509_PURPOSE_get0(i);
    int id = X509_PURPOSE_get_id(purp);
    const char * pname = X509_PURPOSE_get0_sname(purp);

    set = X509_check_purpose(cert, id, 0);
    if (set)
    {
      AUXILIAR_SET(L, -1, pname, 1, boolean);
    }
    set = X509_check_purpose(cert, id, 1);
    if (set)
    {
      lua_pushfstring(L, "%s CA", pname);
      pname = lua_tostring(L, -1);
      AUXILIAR_SET(L, -2, pname, 1, boolean);
      lua_pop(L, 1);
    }
  }
  lua_setfield(L, -2, "purposes");

  {
    int n = X509_get_ext_count(cert);
    if (n > 0)
    {
      lua_pushstring(L, "extensions");
      lua_newtable(L);
      for (i = 0; i < n; i++)
      {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        ext = X509_EXTENSION_dup(ext);
        lua_pushinteger(L, i + 1);
        PUSH_OBJECT(ext, "openssl.x509_extension");
        lua_rawset(L, -3);
      }
      lua_rawset(L, -3);
    }
  }

  return 1;
}

static LUA_FUNCTION(openssl_x509_free)
{
  X509 *cert = CHECK_OBJECT(1, X509, "openssl.x509");
  X509_free(cert);
  return 0;
}

static LUA_FUNCTION(openssl_x509_public_key)
{
  X509 *cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
    return 1;
  }
  else
  {
    EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    int ret = X509_set_pubkey(cert, pkey);
    return openssl_pushresult(L, ret);
  }
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
  int err;
  X509 *err_cert;

  /*
  * it is ok to use a self signed certificate This case will catch both
  * the initial ok == 0 and the final ok == 1 calls to this function
  */
  err = X509_STORE_CTX_get_error(ctx);
  if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
    return 1;

  /*
  * BAD we should have gotten an error.  Normally if everything worked
  * X509_STORE_CTX_get_error(ctx) will still be set to
  * DEPTH_ZERO_SELF_....
  */
  if (ok)
  {
    //BIO_printf(bio_err, "error with certificate to be certified - should be self signed\n");
    return 0;
  }
  else
  {
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    //print_name(bio_err, NULL, X509_get_subject_name(err_cert), 0);
    //BIO_printf(bio_err, "error with certificate - error %d at depth %d\n%s\n", err, X509_STORE_CTX_get_error_depth(ctx), X509_verify_cert_error_string(err));
    return 1;
  }
}

static LUA_FUNCTION(openssl_x509_check)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (auxiliar_isclass(L, "openssl.evp_pkey", 2))
  {
    EVP_PKEY * key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    lua_pushboolean(L, X509_check_private_key(cert, key));
    return 1;
  }
  else
  {
    X509_STORE* store = CHECK_OBJECT(2, X509_STORE, "openssl.x509_store");
    STACK_OF(X509)* untrustedchain = lua_isnoneornil(L, 3) ?  NULL : openssl_sk_x509_fromtable(L, 3);
    int purpose = 0;
    int ret = 0;
    if (!lua_isnone(L, 4)) {
      int purpose_id = X509_PURPOSE_get_by_sname((char*)luaL_optstring(L, 4, "any"));
      if (purpose_id >= 0) {
        X509_PURPOSE* ppurpose = X509_PURPOSE_get0(purpose_id);
        if (ppurpose) {
          purpose = ppurpose->purpose;
        }
      }
    }
#if 0
    X509_STORE_set_verify_cb_func(store, verify_cb);
#endif
    ret = check_cert(store, cert, untrustedchain, purpose);
    lua_pushboolean(L, ret == X509_V_OK);
    lua_pushinteger(L, ret);

    return 2;
  }
}

#if OPENSSL_VERSION_NUMBER > 0x10002000L
static LUA_FUNCTION(openssl_x509_check_host)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isstring(L, 2))
  {
    const char *hostname = lua_tostring(L, 2);
    lua_pushboolean(L, X509_check_host(cert, hostname, strlen(hostname), 0, NULL));
  } else {
    lua_pushboolean(L, 0);
  }
  return 1;
}

static LUA_FUNCTION(openssl_x509_check_email)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isstring(L, 2))
  {
    const char *email = lua_tostring(L, 2);
    lua_pushboolean(L, X509_check_email(cert, email, strlen(email), 0));
  } else {
    lua_pushboolean(L, 0);
  }
  return 1;
}

static LUA_FUNCTION(openssl_x509_check_ip_asc)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isstring(L, 2))
  {
    const char *ip_asc = lua_tostring(L, 2);
    lua_pushboolean(L, X509_check_ip_asc(cert, ip_asc, 0));
  } else {
    lua_pushboolean(L, 0);
  }
  return 1;
}
#endif

IMP_LUA_SK(X509, x509)

static STACK_OF(X509) * load_all_certs_from_file(BIO *in)
{
  STACK_OF(X509) *stack = sk_X509_new_null();
  if (stack)
  {
    STACK_OF(X509_INFO) *sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk))
    {
      X509_INFO *xi = sk_X509_INFO_shift(sk);
      if (xi->x509 != NULL)
      {
        sk_X509_push(stack, xi->x509);
        xi->x509 = NULL;
      }
      X509_INFO_free(xi);
    }
    sk_X509_INFO_free(sk);
  };

  if (sk_X509_num(stack) == 0)
  {
    sk_X509_free(stack);
    stack = NULL;
  }
  return stack;
};

static int openssl_x509_subject(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    X509_NAME* xn = X509_get_subject_name(cert);
    return openssl_push_xname_asobject(L, xn);
  }
  else
  {
    X509_NAME *xn = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
    int ret = X509_set_subject_name(cert, xn);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_x509_issuer(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    X509_NAME* xn = X509_get_issuer_name(cert);
    return openssl_push_xname_asobject(L, xn);
  }
  else
  {
    X509_NAME* xn = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
    int ret = X509_set_issuer_name(cert, xn);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_x509_digest(lua_State* L)
{
  unsigned int bytes;
  unsigned char buffer[EVP_MAX_MD_SIZE];
  char hex_buffer[EVP_MAX_MD_SIZE * 2];
  X509 *cert = CHECK_OBJECT(1, X509, "openssl.x509");
  const EVP_MD *digest = lua_isnoneornil(L, 2) ? EVP_sha1() : get_digest(L, 2);
  int ret;
  if (!digest)
  {
    lua_pushnil(L);
    lua_pushfstring(L, "digest algorithm not supported (%s)", lua_tostring(L, 2));
    return 2;
  }
  ret = X509_digest(cert, digest, buffer, &bytes);
  if (ret)
  {
    to_hex((char*)buffer, bytes, hex_buffer);
    lua_pushlstring(L, hex_buffer, bytes * 2);
    return 1;
  }
  return openssl_pushresult(L, ret);
};

static int openssl_x509_notbefore(lua_State *L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    return PUSH_ASN1_TIME(L, X509_get_notBefore(cert));
  }
  else
  {
    ASN1_TIME* at = NULL;
    int ret = 1;
    if (lua_isnumber(L, 2))
    {
      time_t time = lua_tointeger(L, 2);
      at = ASN1_TIME_new();
      ASN1_TIME_set(at, time);
    }
    else if (lua_isstring(L, 2))
    {
      const char* time = lua_tostring(L, 2);
      at = ASN1_TIME_new();
      if (ASN1_TIME_set_string(at, time) != 1)
      {
        ASN1_TIME_free(at);
        at = NULL;
      }
    }
    if (at)
    {
      ret = X509_set_notBefore(cert, at);
      ASN1_TIME_free(at);
    }
    else
      ret = 0;
    return openssl_pushresult(L, ret);
  };
}

static int openssl_x509_notafter(lua_State *L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    return PUSH_ASN1_TIME(L, X509_get_notAfter(cert));
  }
  else
  {
    ASN1_TIME* at = NULL;
    int ret = 1;
    if (lua_isnumber(L, 2))
    {
      time_t time = lua_tointeger(L, 2);
      at = ASN1_TIME_new();
      ASN1_TIME_set(at, time);
    }
    else if (lua_isstring(L, 2))
    {
      const char* time = lua_tostring(L, 2);
      at = ASN1_TIME_new();
      if (ASN1_TIME_set_string(at, time) != 1)
      {
        ASN1_TIME_free(at);
        at = NULL;
      }
    }
    if (at)
    {
      ret = X509_set_notAfter(cert, at);
      ASN1_TIME_free(at);
    }
    else
      ret = 0;
    return openssl_pushresult(L, ret);
  }
}

static int openssl_x509_valid_at(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    time_t now = 0;;
    time(&now);

    lua_pushboolean(L, (X509_cmp_time(X509_get_notAfter(cert), &now)     >= 0
                        && X509_cmp_time(X509_get_notBefore(cert), &now) <= 0));
    PUSH_ASN1_TIME(L, X509_get_notBefore(cert));
    PUSH_ASN1_TIME(L, X509_get_notAfter(cert));
    return 3;
  }
  else if (lua_gettop(L) == 2)
  {
    time_t time = luaL_checkinteger(L, 2);
    lua_pushboolean(L, (X509_cmp_time(X509_get_notAfter(cert), &time)     >= 0
                        && X509_cmp_time(X509_get_notBefore(cert), &time) <= 0));
    PUSH_ASN1_TIME(L, X509_get_notBefore(cert));
    PUSH_ASN1_TIME(L, X509_get_notAfter(cert));
    return 3;
  }
  else if (lua_gettop(L) == 3)
  {
    time_t before, after;
    ASN1_TIME *ab, *aa;
    int ret = 1;
    before = lua_tointeger(L, 2);
    after  = lua_tointeger(L, 3);

    ab = ASN1_TIME_new();
    aa = ASN1_TIME_new();
    ASN1_TIME_set(ab, before);
    ASN1_TIME_set(aa, after);
    ret = X509_set_notBefore(cert, ab);
    if (ret == 1)
      ret = X509_set_notAfter(cert, aa);

    ASN1_TIME_free(ab);
    ASN1_TIME_free(aa);

    return openssl_pushresult(L, ret);
  }
  return 0;
}

static int openssl_x509_serial(lua_State *L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  ASN1_INTEGER *serial = X509_get_serialNumber(cert);
  if (lua_isboolean(L, 2))
  {
    int asobj = lua_toboolean(L, 2);
    if (asobj)
    {
      PUSH_ASN1_INTEGER(L, serial);
    }
    else
    {
      BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
      PUSH_OBJECT(bn, "openssl.bn");
    }
  }
  else if (lua_isnone(L, 2))
  {
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    char *tmp = BN_bn2hex(bn);
    lua_pushstring(L, tmp);
    OPENSSL_free(tmp);
    BN_free(bn);
  }
  else
  {
    int ret;
    if (auxiliar_isclass(L, "openssl.asn1_string", 2))
    {
      serial = CHECK_OBJECT(2, ASN1_STRING, "openssl.asn1_string");
    }
    else
    {
      BIGNUM *bn = BN_get(L, 2);
      serial = BN_to_ASN1_INTEGER(bn, NULL);
      BN_free(bn);
    }
    luaL_argcheck(L, serial != NULL, 2, "not accept");
    ret = X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    return openssl_pushresult(L, ret);
  }
  return 1;
}

static int openssl_x509_version(lua_State *L)
{
  int version;
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    version = X509_get_version(cert);
    lua_pushinteger(L, version);
    return 1;
  }
  else
  {
    int ret;
    version = luaL_checkint(L, 2);
    ret = X509_set_version(cert, version);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_x509_extensions(lua_State* L)
{
  X509 *peer = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnone(L, 2))
  {
    STACK_OF(X509_EXTENSION) *exts = peer->cert_info->extensions;
    if (exts)
    {
      openssl_sk_x509_extension_totable(L, exts);
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else
  {
    STACK_OF(X509_EXTENSION) *exts = openssl_sk_x509_extension_fromtable(L, 2);
    sk_X509_EXTENSION_pop_free(peer->cert_info->extensions, X509_EXTENSION_free);
    peer->cert_info->extensions = exts;
    return openssl_pushresult(L, 1);
  }
}

static int openssl_x509_new(lua_State* L)
{
  int i = 1;
  int ret = 1;
  int n = lua_gettop(L);
  X509 *x = X509_new();

  ret = X509_set_version(x, 2);
  if (ret == 1 && (
        auxiliar_isclass(L, "openssl.bn", i) ||
        lua_isstring(L, i) || lua_isnumber(L, i)
      ))
  {
    BIGNUM *bn = BN_get(L, i);
    ASN1_INTEGER* ai = BN_to_ASN1_INTEGER(bn, NULL);
    BN_free(bn);
    ret = X509_set_serialNumber(x, ai);
    ASN1_INTEGER_free(ai);
    i++;
  }

  for (; i <= n; i++)
  {
    if (ret == 1 && auxiliar_isclass(L, "openssl.x509_req", i))
    {
      X509_REQ* csr = CHECK_OBJECT(i, X509_REQ, "openssl.x509_req");
      X509_NAME* xn = X509_REQ_get_subject_name(csr);
      ret = X509_set_subject_name(x, xn);

      if (ret == 1)
      {
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(csr);
        int j, n1;
        n1 = sk_X509_EXTENSION_num(exts);
        for (j = 0; ret == 1 && j < n1; j++)
        {
          ret = X509_add_ext(x, sk_X509_EXTENSION_value(exts, j), j);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
      }
      if (ret == 1)
      {
        EVP_PKEY* pkey = X509_REQ_get_pubkey(csr);
        ret = X509_set_pubkey(x, pkey);
        EVP_PKEY_free(pkey);
      }
      i++;
    };

    if (ret == 1 && auxiliar_isclass(L, "openssl.x509_name", i))
    {
      X509_NAME *xn = CHECK_OBJECT(i, X509_NAME, "openssl.x509_name");
      ret = X509_set_subject_name(x, xn);
      i++;
    }
  }

  if (ret == 1)
  {
    PUSH_OBJECT(x, "openssl.x509");
    return 1;
  }
  else
  {
    X509_free(x);
    return openssl_pushresult(L, ret);
  }
};

static int openssl_x509_sign(lua_State*L)
{
  X509* x = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnoneornil(L, 2) && x->cert_info != NULL)
  {
    unsigned char *out = NULL;
    int len = i2d_X509_CINF(x->cert_info, &out);
    if (len > 0)
    {
      lua_pushlstring(L, (const char *)out, len);
      OPENSSL_free(out);
      return 1;
    }
    return openssl_pushresult(L, len);
  }
  else if (auxiliar_isclass(L, "openssl.evp_pkey", 2))
  {
    EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    const EVP_MD *md;
    int ret = 1;
    int i = 3;
    if (auxiliar_isclass(L, "openssl.x509_name", 3))
    {
      X509_NAME* xn = CHECK_OBJECT(3, X509_NAME, "openssl.x509_name");
      ret = X509_set_issuer_name(x, xn);
      i++;
    }
    else
    {
      X509* ca = CHECK_OBJECT(3, X509, "openssl.x509");
      X509_NAME* xn = X509_get_subject_name(ca);
      ret = X509_check_private_key(ca, pkey);
      if (ret == 1)
      {
        ret = X509_set_issuer_name(x, xn);
      }
      i++;
    }

    if (ret == 1)
    {
      md = lua_isnoneornil(L, i) ?
           EVP_get_digestbyname("sha1") :
           get_digest(L, i);
      ret = X509_sign(x, pkey, md);
      if (ret > 0)
        ret = 1;
    }
    return openssl_pushresult(L, ret);
  }
  else
  {
    size_t sig_len;
    const char* sig = luaL_checklstring(L, 2, &sig_len);
    int nid = openssl_get_nid(L, 3);
    int ret = ASN1_BIT_STRING_set(x->signature, (unsigned char*)sig, (int)sig_len);
    if (ret == 1)
    {
      ASN1_OBJECT *obj = OBJ_nid2obj(nid);
      ret = X509_ALGOR_set0(x->sig_alg, obj, V_ASN1_UNDEF, NULL);
    }
    return openssl_pushresult(L, ret);
  }
}

static int openssl_x509_verify(lua_State*L)
{
  X509* x = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isnoneornil(L, 2) && x->cert_info != NULL)
  {
    unsigned char *out = NULL;
    int len = i2d_X509_CINF(x->cert_info, &out);
    if (len > 0)
    {
      lua_pushlstring(L, (const char *)out, len);
      OPENSSL_free(out);
      if (x->signature != NULL)
      {
        lua_pushlstring(L, (const char *)x->signature->data, x->signature->length);
      }
      else
        lua_pushnil(L);
      if (x->sig_alg) {
        X509_ALGOR *alg = X509_ALGOR_dup(x->sig_alg);
        PUSH_OBJECT(alg, "openssl.x509_algor");
      }
      else
        lua_pushnil(L);
      return 3;
    }
    return openssl_pushresult(L, len);
  }
  else
  {
    EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    int ret = X509_verify(x, pkey);
    return openssl_pushresult(L, ret);
  }
}

static luaL_Reg x509_funcs[] =
{
  {"parse",       openssl_x509_parse},
  {"export",      openssl_x509_export},
  {"check",       openssl_x509_check},
#if OPENSSL_VERSION_NUMBER > 0x10002000L
  {"check_host",  openssl_x509_check_host},
  {"check_email", openssl_x509_check_email},
  {"check_ip_asc",openssl_x509_check_ip_asc},
#endif
  {"pubkey",      openssl_x509_public_key},
  {"version",     openssl_x509_version},

  {"__gc",        openssl_x509_free},
  {"__tostring",  auxiliar_tostring},

  /* compat with luasec */
  {"digest",     openssl_x509_digest},
  {"extensions", openssl_x509_extensions},
  {"issuer",     openssl_x509_issuer},
  {"notbefore",  openssl_x509_notbefore},
  {"notafter",   openssl_x509_notafter},
  {"serial",     openssl_x509_serial},
  {"subject",    openssl_x509_subject},
  {"validat",    openssl_x509_valid_at},

  {"sign",       openssl_x509_sign},
  {"verify",     openssl_x509_verify},

  {NULL,      NULL},
};


static int openssl_push_purpose(lua_State*L , X509_PURPOSE* purpose)
{
  lua_newtable(L);

  AUXILIAR_SET(L, -1, "purpose", purpose->purpose, integer);
  AUXILIAR_SET(L, -1, "trust", purpose->trust, integer);
  AUXILIAR_SET(L, -1, "flags", purpose->flags, integer);

  AUXILIAR_SET(L, -1, "name", purpose->name, string);
  AUXILIAR_SET(L, -1, "sname", purpose->sname, string);

  return 1;
};

static int openssl_x509_purpose(lua_State*L)
{
  if (lua_isnoneornil(L, 1))
  {
    int count = X509_PURPOSE_get_count();
    int i;
    lua_newtable(L);
    for (i = 0; i < count; i++)
    {
      X509_PURPOSE* purpose = X509_PURPOSE_get0(i);
      openssl_push_purpose(L, purpose);
      lua_rawseti(L, -2, i + 1);
    }
    return 1;
  }
  else if (lua_isnumber(L, 1))
  {
    int idx = X509_PURPOSE_get_by_id(lua_tointeger(L, 1));
    if (idx >= 0)
    {
      X509_PURPOSE* purpose = X509_PURPOSE_get0(idx);
      openssl_push_purpose(L, purpose);
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else if (lua_isstring(L, 1))
  {
    char* name = (char*)lua_tostring(L, 1);
    int idx = X509_PURPOSE_get_by_sname(name);
    if (idx >= 0)
    {
      X509_PURPOSE* purpose = X509_PURPOSE_get0(idx);
      openssl_push_purpose(L, purpose);
    }
    else
      lua_pushnil(L);
    return 1;
  }
  return 0;
};

static const char* usage_mode[] =
{
  "standard",
  "netscape",
  "extend",
  NULL
};

static int openssl_x509_certtypes(lua_State*L)
{
  int mode = luaL_checkoption(L, 1, "standard", usage_mode);
  int i;
  const BIT_STRING_BITNAME* bitname;

  switch (mode)
  {
  case 0:
  {
    const static BIT_STRING_BITNAME key_usage_type_table[] =
    {
      {0, "Digital Signature", "digitalSignature"},
      {1, "Non Repudiation", "nonRepudiation"},
      {2, "Key Encipherment", "keyEncipherment"},
      {3, "Data Encipherment", "dataEncipherment"},
      {4, "Key Agreement", "keyAgreement"},
      {5, "Certificate Sign", "keyCertSign"},
      {6, "CRL Sign", "cRLSign"},
      {7, "Encipher Only", "encipherOnly"},
      {8, "Decipher Only", "decipherOnly"},
      { -1, NULL, NULL}
    };
    lua_newtable(L);
    for (i = 0, bitname = &key_usage_type_table[i]; bitname->bitnum != -1; i++, bitname = &key_usage_type_table[i])
    {
      openssl_push_bit_string_bitname(L, bitname);
      lua_rawseti(L, -2, i + 1);
    }
    return 1;

  }
  case 1:
  {
    const static BIT_STRING_BITNAME ns_cert_type_table[] =
    {
      {0, "SSL Client", "client"},
      {1, "SSL Server", "server"},
      {2, "S/MIME", "email"},
      {3, "Object Signing", "objsign"},
      {4, "Unused", "reserved"},
      {5, "SSL CA", "sslCA"},
      {6, "S/MIME CA", "emailCA"},
      {7, "Object Signing CA", "objCA"},
      { -1, NULL, NULL}
    };
    lua_newtable(L);
    for (i = 0, bitname = &ns_cert_type_table[i]; bitname->bitnum != -1; i++, bitname = &ns_cert_type_table[i])
    {
      openssl_push_bit_string_bitname(L, bitname);
      lua_rawseti(L, -2, i + 1);
    }
    return 1;
  }
  case 2:
  {
    static const int ext_nids[] =
    {
      NID_server_auth,
      NID_client_auth,
      NID_email_protect,
      NID_code_sign,
      NID_ms_sgc,
      NID_ns_sgc,
      NID_OCSP_sign,
      NID_time_stamp,
      NID_dvcs,
      NID_anyExtendedKeyUsage
    };
    int count = sizeof(ext_nids) / sizeof(int);
    int nid;
    lua_newtable(L);
    for (i = 0; i < count; i++)
    {
      nid = ext_nids[i];
      lua_newtable(L);
      lua_pushstring(L, OBJ_nid2ln(nid));
      lua_setfield(L, -2, "lname");
      lua_pushstring(L, OBJ_nid2sn(nid));
      lua_setfield(L, -2, "sname");
      lua_pushinteger(L, nid);
      lua_setfield(L, -2, "nid");
      lua_rawseti(L, -2, i + 1);
    };
    return 1;
  }
  }
  return 0;
}

static int openssl_verify_cert_error_string(lua_State*L)
{
  int v = luaL_checkint(L, 1);
  const char*s = X509_verify_cert_error_string(v);
  lua_pushstring(L, s);
  return 1;
}

static luaL_Reg R[] =
{
  {"new",           openssl_x509_new },
  {"read",          openssl_x509_read },
  {"purpose",       openssl_x509_purpose },
  {"certtypes",     openssl_x509_certtypes },
  {"verify_cert_error_string", openssl_verify_cert_error_string },

  {NULL,    NULL}
};

int luaopen_x509(lua_State *L)
{
  auxiliar_newclass(L, "openssl.x509", x509_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  openssl_register_xname(L);
  lua_setfield(L, -2, "name");
  openssl_register_xattribute(L);
  lua_setfield(L, -2, "attribute");
  openssl_register_xextension(L);
  lua_setfield(L, -2, "extension");
  openssl_register_xstore(L);
  lua_setfield(L, -2, "store");
  openssl_register_xalgor(L);
  lua_setfield(L, -2, "algor");

  luaopen_x509_req(L);
  lua_setfield(L, -2, "req");
  luaopen_x509_crl(L);
  lua_setfield(L, -2, "crl");

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
