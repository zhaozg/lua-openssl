/*--------------------------------------------------------------------------
 * LuaSec 0.5
 *
 * Copyright (C) 2014 Kim Alvefur, Paul Aurich, Tobias Markmann
 *                    Matthew Wild, Bruno Silvestre.
 * Modify by GeorgeZhao, for lua-openssl keep with luasec
 *--------------------------------------------------------------------------*/

static const char* hex_tab = "0123456789abcdef";


/*---------------------------------------------------------------------------*/

/**
 * Convert the buffer 'in' to hexadecimal.
 */
static void to_hex(const char* in, int length, char* out)
{
  int i;
  for (i = 0; i < length; i++) {
    out[i*2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i*2+1] = hex_tab[(in[i]) & 0xF];
  }
}

/**
 * Converts the ASN1_OBJECT into a textual representation and put it
 * on the Lua stack.
 */
static void push_asn1_objname(lua_State* L, ASN1_OBJECT *object, int no_name)
{
  char buffer[256];
  int len = OBJ_obj2txt(buffer, sizeof(buffer), object, no_name);
  len = (len < sizeof(buffer)) ? len : sizeof(buffer);
  lua_pushlstring(L, buffer, len);
}

/**
 * Push the ASN1 string on the stack.
 */

static void push_asn1_string(lua_State* L, ASN1_STRING *string, int utf8)
{
  int len;
  unsigned char *data;
  if (!string)
    lua_pushnil(L);
  if (utf8) {
    len = ASN1_STRING_to_UTF8(&data, string);
    if (len >= 0) {
      lua_pushlstring(L, (char*)data, len);
      OPENSSL_free(data);
    }else
      lua_pushnil(L);
  } else {
    lua_pushlstring(L, (char*)ASN1_STRING_data(string),
      ASN1_STRING_length(string));
  }
}

/**
 * Return a human readable time.
 */
static int push_asn1_time(lua_State *L, ASN1_UTCTIME *tm)
{
  char *tmp;
  long size;
  BIO *out = BIO_new(BIO_s_mem());
  ASN1_TIME_print(out, tm);
  size = BIO_get_mem_data(out, &tmp);
  lua_pushlstring(L, tmp, size);
  BIO_free(out);
  return 1;
}

/**
 * 
 */
static int push_subtable(lua_State* L, int idx)
{
  lua_pushvalue(L, -1);
  lua_gettable(L, idx-1);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -2);
    lua_pushvalue(L, -2);
    lua_settable(L, idx-3);
    lua_replace(L, -2); /* Replace key with table */
    return 1;
  }
  lua_replace(L, -2); /* Replace key with table */
  return 0;
}

/**
 * Retrive the general names from the object.
 */
static int push_x509_name(lua_State* L, X509_NAME *name, int encode)
{
  int i;
  int n_entries;
  ASN1_OBJECT *object;
  X509_NAME_ENTRY *entry;
  lua_newtable(L);
  n_entries = X509_NAME_entry_count(name);
  for (i = 0; i < n_entries; i++) {
    entry = X509_NAME_get_entry(name, i);
    object = X509_NAME_ENTRY_get_object(entry);
    lua_newtable(L);
    push_asn1_objname(L, object, 1);
    lua_setfield(L, -2, "oid");
    push_asn1_objname(L, object, 0);
    lua_setfield(L, -2, "name");
    push_asn1_string(L, X509_NAME_ENTRY_get_data(entry), encode);
    lua_setfield(L, -2, "value");
    lua_rawseti(L, -2, i+1);
  }
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * Retrive the Subject from the certificate.
 */
static int meth_subject(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);
  return push_x509_name(L, X509_get_subject_name(cert), utf8);
}

/**
 * Retrive the Issuer from the certificate.
 */
static int meth_issuer(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);
  return push_x509_name(L, X509_get_issuer_name(cert), utf8);
}

/**
 * Retrieve the extensions from the certificate.
 */
int meth_extensions(lua_State* L)
{
  int j;
  int i = -1;
  int n_general_names;
  OTHERNAME *otherName;
  X509_EXTENSION *extension;
  GENERAL_NAME *general_name;
  STACK_OF(GENERAL_NAME) *values;
  X509 *peer = CHECK_OBJECT(1, X509, "openssl.x509");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);

  /* Return (ret) */
  lua_newtable(L);

  while ((i = X509_get_ext_by_NID(peer, NID_subject_alt_name, i)) != -1) {
    extension = X509_get_ext(peer, i);
    if (extension == NULL)
      break;
    values = X509V3_EXT_d2i(extension);
    if (values == NULL)
      break;

    /* Push ret[oid] */
    push_asn1_objname(L, extension->object, 1);
    push_subtable(L, -2);

    /* Set ret[oid].name = name */
    push_asn1_objname(L, extension->object, 0);
    lua_setfield(L, -2, "name");

    n_general_names = sk_GENERAL_NAME_num(values);
    for (j = 0; j < n_general_names; j++) {
      general_name = sk_GENERAL_NAME_value(values, j);
      switch (general_name->type) {
      case GEN_OTHERNAME:
        otherName = general_name->d.otherName;
        push_asn1_objname(L, otherName->type_id, 1);
        if (push_subtable(L, -2)) {
          push_asn1_objname(L, otherName->type_id, 0);
          lua_setfield(L, -2, "name");
        }
        push_asn1_string(L, otherName->value->value.asn1_string, utf8);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_DNS:
        lua_pushstring(L, "dNSName");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.dNSName, utf8);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_EMAIL:
        lua_pushstring(L, "rfc822Name");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.rfc822Name, utf8);
        lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
        lua_pop(L, 1);
        break;
      case GEN_URI:
        lua_pushstring(L, "uniformResourceIdentifier");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.uniformResourceIdentifier, utf8);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_IPADD:
        lua_pushstring(L, "iPAddress");
        push_subtable(L, -2);
        push_asn1_string(L, general_name->d.iPAddress, utf8);
        lua_rawseti(L, -2, lua_rawlen(L, -2)+1);
        lua_pop(L, 1);
        break;
      case GEN_X400:
        /* x400Address   */
        /* not supported */
        break;
      case GEN_DIRNAME:
        /* directoryName */
        /* not supported */
        break;
      case GEN_EDIPARTY:
        /* ediPartyName */
        /* not supported */
        break;
      case GEN_RID:
        /* registeredID  */
        /* not supported */
        break;
      }
    }
    lua_pop(L, 1); /* ret[oid] */
    i++;           /* Next extension */
  }
  return 1;
}

/**
 * Convert the certificate to PEM format.
 */
static int meth_pem(lua_State* L)
{
  char* data;
  long bytes;
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_X509(bio, cert)) {
    lua_pushnil(L);
    return 1;
  }
  bytes = BIO_get_mem_data(bio, &data);
  if (bytes > 0)
    lua_pushlstring(L, data, bytes);
  else
    lua_pushnil(L);
  BIO_free(bio);
  return 1;
}

/**
 * Extract public key in PEM format.
 */
static int meth_pubkey(lua_State* L)
{
  char* data;
  long bytes;
  int ret = 1;
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  BIO *bio = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if(PEM_write_bio_PUBKEY(bio, pkey)) {
    bytes = BIO_get_mem_data(bio, &data);
    if (bytes > 0) {
      lua_pushlstring(L, data, bytes);
      switch(EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
          lua_pushstring(L, "RSA");
          break;
        case EVP_PKEY_DSA:
          lua_pushstring(L, "DSA");
          break;
        case EVP_PKEY_DH:
          lua_pushstring(L, "DH");
          break;
        case EVP_PKEY_EC:
          lua_pushstring(L, "EC");
          break;
        default:
          lua_pushstring(L, "Unknown");
          break;
      }
      lua_pushinteger(L, EVP_PKEY_bits(pkey));
      ret = 3;
    }
    else
      lua_pushnil(L);
  }
  else
    lua_pushnil(L);
  /* Cleanup */
  BIO_free(bio);
  EVP_PKEY_free(pkey);
  return ret;
}

/**
 * Compute the fingerprint.
 */
static int meth_digest(lua_State* L)
{
  unsigned int bytes;
  const EVP_MD *digest = NULL;
  unsigned char buffer[EVP_MAX_MD_SIZE];
  char hex_buffer[EVP_MAX_MD_SIZE*2];
  X509 *cert = CHECK_OBJECT(1, X509, "openssl.x509");
  const char *str = luaL_optstring(L, 2, NULL);
  if (!str)
    digest = EVP_sha1();
  else {
    if (!strcmp(str, "sha1"))
      digest = EVP_sha1();
    else if (!strcmp(str, "sha256"))
      digest = EVP_sha256();
    else if (!strcmp(str, "sha512"))
      digest = EVP_sha512();
  }
  if (!digest) {
    lua_pushnil(L);
    lua_pushfstring(L, "digest algorithm not supported (%s)", str);
    return 2;
  }
  if (!X509_digest(cert, digest, buffer, &bytes)) {
    lua_pushnil(L);
    lua_pushfstring(L, "error processing the certificate (%s)",
      ERR_reason_error_string(ERR_get_error()));
    return 2;
  }
  to_hex((char*)buffer, bytes, hex_buffer);
  lua_pushlstring(L, hex_buffer, bytes*2);
  return 1;
}

/**
 * Check if the certificate is valid in a given time.
 */
static int meth_valid_at(lua_State* L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  time_t time = luaL_checkinteger(L, 2);
  lua_pushboolean(L, (X509_cmp_time(X509_get_notAfter(cert), &time)     >= 0
                      && X509_cmp_time(X509_get_notBefore(cert), &time) <= 0));
  return 1;
}

/**
 * Return the serial number.
 */
static int meth_serial(lua_State *L)
{
  char *tmp;
  BIGNUM *bn;
  ASN1_INTEGER *serial;
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  serial = X509_get_serialNumber(cert);
  bn = ASN1_INTEGER_to_BN(serial, NULL);
  tmp = BN_bn2hex(bn);
  lua_pushstring(L, tmp);
  BN_free(bn);
  OPENSSL_free(tmp);
  return 1;
}

/**
 * Return not before date.
 */
static int meth_notbefore(lua_State *L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  return push_asn1_time(L, X509_get_notBefore(cert));
}

/**
 * Return not after date.
 */
static int meth_notafter(lua_State *L)
{
  X509* cert = CHECK_OBJECT(1, X509, "openssl.x509");
  return push_asn1_time(L, X509_get_notAfter(cert));
}
