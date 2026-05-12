/***
 * pkey core module
 * Core key management, type mapping, and module registration
 *
 * @module pkey
 */
#include "pkey.h"

/* Suppress deprecation warnings for low-level key APIs in OpenSSL 3.0+ */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#ifndef OSSL_NELEM
#define OSSL_NELEM(ary) (sizeof(ary) / sizeof(ary[0]))
#endif

#endif

/* ========================================================================
 * Type mapping: standard_name2type and helpers
 * ======================================================================== */

static const OSSL_ITEM standard_name2type[] = {
#ifdef EVP_PKEY_RSA
  { EVP_PKEY_RSA,     "RSA"      },
#endif
#ifdef EVP_PKEY_RSA_PSS
  { EVP_PKEY_RSA_PSS, "RSA-PSS"  },
#endif
#ifdef EVP_PKEY_EC
  { EVP_PKEY_EC,      "EC"       },
#endif
#ifdef EVP_PKEY_ED25519
  { EVP_PKEY_ED25519, "ED25519"  },
#endif
#ifdef EVP_PKEY_ED448
  { EVP_PKEY_ED448,   "ED448"    },
#endif
#ifdef EVP_PKEY_X25519
  { EVP_PKEY_X25519,  "X25519"   },
#endif
#ifdef EVP_PKEY_X448
  { EVP_PKEY_X448,    "X448"     },
#endif
#ifdef EVP_PKEY_SM2
  { EVP_PKEY_SM2,     "SM2"      },
#endif
#ifdef EVP_PKEY_DH
  { EVP_PKEY_DH,      "DH"       },
#endif
#ifdef EVP_PKEY_DHX
  { EVP_PKEY_DHX,     "X9.42 DH" },
#endif
#ifdef EVP_PKEY_DHX
  { EVP_PKEY_DHX,     "DHX"      },
#endif
#ifdef EVP_PKEY_DSA
  { EVP_PKEY_DSA,     "DSA"      },
#endif
};

int
evp_pkey_name2type(const char *name)
{
  size_t i;

  for (i = 0; i < OSSL_NELEM(standard_name2type); i++) {
    if (strcasecmp(name, standard_name2type[i].ptr) == 0) return (int)standard_name2type[i].id;
  }

  return -1;
}

const char *
evp_pkey_type2name(int type)
{
  size_t      i;
  const char *ret = NULL;

  for (i = 0; i < OSSL_NELEM(standard_name2type); i++) {
    if (type == (int)standard_name2type[i].id) {
      ret = standard_name2type[i].ptr;
      break;
    }
  }

  return ret;
}

/* ========================================================================
 * openssl_pkey_free - __gc metamethod
 * ======================================================================== */

/***
 * free EVP_PKEY object
 * @function __gc
 */
int
openssl_pkey_free(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  EVP_PKEY_free(pkey);
  return 0;
}

/* ========================================================================
 * openssl_pkey_bits
 * ======================================================================== */

/***
 * get key bits
 * @function bits
 * @treturn integer key size in bits
 */
int
openssl_pkey_bits(lua_State *L)
{
  EVP_PKEY   *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  lua_Integer ret = EVP_PKEY_bits(pkey);
  lua_pushinteger(L, ret);
  return 1;
}

/* ========================================================================
 * openssl_pkey_mssing_parameters
 * ======================================================================== */

/***
 * check if key parameters are missing
 * @function missing_paramaters
 * @treturn boolean true if key is missing parameters
 */
int
openssl_pkey_mssing_parameters(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int       ret = EVP_PKEY_missing_parameters(pkey);
  lua_pushboolean(L, ret == 1);
  return 1;
}

/* ========================================================================
 * openssl_pkey_is_private1
 * ======================================================================== */

/***
 * return key is private or not
 * @function is_private
 * @treturn boolean ture is private or public key
 */
int
openssl_pkey_is_private1(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int private = openssl_pkey_is_private(pkey);
  luaL_argcheck(L, private == 0 || private == 1, 1, "not support");

  lua_pushboolean(L, private);
  return 1;
}

/* ========================================================================
 * openssl_pkey_get_public
 * ======================================================================== */

/***
 * return public key
 * @function get_public
 * @treturn openssl.evp_pkey pub
 */
int
openssl_pkey_get_public(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int       ret = 0;
  size_t    len;

#if OPENSSL_VERSION_NUMBER > 0x30100000L && !defined(LIBRESSL_VERSION_NUMBER)
  if (EVP_PKEY_id(pkey) == EVP_PKEY_SM2) {
    /* NOTES: bugs in openssl3 for SM2, ugly hack */
    EC_KEY *ec = (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey);
    ec = EC_KEY_dup(ec);
    EC_KEY_set_private_key(ec, NULL);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
    return 1;
  }
#endif

  len = i2d_PUBKEY(pkey, NULL);

  if (len > 0) {
    unsigned char *buf = OPENSSL_malloc(len);

    if (buf != NULL) {
      unsigned char *p = buf;
      EVP_PKEY      *pub = EVP_PKEY_new();
#if OPENSSL_VERSION_NUMBER > 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      EVP_PKEY_copy_parameters(pub, pkey);
#endif
      len = i2d_PUBKEY(pkey, &p);
      p = buf;
      pub = d2i_PUBKEY(&pub, (const unsigned char **)&p, len);
      if (pub) {
        PUSH_OBJECT(pub, "openssl.evp_pkey");
        ret = 1;
      }
      OPENSSL_free(buf);
    }
  }

  return ret;
}

/* ========================================================================
 * openssl_pkey_parse
 * ======================================================================== */

/***
 * get key details as table
 * @function parse
 * @treturn table infos with key bits,pkey,type, pkey may be rsa,dh,dsa, show as table with factor hex
 * encoded bignum
 */
int
openssl_pkey_parse(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int       typ = EVP_PKEY_id(pkey);

  lua_newtable(L);

  AUXILIAR_SET(L, -1, "bits", EVP_PKEY_bits(pkey), integer);
  AUXILIAR_SET(L, -1, "size", EVP_PKEY_size(pkey), integer);
  AUXILIAR_SET(L, -1, "type", evp_pkey_type2name(typ), string);

  switch (typ) {
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA: {
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    PUSH_OBJECT(rsa, "openssl.rsa");
    lua_setfield(L, -2, "rsa");
  } break;
#endif
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA: {
    DSA *dsa = EVP_PKEY_get1_DSA(pkey);
    PUSH_OBJECT(dsa, "openssl.dsa");
    lua_setfield(L, -2, "dsa");
  } break;
#endif
#ifndef OPENSSL_NO_DH
  case EVP_PKEY_DH: {
    DH *dh = EVP_PKEY_get1_DH(pkey);
    PUSH_OBJECT(dh, "openssl.dh");
    lua_setfield(L, -2, "dh");
  } break;
#endif
#if OPENSSL_VERSION_NUMBER > 0x30000000
#ifndef OPENSSL_NO_SM2
  case EVP_PKEY_SM2: {
    const EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    PUSH_OBJECT(ec, "openssl.ec_key");
    lua_setfield(L, -2, "sm2");
  } break;
#endif
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
#if OPENSSL_VERSION_NUMBER < 0x30000000
#ifdef EVP_PKEY_SM2
  case EVP_PKEY_SM2:
#endif
#endif
  {
    const EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    PUSH_OBJECT(ec, "openssl.ec_key");
    lua_setfield(L, -2, "ec");
  } break;
#endif

  default:
    break;
  };
  return 1;
}

/* ========================================================================
 * openssl_pkey_export
 * ======================================================================== */

/***
 * openssl.evp_pkey object
 * @type evp_pkey
 */

/***
export evp_pkey as pem/der string
@function export
@tparam[opt='pem'] string support export as 'pem' or 'der' format, default is 'pem'
@tparam[opt=false] boolean raw true for export low layer key just rsa,dsa,ec
@tparam[opt] string passphrase if given, export key will encrypt with aes-128-cbc,
only need when export private key
@treturn string
*/
int openssl_pkey_export(lua_State *L)
{
  EVP_PKEY         *key;
  int               ispriv = 0;
  int               exraw = 0;
  int               fmt = FORMAT_AUTO;
  size_t            passphrase_len = 0;
  BIO              *bio_out = NULL;
  int               ret = 0;
  const EVP_CIPHER *cipher;
  const char       *passphrase = NULL;

  key = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  ispriv = openssl_pkey_is_private(key);

  fmt = lua_type(L, 2);
  luaL_argcheck(L, fmt == LUA_TSTRING || fmt == LUA_TNONE, 2, "only accept 'pem','der' or none");
  fmt = luaL_checkoption(L, 2, "pem", format);
  luaL_argcheck(
    L, fmt == FORMAT_PEM || fmt == FORMAT_DER, 2, "only accept pem or der, default is pem");

  if (!lua_isnone(L, 3)) exraw = lua_toboolean(L, 3);
  passphrase = luaL_optlstring(L, 4, NULL, &passphrase_len);

  if (passphrase) {
    cipher = (EVP_CIPHER *)EVP_aes_128_cbc();
  } else {
    cipher = NULL;
  }

  bio_out = BIO_new(BIO_s_mem());
  if (fmt == FORMAT_PEM) {
    if (exraw == 0) {
      ret = ispriv
              ? PEM_write_bio_PrivateKey(
                  bio_out, key, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
              : PEM_write_bio_PUBKEY(bio_out, key);
    } else {
      /* export raw key format */
      switch (EVP_PKEY_type(EVP_PKEY_id(key))) {
#ifndef OPENSSL_NO_RSA
      case EVP_PKEY_RSA:
        ret = ispriv ? PEM_write_bio_RSAPrivateKey(bio_out,
                                                   EVP_PKEY_get0_RSA(key),
                                                   cipher,
                                                   (unsigned char *)passphrase,
                                                   passphrase_len,
                                                   NULL,
                                                   NULL)
                     : PEM_write_bio_RSAPublicKey(bio_out, EVP_PKEY_get0_RSA(key));
        break;
#endif
#ifndef OPENSSL_NO_DSA
      case EVP_PKEY_DSA: {
        ret = ispriv ? PEM_write_bio_DSAPrivateKey(bio_out,
                                                   EVP_PKEY_get0_DSA(key),
                                                   cipher,
                                                   (unsigned char *)passphrase,
                                                   passphrase_len,
                                                   NULL,
                                                   NULL)
                     : PEM_write_bio_DSA_PUBKEY(bio_out, EVP_PKEY_get0_DSA(key));
      } break;
#endif
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC:
        ret = ispriv ? PEM_write_bio_ECPrivateKey(bio_out,
                                                  EVP_PKEY_get0_EC_KEY(key),
                                                  cipher,
                                                  (unsigned char *)passphrase,
                                                  passphrase_len,
                                                  NULL,
                                                  NULL)
                     : PEM_write_bio_EC_PUBKEY(bio_out, EVP_PKEY_get0_EC_KEY(key));
        break;
#endif
      default:
        break;
      }
    }
  } else {
    /* out put der */
    if (exraw == 0) {
      ret = ispriv ? (passphrase == NULL
                        ? i2d_PrivateKey_bio(bio_out, key)
                        : i2d_PKCS8PrivateKey_bio(
                            bio_out, key, cipher, (char *)passphrase, passphrase_len, NULL, NULL))
                   : i2d_PUBKEY_bio(bio_out, key);
    } else {
      /* output raw key, rsa, ec, dh, dsa */
      switch (EVP_PKEY_type(EVP_PKEY_id(key))) {
#ifndef OPENSSL_NO_RSA
      case EVP_PKEY_RSA:
        ret = ispriv ? i2d_RSAPrivateKey_bio(bio_out, EVP_PKEY_get0_RSA(key))
                     : i2d_RSAPublicKey_bio(bio_out, EVP_PKEY_get0_RSA(key));
        break;
#endif
#ifndef OPENSSL_NO_DSA
      case EVP_PKEY_DSA: {
        ret = ispriv ? i2d_DSAPrivateKey_bio(bio_out, EVP_PKEY_get0_DSA(key))
                     : i2d_DSA_PUBKEY_bio(bio_out, EVP_PKEY_get0_DSA(key));
      } break;
#endif
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC:
        ret = ispriv ? i2d_ECPrivateKey_bio(bio_out, EVP_PKEY_get0_EC_KEY(key))
                     : i2d_EC_PUBKEY_bio(bio_out, EVP_PKEY_get0_EC_KEY(key));
        break;
#endif
      default:
        ret = ispriv ? i2d_PrivateKey_bio(bio_out, key) : i2d_PUBKEY_bio(bio_out, key);
      }
    }
  }

  if (ret) {
    char *bio_mem_ptr;
    long  bio_mem_len;

    bio_mem_len = BIO_get_mem_data(bio_out, &bio_mem_ptr);

    lua_pushlstring(L, bio_mem_ptr, bio_mem_len);
    ret = 1;
  }

  if (bio_out) BIO_free(bio_out);

  return ret;
}

/* ========================================================================
 * openssl_pkey_encrypt / decrypt (RSA only)
 * ======================================================================== */

/***
 * encrypt message with public key
 * encrypt length of message must not longer than key size, if shorter will do padding,currently
 * supports 6 padding modes. They are: pkcs1, sslv23, no, oaep, x931, pss.
 * @function encrypt
 * @tparam string data data to be encrypted
 * @tparam string[opt='pkcs1'] string padding padding mode
 * @treturn string encrypted message
 */
int
openssl_pkey_encrypt(lua_State *L)
{
  size_t        dlen = 0;
  EVP_PKEY     *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char   *data = luaL_checklstring(L, 2, &dlen);
  int           padding = openssl_get_padding(L, 3, "pkcs1");
  ENGINE       *engine = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
  size_t        clen = EVP_PKEY_size(pkey);
  EVP_PKEY_CTX *ctx = NULL;
  int           ret = 0;
  int           typ = EVP_PKEY_type(EVP_PKEY_id(pkey));

  luaL_argcheck(
    L, typ == EVP_PKEY_RSA || typ == EVP_PKEY_RSA2, 1, "EVP_PKEY must be of type RSA or RSA2");

  ctx = EVP_PKEY_CTX_new(pkey, engine);
  if (EVP_PKEY_encrypt_init(ctx) == 1) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) == 1) {
      byte *buf = malloc(clen);
      if (EVP_PKEY_encrypt(ctx, buf, &clen, (const unsigned char *)data, dlen) == 1) {
        lua_pushlstring(L, (const char *)buf, clen);
        ret = 1;
      }
      free(buf);
    }
  }
  EVP_PKEY_CTX_free(ctx);

  return ret;
}

/***
 * decrypt message with private key
 * pair with encrypt
 * @function decrypt
 * @tparam string data data to be decrypted
 * @tparam string[opt='pkcs1'] string padding padding mode
 * @treturn[1] string result
 * @treturn[2] nil
 */
int
openssl_pkey_decrypt(lua_State *L)
{
  size_t        dlen = 0;
  EVP_PKEY     *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char   *data = luaL_checklstring(L, 2, &dlen);
  int           padding = openssl_get_padding(L, 3, "pkcs1");
  ENGINE       *engine = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
  size_t        clen = EVP_PKEY_size(pkey);
  EVP_PKEY_CTX *ctx = NULL;
  int           ret = 0;
  int           type = EVP_PKEY_type(EVP_PKEY_id(pkey));

  luaL_argcheck(
    L, type == EVP_PKEY_RSA || type == EVP_PKEY_RSA2, 1, "EVP_PKEY must be of type RSA or RSA2");

  ctx = EVP_PKEY_CTX_new(pkey, engine);
  if (EVP_PKEY_decrypt_init(ctx) == 1) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) == 1) {
      byte *buf = malloc(clen);

      if (EVP_PKEY_decrypt(ctx, buf, &clen, (const unsigned char *)data, dlen) == 1) {
        lua_pushlstring(L, (const char *)buf, clen);
        ret = 1;
      }
      free(buf);
    }
  }
  EVP_PKEY_CTX_free(ctx);

  return ret;
}

/* ========================================================================
 * openssl_pkey_ctx - create EVP_PKEY_CTX context
 * ======================================================================== */

/***
 * create EVP_PKEY_CTX context for public key operations
 * @function ctx
 * @tparam[opt] openssl.engine engine optional engine for hardware acceleration
 * @treturn evp_pkey_ctx public key context object for RSA operations
 */
int
openssl_pkey_ctx(lua_State *L)
{
  EVP_PKEY     *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  ENGINE       *engine = lua_isnoneornil(L, 2) ? NULL : CHECK_OBJECT(2, ENGINE, "openssl.engine");
  EVP_PKEY_CTX *ctx = NULL;
  int           typ = EVP_PKEY_type(EVP_PKEY_id(pkey));

  luaL_argcheck(
    L, typ == EVP_PKEY_RSA || typ == EVP_PKEY_RSA2, 1, "EVP_PKEY must be of type RSA or RSA2");

  ctx = EVP_PKEY_CTX_new(pkey, engine);
  if (ctx) {
    PUSH_OBJECT(ctx, "openssl.evp_pkey_ctx");
    return 1;
  }

  return openssl_pushresult(L, 0);
}

/* ========================================================================
 * EVP_PKEY_CTX operations
 * ======================================================================== */

/***
 * create new EVP_PKEY_CTX context
 * @function ctx_new
 * @tparam string alg algorithm name
 * @tparam[opt] openssl.engine engine optional engine for hardware acceleration
 * @treturn evp_pkey_ctx public key context object
 */
int
openssl_pkey_ctx_new(lua_State *L)
{
  int     nid = lua_isnumber(L, 1) ? lua_tointeger(L, 1) : OBJ_txt2nid(luaL_checkstring(L, 1));
  ENGINE *eng = lua_isnoneornil(L, 2) ? NULL : CHECK_OBJECT(2, ENGINE, "openssl.engine");
  EVP_PKEY_CTX *pctx;

  luaL_argcheck(L, nid > 0, 1, "invalid public key algorithm");

  pctx = EVP_PKEY_CTX_new_id(nid, eng);
  if (pctx) {
    PUSH_OBJECT(pctx, "openssl.evp_pkey_ctx");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

/***
 * free EVP_PKEY_CTX context
 * @function __gc
 */
int
openssl_pkey_ctx_free(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  EVP_PKEY_CTX_free(ctx);
  return 0;
}

/***
 * generate key
 * @function keygen
 * @treturn openssl.evp_pkey generated key
 */
int
openssl_pkey_ctx_keygen(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  int           bits = luaL_optinteger(L, 2, 0);
  EVP_PKEY     *pkey = NULL;

  int ret = EVP_PKEY_keygen_init(ctx);
  if (ret == 1) {
    ret = EVP_PKEY_keygen(ctx, &pkey);
  }
  if (ret == 1) {
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
  } else if (ret == -2) {
    lua_pushnil(L);
    lua_pushstring(L, "NOT_SUPPORT");
    ret = 2;
  } else
    ret = openssl_pushresult(L, ret);

  (void)bits;
  return ret;
}

/***
 * ctrl
 * @function ctrl
 */
int
openssl_pkey_ctx_ctrl(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  int           ret = 0;

  if (lua_isnumber(L, 2)) {
    int type = lua_tointeger(L, 2);
    int p1 = luaL_checkint(L, 3);
    long p2 = luaL_optlong(L, 4, 0);
    ret = EVP_PKEY_CTX_ctrl(ctx, -1, type, p1, p2, NULL);
  } else if (lua_isstring(L, 2)) {
    const char *name = lua_tostring(L, 2);
    const char *value = luaL_checkstring(L, 3);
    ret = EVP_PKEY_CTX_ctrl_str(ctx, name, value);
  }

  lua_pushboolean(L, ret > 0);
  return 1;
}

/***
 * decrypt_init
 * @function decrypt_init
 * @tparam[opt] string|env_digest md_alg digest algorithm
 * @treturn boolean true for success
 */
int
openssl_pkey_ctx_decrypt_init(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");

  if (EVP_PKEY_decrypt_init(ctx) <= 0) return openssl_pushresult(L, 0);

  lua_pushvalue(L, 1);
  return 1;
}

/***
 * encrypt_init
 * @function encrypt_init
 * @tparam[opt] string|env_digest md_alg digest algorithm
 * @treturn boolean true for success
 */
int
openssl_pkey_ctx_encrypt_init(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");

  if (EVP_PKEY_encrypt_init(ctx) <= 0) return openssl_pushresult(L, 0);

  lua_pushvalue(L, 1);
  return 1;
}

/***
 * verify_init
 * @function verify_init
 * @tparam[opt] string|env_digest md_alg digest algorithm
 * @treturn boolean true for success
 */
int
openssl_pkey_ctx_verify_init(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");

  if (EVP_PKEY_verify_init(ctx) <= 0) return openssl_pushresult(L, 0);

  lua_pushvalue(L, 1);
  return 1;
}

/***
 * sign_init
 * @function sign_init
 * @tparam[opt] string|env_digest md_alg digest algorithm
 * @treturn boolean true for success
 */
int
openssl_pkey_ctx_sign_init(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");

  if (EVP_PKEY_sign_init(ctx) <= 0) return openssl_pushresult(L, 0);

  lua_pushvalue(L, 1);
  return 1;
}

/***
 * decrypt
 * @function decrypt
 * @tparam string data data to decrypt
 * @treturn string decrypted data
 */
int
openssl_pkey_ctx_decrypt(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  size_t        dlen = 0;
  const char   *data = luaL_checklstring(L, 2, &dlen);
  int           ret = 0;

  size_t clen = dlen;
  byte  *buf = malloc(clen);
  if (EVP_PKEY_decrypt(ctx, buf, &clen, (const unsigned char *)data, dlen) == 1) {
    lua_pushlstring(L, (const char *)buf, clen);
    ret = 1;
  }
  free(buf);

  return ret;
}

/***
 * encrypt
 * @function encrypt
 * @tparam string data data to encrypt
 * @treturn string encrypted data
 */
int
openssl_pkey_ctx_encrypt(lua_State *L)
{
  EVP_PKEY_CTX *ctx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  size_t        in_len = 0;
  const char   *in = luaL_checklstring(L, 2, &in_len);
  int           ret = 0;
  size_t        buf_len = 0;
  byte         *buf = NULL;

  if (EVP_PKEY_encrypt(ctx, NULL, &buf_len, (const unsigned char *)in, in_len) > 0) {
    buf = malloc(buf_len);
    if (EVP_PKEY_encrypt(ctx, buf, &buf_len, (const unsigned char *)in, in_len) > 0) {
      lua_pushlstring(L, (const char *)buf, buf_len);
      ret = 1;
    }
    free(buf);
  }

  return ret;
}

/***
 * verify
 * @function verify
 * @tparam string sig signature
 * @tparam string data data to verify
 * @treturn boolean true if signature is valid
 */
int
openssl_pkey_ctx_verify(lua_State *L)
{
  EVP_PKEY_CTX *pCtx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  size_t        dlen = 0;
  const char   *data = luaL_checklstring(L, 2, &dlen);
  size_t        slen = 0;
  const char   *sign = luaL_checklstring(L, 3, &slen);

  int ret
    = EVP_PKEY_verify(pCtx, (const unsigned char *)data, dlen, (const unsigned char *)sign, slen);
  lua_pushboolean(L, ret > 0);

  return 1;
}

/***
 * sign
 * @function sign
 * @tparam string data data to sign
 * @treturn string signature
 */
int
openssl_pkey_ctx_sign(lua_State *L)
{
  EVP_PKEY_CTX  *pCtx = CHECK_OBJECT(1, EVP_PKEY_CTX, "openssl.evp_pkey_ctx");
  size_t         digest_len = 0;
  const char    *digest = luaL_checklstring(L, 2, &digest_len);
  size_t         sig_len = 0;
  unsigned char *sig = NULL;
  int            ret = 0;

  if (EVP_PKEY_sign(pCtx, NULL, &sig_len, (const unsigned char *)digest, digest_len) > 0) {
    sig = malloc(sig_len);
    if (EVP_PKEY_sign(pCtx, sig, &sig_len, (const unsigned char *)digest, digest_len) > 0) {
      lua_pushlstring(L, (const char *)sig, sig_len);
      ret = 1;
    }
    free(sig);
  }

  return ret;
}

/* ========================================================================
 * luaL_Reg arrays
 * ======================================================================== */

luaL_Reg pkey_funcs[] = {
  { "is_private",         openssl_pkey_is_private1       },
  { "get_public",         openssl_pkey_get_public        },
#ifndef OPENSSL_NO_ENGINE
  { "set_engine",         openssl_pkey_set_engine        },
#endif

  { "export",             openssl_pkey_export            },
  { "parse",              openssl_pkey_parse             },
  { "bits",               openssl_pkey_bits              },

  { "ctx",                openssl_pkey_ctx               },
  { "encrypt",            openssl_pkey_encrypt           },
  { "decrypt",            openssl_pkey_decrypt           },
  { "sign",               openssl_sign                   },
  { "verify",             openssl_verify                 },

  { "seal",               openssl_seal                   },
  { "open",               openssl_open                   },

  { "derive",             openssl_derive                 },

#if defined(OPENSSL_SUPPORT_SM2) && OPENSSL_VERSION_NUMBER < 0x30000000
  { "as_sm2",             openssl_pkey_as_sm2            },
#endif
  { "missing_paramaters", openssl_pkey_mssing_parameters },

  { "__gc",               openssl_pkey_free              },
  { "__tostring",         auxiliar_tostring              },

  { NULL,                 NULL                           },
};

luaL_Reg pkey_ctx_funcs[] = {
  { "encrypt_init", openssl_pkey_ctx_encrypt_init },
  { "decrypt_init", openssl_pkey_ctx_decrypt_init },
  { "verify_init",  openssl_pkey_ctx_verify_init  },
  { "sign_init",    openssl_pkey_ctx_sign_init    },

  { "ctrl",         openssl_pkey_ctx_ctrl         },

  { "keygen",       openssl_pkey_ctx_keygen       },

  { "decrypt",      openssl_pkey_ctx_decrypt      },
  { "encrypt",      openssl_pkey_ctx_encrypt      },

  { "verify",       openssl_pkey_ctx_verify       },
  { "sign",         openssl_pkey_ctx_sign         },

  { "__gc",         openssl_pkey_ctx_free         },
  { "__tostring",   auxiliar_tostring             },

  { NULL,           NULL                          },
};

static const luaL_Reg R[] = {
  { "read",        openssl_pkey_read        },
  { "new",         openssl_pkey_new         },
  { "ctx_new",     openssl_pkey_ctx_new     },

  { "seal",        openssl_seal             },
  { "seal_init",   openssl_seal_init        },
  { "seal_update", openssl_seal_update      },
  { "seal_final",  openssl_seal_final       },
  { "open",        openssl_open             },
  { "open_init",   openssl_open_init        },
  { "open_update", openssl_open_update      },
  { "open_final",  openssl_open_final       },

  { "get_public",  openssl_pkey_get_public  },
#ifndef OPENSSL_NO_ENGINE
  { "set_engine",  openssl_pkey_set_engine  },
#endif
  { "is_private",  openssl_pkey_is_private1 },
  { "export",      openssl_pkey_export      },
  { "parse",       openssl_pkey_parse       },
  { "bits",        openssl_pkey_bits        },

  { "encrypt",     openssl_pkey_encrypt     },
  { "decrypt",     openssl_pkey_decrypt     },
  { "sign",        openssl_sign             },
  { "verify",      openssl_verify           },
  { "derive",      openssl_derive           },

#if defined(OPENSSL_SUPPORT_SM2) && OPENSSL_VERSION_NUMBER < 0x30000000
  { "as_sm2",      openssl_pkey_as_sm2      },
#endif

  { NULL,          NULL                     }
};

/* ========================================================================
 * luaopen_pkey - module entry point
 * ======================================================================== */

int
luaopen_pkey(lua_State *L)
{
  size_t i;

  auxiliar_newclass(L, "openssl.evp_pkey", pkey_funcs);
  auxiliar_newclass(L, "openssl.evp_pkey_ctx", pkey_ctx_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  for (i = 0; i < OSSL_NELEM(standard_name2type); i++) {
    lua_pushstring(L, standard_name2type[i].ptr);
    lua_pushinteger(L, standard_name2type[i].id);
    lua_rawset(L, -3);
  }

  return 1;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
