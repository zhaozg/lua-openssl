/***
ec module to create EC keys and do EC key processes.

@module ec
@usage
  ec = require('openssl').ec
*/
#include <openssl/engine.h>

#include "openssl.h"
#include "private.h"

#if !defined(OPENSSL_NO_EC)

#include "ec_util.c"
/* Include EC_GROUP and EC_POINT modules */
#include "group.c"
#include "point.c"

static int
openssl_ecdsa_do_sign(lua_State *L)
{
  EC_KEY     *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t      l;
  const char *sdata = luaL_checklstring(L, 2, &l);
  ECDSA_SIG  *sig = ECDSA_do_sign((const unsigned char *)sdata, l, ec);
  int         der = lua_isnone(L, 3) ? 1 : lua_toboolean(L, 3);
  int         ret = 0;

  if (der) {
    unsigned char *p = NULL;
    l = i2d_ECDSA_SIG(sig, &p);
    if (l > 0) {
      lua_pushlstring(L, (const char *)p, l);
      OPENSSL_free(p);
      ret = 1;
    }
  } else {
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    r = BN_dup(r);
    s = BN_dup(s);

    PUSH_OBJECT(r, "openssl.bn");
    PUSH_OBJECT(s, "openssl.bn");
    ret = 2;
  }
  ECDSA_SIG_free(sig);
  return ret;
}

static int
openssl_ecdsa_do_verify(lua_State *L)
{
  size_t      l, sigl;
  int         ret;
  EC_KEY     *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  const char *dgst = luaL_checklstring(L, 2, &l);
  int         top = lua_gettop(L);
  if (top == 3) {
    const char *s = luaL_checklstring(L, 3, &sigl);
    ECDSA_SIG  *sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&s, sigl);
    ret = ECDSA_do_verify((const unsigned char *)dgst, l, sig, ec);
    ECDSA_SIG_free(sig);
  } else {
    BIGNUM    *r = BN_get(L, 3);
    BIGNUM    *s = BN_get(L, 4);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);
    ret = ECDSA_do_verify((const unsigned char *)dgst, l, sig, ec);
    ECDSA_SIG_free(sig);
  }
  if (ret == -1) return openssl_pushresult(L, ret);
  lua_pushboolean(L, ret);
  return 1;
}

/***
do EC sign

@function sign
@tparam ec_key eckey
@tparam string digest result of digest to be signed
@tparam evp_md|string|nid md digest alg identity, default is sm3
@treturn string signature
*/
static int openssl_ecdsa_sign(lua_State *L)
{
  int                  ret;
  EC_KEY              *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t               dgstlen = 0;
  const unsigned char *dgst = (const unsigned char *)luaL_checklstring(L, 2, &dgstlen);
  const EVP_MD        *md = get_digest(L, 3, NULL);
  unsigned int         siglen = ECDSA_size(eckey);
  unsigned char       *sig = OPENSSL_malloc(siglen);

  luaL_argcheck(L, dgstlen == EVP_MD_size(md), 4, "invalid digest");
  ret = ECDSA_sign(EVP_MD_type(md), dgst, dgstlen, sig, &siglen, eckey);
  if (ret == 1) {
    lua_pushlstring(L, (const char *)sig, siglen);
  } else
    ret = openssl_pushresult(L, ret);
  OPENSSL_free(sig);
  return ret;
}

/***
do EC verify, input msg is digest result

@function verify
@tparam ec_key eckey
@tparam string digest result of digest to be signed
@tparam string signature
@tparam evp_md|string|nid md digest alg identity
@treturn boolean true for verified, false for invalid signature
@return nil for error, and followed by error message
*/
static int openssl_ecdsa_verify(lua_State *L)
{
  int                  ret;
  EC_KEY              *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t               dgstlen = 0;
  const unsigned char *dgst = (const unsigned char *)luaL_checklstring(L, 2, &dgstlen);
  size_t               siglen = 0;
  const unsigned char *sig = (const unsigned char *)luaL_checklstring(L, 3, &siglen);
  const EVP_MD        *md = get_digest(L, 4, NULL);
  int                  type = EVP_MD_type(md);

  luaL_argcheck(L, dgstlen == EVP_MD_size(md), 4, "invalid digest");
  ret = ECDSA_verify(type, dgst, (int)dgstlen, sig, (int)siglen, eckey);
  if (ret == -1) return openssl_pushresult(L, ret);
  lua_pushboolean(L, ret);
  return 1;
}

static int
openssl_key_free(lua_State *L)
{
  EC_KEY *p = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  EC_KEY_free(p);
  return 0;
}

/***
parse EC key components and parameters
@function parse
@tparam[opt=false] boolean basic true for basic information only
@treturn table EC key information including encoding flags, conversion form, group, and key components
*/
static int
openssl_key_parse(lua_State *L)
{
  EC_KEY         *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  int             basic = luaL_opt(L, lua_toboolean, 2, 0);
  const EC_POINT *point = EC_KEY_get0_public_key(ec);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  const BIGNUM   *priv = EC_KEY_get0_private_key(ec);
  lua_newtable(L);

  AUXILIAR_SET(L, -1, "enc_flag", EC_KEY_get_enc_flags(ec), integer);
  AUXILIAR_SET(L, -1, "conv_form", EC_KEY_get_conv_form(ec), integer);
  AUXILIAR_SET(L, -1, "curve_name", EC_GROUP_get_curve_name(group), integer);

  if (basic) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (priv != NULL) {
      priv = BN_dup(priv);
      AUXILIAR_SETOBJECT(L, priv, "openssl.bn", -1, "d");
    }

    if (point && EC_POINT_get_affine_coordinates(group, point, x, y, NULL) == 1) {
      AUXILIAR_SETOBJECT(L, x, "openssl.bn", -1, "x");
      AUXILIAR_SETOBJECT(L, y, "openssl.bn", -1, "y");
    };
  } else {
    point = EC_POINT_dup(point, group);
    AUXILIAR_SETOBJECT(L, point, "openssl.ec_point", -1, "pub_key");
    group = EC_GROUP_dup(group);
    AUXILIAR_SETOBJECT(L, group, "openssl.ec_group", -1, "group");

    OPENSSL_PKEY_GET_BN(priv, priv_key);
  }
  return 1;
};

#ifndef OPENSSL_NO_ECDH
static const int KDF1_SHA1_len = 20;
static void *
KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen)
{
#ifndef OPENSSL_NO_SHA
  if (*outlen < SHA_DIGEST_LENGTH)
    return NULL;
  else
    *outlen = SHA_DIGEST_LENGTH;
  return SHA1(in, inlen, out);
#else
  return NULL;
#endif /* OPENSSL_NO_SHA */
}
#endif /* OPENSSL_NO_ECDH */

#define MAX_ECDH_SIZE 256

/***
compute ECDH shared key
@function compute_key
@tparam ec_key peer peer EC key for key exchange
@tparam[opt] function kdf key derivation function
@treturn string shared secret or nil if failed
*/
static int
openssl_ecdh_compute_key(lua_State *L)
{
  EC_KEY *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  EC_KEY *peer = CHECK_OBJECT(2, EC_KEY, "openssl.ec_key");

  int           field_size, outlen, secret_size_a;
  unsigned char secret_a[MAX_ECDH_SIZE];
  void *(*kdf)(const void *in, size_t inlen, void *out, size_t *xoutlen);
  field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ec));
  if (field_size <= 24 * 8) {
    outlen = KDF1_SHA1_len;
    kdf = KDF1_SHA1;
  } else {
    outlen = (field_size + 7) / 8;
    kdf = NULL;
  }
  secret_size_a = ECDH_compute_key(secret_a, outlen, EC_KEY_get0_public_key(peer), ec, kdf);
  lua_pushlstring(L, (const char *)secret_a, secret_size_a);
  return 1;
}

/***
set ECDSA signing method for EC key
@function set_method
@tparam engine engine engine providing the ECDSA method
@treturn boolean result true for success
*/
static int
openssl_ecdsa_set_method(lua_State *L)
{
#ifndef OPENSSL_NO_ENGINE
  EC_KEY *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  ENGINE *e = CHECK_OBJECT(2, ENGINE, "openssl.engine");
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
  const ECDSA_METHOD *m = ENGINE_get_ECDSA(e);
  if (m) {
    int r = ECDSA_set_method(ec, m);
    return openssl_pushresult(L, r);
  }
#else
  const EC_KEY_METHOD *m = ENGINE_get_EC(e);
  if (m) {
    int r = EC_KEY_set_method(ec, m);
    return openssl_pushresult(L, r);
  }
#endif
#endif
  return 0;
}

/***
check if EC key is valid
@function check
@treturn boolean true if key is valid, false otherwise
*/
static int
openssl_key_check_key(lua_State *L)
{
  EC_KEY *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  lua_pushboolean(L, EC_KEY_check_key(ec));
  return 1;
}

/***
export EC key to DER format
@function export
@treturn string DER encoded EC private key
*/
static int
openssl_key_export(lua_State *L)
{
  EC_KEY        *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  unsigned char *der = NULL;
  int            len = i2d_ECPrivateKey(ec, &der);
  if (len > 0)
    lua_pushlstring(L, (const char *)der, len);
  else
    lua_pushnil(L);
  if (der) OPENSSL_free(der);
  return 1;
}

/***
get or set EC group for EC key
@function group
@tparam[opt] ec_group group optional EC group to set
@treturn ec_group current EC group when called without parameters
@treturn boolean true when setting group successfully
*/
static int
openssl_key_group(lua_State *L)
{
  EC_KEY *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  if (!lua_isnone(L, 2)) {
    EC_GROUP *g = CHECK_OBJECT(2, EC_GROUP, "openssl.ec_group");
    int       ret = EC_KEY_set_group(ec, g);
    return openssl_pushresult(L, ret);
  } else {
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    g = EC_GROUP_dup(g);
    PUSH_OBJECT(g, "openssl.ec_group");
    return 1;
  }
}

/***
read EC key from DER encoded data
@function read
@tparam string der DER encoded EC private key data
@treturn ec_key|nil parsed EC key or nil on failure
*/
static int
openssl_key_read(lua_State *L)
{
  size_t               len = 0;
  const unsigned char *der = (const unsigned char *)luaL_checklstring(L, 1, &len);

  EC_KEY *ec = d2i_ECPrivateKey(NULL, &der, len);
  if (ec)
    PUSH_OBJECT(ec, "openssl.ec_key");
  else
    lua_pushnil(L);
  return 1;
}

/***
get or set point conversion form for EC key
@function conv_form
@tparam[opt] string|number form point conversion form to set
@treturn[1] string point conversion form name if getting
@treturn[1] number point conversion form value if getting
@treturn[2] boolean result true for success if setting
*/
static int
openssl_key_conv_form(lua_State *L)
{
  EC_KEY                 *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  point_conversion_form_t cform;
  if (lua_isnone(L, 2)) {
    cform = EC_KEY_get_conv_form(ec);
    openssl_push_point_conversion_form(L, cform);
    lua_pushinteger(L, cform);
    return 2;
  } else if (lua_isnumber(L, 2))
    cform = lua_tointeger(L, 2);
  else
    cform = openssl_to_point_conversion_form(L, 2, NULL);
  EC_KEY_set_conv_form(ec, cform);
  lua_pushvalue(L, 1);
  return 1;
}

/***
get or set encoding flags for EC key
@function enc_flags
@tparam[opt] string|number flags encoding flags to set
@treturn[1] string encoding flags name if getting
@treturn[1] number encoding flags value if getting
@treturn[2] boolean result true for success if setting
*/
static int
openssl_key_enc_flags(lua_State *L)
{
  EC_KEY      *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  unsigned int flags;
  if (lua_isnone(L, 2)) {
    flags = EC_KEY_get_enc_flags(ec);
    openssl_push_group_asn1_flag(L, flags);
    lua_pushinteger(L, flags);
    return 2;
  } else if (lua_isnumber(L, 2))
    flags = luaL_checkint(L, 2);
  else
    flags = openssl_to_group_asn1_flag(L, 2, NULL);
  EC_KEY_set_enc_flags(ec, flags);
  lua_pushvalue(L, 1);
  return 1;
}

#ifdef EC_EXT
EC_EXT_DEFINE
#endif

static luaL_Reg ec_key_funs[] = {
  { "check",       openssl_key_check_key },
  { "export",      openssl_key_export    },
  { "parse",       openssl_key_parse     },
  { "group",       openssl_key_group     },
  { "do_sign",     openssl_ecdsa_do_sign    },
  { "do_verify",   openssl_ecdsa_do_verify  },
  { "sign",        openssl_ecdsa_sign       },
  { "verify",      openssl_ecdsa_verify     },
  { "compute_key", openssl_ecdh_compute_key },
  { "set_method",  openssl_ecdsa_set_method },
  { "conv_form",   openssl_key_conv_form },
  { "enc_flags",   openssl_key_enc_flags },

#ifdef EC_EXT
  EC_EXT
#endif

  { "__gc",        openssl_key_free      },
  { "__tostring",  auxiliar_tostring        },

  { NULL,          NULL                     }
};

/***
list all available elliptic curve names
@function list
@treturn table array of curve names and descriptions
*/
static int openssl_list_curve_name(lua_State *L)
{
  size_t            i = 0;
  size_t            crv_len = EC_get_builtin_curves(NULL, 0);
  EC_builtin_curve *curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));

  if (curves == NULL) return 0;

  if (!EC_get_builtin_curves(curves, crv_len)) {
    OPENSSL_free(curves);
    return 0;
  }

  lua_newtable(L);
  for (i = 0; i < crv_len; i++) {
    const char *comment;
    const char *sname;
    comment = curves[i].comment;
    sname = OBJ_nid2sn(curves[i].nid);
    if (comment == NULL) comment = "CURVE DESCRIPTION NOT AVAILABLE";
    if (sname == NULL) sname = "";

    AUXILIAR_SET(L, -1, sname, comment, string);
  }

  OPENSSL_free(curves);
  return 1;
};

static luaL_Reg R[] = {
  { "read",      openssl_key_read        },
  { "list",      openssl_list_curve_name },

  { "do_sign",   openssl_ecdsa_do_sign      },
  { "do_verify", openssl_ecdsa_do_verify    },
  { "sign",      openssl_ecdsa_sign         },
  { "verify",    openssl_ecdsa_verify       },

  { NULL,        NULL                       }
};

int
luaopen_ec(lua_State *L)
{
  auxiliar_newclass(L, "openssl.ec_key", ec_key_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  /* Register group sub-module */
  luaopen_ec_group(L);
  lua_setfield(L, -2, "group");

  /* Register point sub-module */
  luaopen_ec_point(L);
  lua_setfield(L, -2, "point");

  return 1;
}

#endif
