/***
EC_GROUP module for Lua OpenSSL binding.

This module provides a complete wrapper for OpenSSL's EC_GROUP operations,
enabling elliptic curve group mathematical operations similar to BIGNUM.

@module group
@usage
  group = require('openssl').group
*/

#include "openssl.h"
#include "private.h"

#if !defined(OPENSSL_NO_EC)
#include <openssl/ec.h>
#include <openssl/engine.h>

#define MYNAME "group"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2024"
#define MYTYPE "openssl.ec_group"

/* Forward declarations */
int openssl_push_group_asn1_flag(lua_State *L, int flag);
int openssl_push_point_conversion_form(lua_State *L, point_conversion_form_t form);
int openssl_to_group_asn1_flag(lua_State *L, int i, const char *defval);
point_conversion_form_t openssl_to_point_conversion_form(lua_State *L, int i, const char *defval);

/***
Create a new EC_GROUP from curve name.

@function new
@tparam string|number curve curve name (string) or NID (number)
@treturn ec_group new elliptic curve group
@usage
  group = require('openssl').group
  g = group.new('prime256v1')
  g = group.new(415)  -- NID for prime256v1
*/
static int openssl_group_new(lua_State *L)
{
  EC_GROUP *g = NULL;
  int nid = NID_undef;

  if (lua_isnumber(L, 1)) {
    nid = lua_tointeger(L, 1);
  } else if (lua_isstring(L, 1)) {
    const char *name = lua_tostring(L, 1);
    nid = OBJ_sn2nid(name);
    if (nid == NID_undef)
      nid = OBJ_ln2nid(name);
    if (nid == NID_undef)
      nid = EC_curve_nist2nid(name);
  }

  if (nid != NID_undef) {
    g = EC_GROUP_new_by_curve_name(nid);
    if (g) {
      EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
      EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_UNCOMPRESSED);
      PUSH_OBJECT(g, MYTYPE);
      return 1;
    }
  }
  
  return luaL_error(L, "invalid curve name or NID");
}

/***
Duplicate an EC_GROUP.

@function dup
@treturn ec_group duplicated elliptic curve group
*/
static int openssl_group_dup(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  EC_GROUP *dup = EC_GROUP_dup(g);
  
  if (dup) {
    PUSH_OBJECT(dup, MYTYPE);
    return 1;
  }
  
  return 0;
}

/***
Get the generator point of the group.

@function generator
@treturn ec_point generator point of the curve
*/
static int openssl_group_generator(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *p = EC_GROUP_get0_generator(g);
  
  if (p) {
    p = EC_POINT_dup(p, g);
    PUSH_OBJECT(p, "openssl.ec_point");
    return 1;
  }
  
  return 0;
}

/***
Get the order of the group.

@function order
@treturn bn order of the group
*/
static int openssl_group_order(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  BIGNUM *order = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_GROUP_get_order(g, order, ctx)) {
    BN_CTX_free(ctx);
    PUSH_OBJECT(order, "openssl.bn");
    return 1;
  }
  
  BN_CTX_free(ctx);
  BN_free(order);
  return 0;
}

/***
Get the cofactor of the group.

@function cofactor
@treturn bn cofactor of the group
*/
static int openssl_group_cofactor(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  BIGNUM *cofactor = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_GROUP_get_cofactor(g, cofactor, ctx)) {
    BN_CTX_free(ctx);
    PUSH_OBJECT(cofactor, "openssl.bn");
    return 1;
  }
  
  BN_CTX_free(ctx);
  BN_free(cofactor);
  return 0;
}

/***
Get the degree of the group (field size in bits).

@function degree
@treturn number degree of the group
*/
static int openssl_group_degree(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  lua_pushinteger(L, EC_GROUP_get_degree(g));
  return 1;
}

/***
Get the curve name NID.

@function curve_name
@treturn number NID of the curve
*/
static int openssl_group_curve_name(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  lua_pushinteger(L, EC_GROUP_get_curve_name(g));
  return 1;
}

/***
Get or set the ASN1 flag.

@function asn1_flag
@tparam[opt] string|number flag ASN1 flag ("explicit" or "named_curve")
@treturn string|number current ASN1 flag (when getting)
@treturn ec_group self (when setting)
*/
static int openssl_group_asn1_flag(lua_State *L)
{
  EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  int asn1_flag;
  
  if (lua_isnone(L, 2)) {
    /* Get */
    asn1_flag = EC_GROUP_get_asn1_flag(g);
    openssl_push_group_asn1_flag(L, asn1_flag);
    lua_pushinteger(L, asn1_flag);
    return 2;
  } else {
    /* Set */
    if (lua_isnumber(L, 2))
      asn1_flag = luaL_checkint(L, 2);
    else
      asn1_flag = openssl_to_group_asn1_flag(L, 2, NULL);
    EC_GROUP_set_asn1_flag(g, asn1_flag);
    lua_pushvalue(L, 1);
    return 1;
  }
}

/***
Get or set the point conversion form.

@function point_conversion_form
@tparam[opt] string|number form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|number current conversion form (when getting)
@treturn ec_group self (when setting)
*/
int openssl_group_point_conversion_form(lua_State *L)
{
  EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  point_conversion_form_t form;
  
  if (lua_isnone(L, 2)) {
    /* Get */
    form = EC_GROUP_get_point_conversion_form(g);
    openssl_push_point_conversion_form(L, form);
    lua_pushinteger(L, form);
    return 2;
  } else {
    /* Set */
    if (lua_isnumber(L, 2))
      form = luaL_checkint(L, 2);
    else
      form = openssl_to_point_conversion_form(L, 2, NULL);
    EC_GROUP_set_point_conversion_form(g, form);
    lua_pushvalue(L, 1);
    return 1;
  }
}

/***
Get curve parameters (p, a, b).

@function curve
@treturn table containing p, a, b as BIGNUM objects
*/
static int openssl_group_curve(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *p = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_GROUP_get_curve(g, p, a, b, ctx)) {
    BN_CTX_free(ctx);
    lua_newtable(L);
    AUXILIAR_SETOBJECT(L, p, "openssl.bn", -1, "p");
    AUXILIAR_SETOBJECT(L, a, "openssl.bn", -1, "a");
    AUXILIAR_SETOBJECT(L, b, "openssl.bn", -1, "b");
    return 1;
  }
  
  BN_CTX_free(ctx);
  BN_free(a);
  BN_free(b);
  BN_free(p);
  return 0;
}

/***
Get the seed value for the group.

@function seed
@treturn string|nil seed value or nil if not set
*/
static int openssl_group_seed(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const unsigned char *seed = EC_GROUP_get0_seed(g);
  size_t seed_len = EC_GROUP_get_seed_len(g);
  
  if (seed && seed_len > 0) {
    lua_pushlstring(L, (const char *)seed, seed_len);
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Parse the EC group to extract all parameters.

@function parse
@treturn table containing all group parameters (generator, order, cofactor, degree, curve_name, etc.)
*/
static int openssl_group_parse(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *generator = EC_GROUP_get0_generator(group);
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a, *b, *p, *order, *cofactor;

  lua_newtable(L);
  
  if (generator) {
    generator = EC_POINT_dup(generator, group);
    AUXILIAR_SETOBJECT(L, generator, "openssl.ec_point", -1, "generator");
  }

  order = BN_new();
  EC_GROUP_get_order(group, order, ctx);
  AUXILIAR_SETOBJECT(L, order, "openssl.bn", -1, "order");

  cofactor = BN_new();
  EC_GROUP_get_cofactor(group, cofactor, ctx);
  AUXILIAR_SETOBJECT(L, cofactor, "openssl.bn", -1, "cofactor");

  openssl_push_group_asn1_flag(L, EC_GROUP_get_asn1_flag(group));
  lua_setfield(L, -2, "asn1_flag");

  AUXILIAR_SET(L, -1, "degree", EC_GROUP_get_degree(group), integer);
  AUXILIAR_SET(L, -1, "curve_name", EC_GROUP_get_curve_name(group), integer);

  openssl_push_point_conversion_form(L, EC_GROUP_get_point_conversion_form(group));
  lua_setfield(L, -2, "conversion_form");

  AUXILIAR_SETLSTR(L, -1, "seed", EC_GROUP_get0_seed(group), EC_GROUP_get_seed_len(group));

  a = BN_new();
  b = BN_new();
  p = BN_new();
  EC_GROUP_get_curve(group, p, a, b, ctx);
  lua_newtable(L);
  {
    AUXILIAR_SETOBJECT(L, p, "openssl.bn", -1, "p");
    AUXILIAR_SETOBJECT(L, a, "openssl.bn", -1, "a");
    AUXILIAR_SETOBJECT(L, b, "openssl.bn", -1, "b");
  }
  lua_setfield(L, -2, "curve");
  BN_CTX_free(ctx);

  return 1;
}

/***
Compare two EC groups for equality.

@function equal
@tparam ec_group other EC group to compare
@treturn boolean true if equal, false otherwise
*/
int openssl_group_equal(lua_State *L)
{
  const EC_GROUP *a = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_GROUP *b = CHECK_OBJECT(2, EC_GROUP, MYTYPE);
  
  lua_pushboolean(L, EC_GROUP_cmp(a, b, NULL) == 0);
  return 1;
}

/***
Free the EC group.

@function free (internal, called by __gc)
*/
int openssl_group_free(lua_State *L)
{
  EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  EC_GROUP_free(g);
  return 0;
}

/***
Convert EC group to string.

@function tostring (internal, called by __tostring)
@treturn string string representation of the group
*/
static int openssl_group_tostring(lua_State *L)
{
  const EC_GROUP *g = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  int nid = EC_GROUP_get_curve_name(g);
  const char *name = OBJ_nid2sn(nid);
  
  if (name)
    lua_pushfstring(L, "ec_group: %s (nid=%d)", name, nid);
  else
    lua_pushfstring(L, "ec_group: nid=%d", nid);
  
  return 1;
}

/* Helper functions */
int openssl_to_group_asn1_flag(lua_State *L, int i, const char *defval)
{
  const char *const flag[] = {"explicit", "named_curve", NULL};
  int f = luaL_checkoption(L, i, defval, flag);
  int form = 0;
  
  if (f == 0)
    form = 0;
  else if (f == 1)
    form = OPENSSL_EC_NAMED_CURVE;
  else
    luaL_argerror(L, i, "invalid parameter, only accept 'explicit' or 'named_curve'");
  
  return form;
}

int openssl_push_group_asn1_flag(lua_State *L, int flag)
{
  if (flag == 0)
    lua_pushstring(L, "explicit");
  else if (flag == 1)
    lua_pushstring(L, "named_curve");
  else
    lua_pushnil(L);
  
  return 1;
}

point_conversion_form_t openssl_to_point_conversion_form(lua_State *L, int i, const char *defval)
{
  const char *options[] = {"compressed", "uncompressed", "hybrid", NULL};
  int f = luaL_checkoption(L, i, defval, options);
  point_conversion_form_t form = 0;
  
  if (f == 0)
    form = POINT_CONVERSION_COMPRESSED;
  else if (f == 1)
    form = POINT_CONVERSION_UNCOMPRESSED;
  else if (f == 2)
    form = POINT_CONVERSION_HYBRID;
  else
    luaL_argerror(L, i, "invalid parameter, only support 'compressed', 'uncompressed' or 'hybrid'");
  
  return form;
}

int openssl_push_point_conversion_form(lua_State *L, point_conversion_form_t form)
{
  if (form == POINT_CONVERSION_COMPRESSED)
    lua_pushstring(L, "compressed");
  else if (form == POINT_CONVERSION_UNCOMPRESSED)
    lua_pushstring(L, "uncompressed");
  else if (form == POINT_CONVERSION_HYBRID)
    lua_pushstring(L, "hybrid");
  else
    lua_pushnil(L);
  
  return 1;
}

/***
Create a new EC point on this group.

@function point_new
@treturn ec_point new elliptic curve point (at infinity)
*/
static int openssl_group_point_new(lua_State *L)
{
  EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  EC_POINT *point = EC_POINT_new(group);
  
  if (point) {
    PUSH_OBJECT(point, "openssl.ec_point");
    return 1;
  }
  
  return 0;
}

/***
Duplicate an EC point on this group.

@function point_dup
@tparam ec_point point the EC point to duplicate
@treturn ec_point duplicated EC point
*/
static int openssl_group_point_dup(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  EC_POINT *dup = EC_POINT_dup(point, group);
  
  if (dup) {
    PUSH_OBJECT(dup, "openssl.ec_point");
    return 1;
  }
  
  return 0;
}

/***
Compare two EC points for equality.

@function point_equal
@tparam ec_point a first EC point
@tparam ec_point b second EC point
@treturn boolean true if equal, false otherwise
*/
int openssl_group_point_equal(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *a = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  const EC_POINT *b = CHECK_OBJECT(3, EC_POINT, "openssl.ec_point");
  BN_CTX *ctx = BN_CTX_new();
  int ret = EC_POINT_cmp(group, a, b, ctx);
  BN_CTX_free(ctx);
  
  lua_pushboolean(L, ret == 0);
  return 1;
}

/***
Convert EC point to octet string.

@function point2oct
@tparam ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil octet string representation or nil on failure
*/
int openssl_group_point2oct(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  point_conversion_form_t form = lua_isnone(L, 3)
                                   ? EC_GROUP_get_point_conversion_form(group)
                                   : openssl_to_point_conversion_form(L, 3, "uncompressed");
  size_t size = EC_POINT_point2oct(group, point, form, NULL, 0, NULL);
  
  if (size > 0) {
    unsigned char *oct = (unsigned char *)OPENSSL_malloc(size);
    size = EC_POINT_point2oct(group, point, form, oct, size, NULL);
    if (size > 0) {
      lua_pushlstring(L, (const char *)oct, size);
      OPENSSL_free(oct);
      return 1;
    }
    OPENSSL_free(oct);
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert octet string to EC point.

@function oct2point
@tparam string oct octet string representation
@treturn ec_point|nil the resulting EC point or nil on failure
*/
int openssl_group_oct2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  size_t size = 0;
  const unsigned char *oct = (const unsigned char *)luaL_checklstring(L, 2, &size);
  EC_POINT *point = EC_POINT_new(group);
  
  if (EC_POINT_oct2point(group, point, oct, size, NULL) == 1) {
    PUSH_OBJECT(point, "openssl.ec_point");
    return 1;
  }
  
  EC_POINT_free(point);
  lua_pushnil(L);
  return 1;
}

/***
Convert EC point to BIGNUM.

@function point2bn
@tparam ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn bn|nil the resulting BIGNUM or nil on failure
*/
int openssl_group_point2bn(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  point_conversion_form_t form = lua_isnone(L, 3)
                                   ? EC_GROUP_get_point_conversion_form(group)
                                   : openssl_to_point_conversion_form(L, 3, "uncompressed");
  BIGNUM *bn = EC_POINT_point2bn(group, point, form, NULL, NULL);
  
  if (bn) {
    PUSH_OBJECT(bn, "openssl.bn");
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert BIGNUM to EC point.

@function bn2point
@tparam bn bn the BIGNUM to convert
@treturn ec_point|nil the resulting EC point or nil on failure
*/
int openssl_group_bn2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const BIGNUM *bn = CHECK_OBJECT(2, BIGNUM, "openssl.bn");
  EC_POINT *point = EC_POINT_bn2point(group, bn, NULL, NULL);
  
  if (point) {
    PUSH_OBJECT(point, "openssl.ec_point");
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert EC point to hexadecimal string.

@function point2hex
@tparam ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil hexadecimal string representation or nil on failure
*/
int openssl_group_point2hex(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  point_conversion_form_t form = lua_isnone(L, 3)
                                   ? EC_GROUP_get_point_conversion_form(group)
                                   : openssl_to_point_conversion_form(L, 3, "uncompressed");
  char *hex = EC_POINT_point2hex(group, point, form, NULL);
  
  if (hex) {
    lua_pushstring(L, hex);
    OPENSSL_free(hex);
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert hexadecimal string to EC point.

@function hex2point
@tparam string hex hexadecimal string representation
@treturn ec_point|nil the resulting EC point or nil on failure
*/
int openssl_group_hex2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  const char *hex = luaL_checkstring(L, 2);
  EC_POINT *point = EC_POINT_hex2point(group, hex, NULL, NULL);
  
  if (point) {
    PUSH_OBJECT(point, "openssl.ec_point");
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Get or set affine coordinates of an EC point.

@function affine_coordinates
@tparam ec_point point the EC point
@tparam[opt] bn x x coordinate (for setting)
@tparam[opt] bn y y coordinate (for setting)
@treturn bn x coordinate (when getting)
@treturn bn y coordinate (when getting)
*/
int openssl_group_affine_coordinates(lua_State *L)
{
  EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  EC_POINT *point = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  
  if (lua_gettop(L) == 2) {
    /* Get coordinates */
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    if (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) == 1) {
      PUSH_BN(x);
      PUSH_BN(y);
      return 2;
    } else {
      BN_free(x);
      BN_free(y);
      return 0;
    }
  } else {
    /* Set coordinates */
    BIGNUM *x = CHECK_OBJECT(3, BIGNUM, "openssl.bn");
    BIGNUM *y = CHECK_OBJECT(4, BIGNUM, "openssl.bn");
    
    if (EC_POINT_set_affine_coordinates(group, point, x, y, NULL) == 1) {
      return 0;
    }
    
    return luaL_error(L, "EC_POINT_set_affine_coordinates failed");
  }
}

/***
Generate EC key pair from this group.

@function generate_key
@treturn ec_key generated EC key object or nil if failed
*/
int openssl_group_generate_key(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, MYTYPE);
  
  EC_KEY *ec = EC_KEY_new();
  if (ec) {
    int ret;
    EC_KEY_set_group(ec, group);
    ret = EC_KEY_generate_key(ec);
    if (ret == 1) {
      PUSH_OBJECT(ec, "openssl.ec_key");
      return 1;
    }
    EC_KEY_free(ec);
    return openssl_pushresult(L, ret);
  }
  return 0;
}

/***
List all available elliptic curve names.

@function list
@treturn table array of curve names and descriptions
*/
static int openssl_group_list(lua_State *L)
{
  size_t i = 0;
  size_t crv_len = EC_get_builtin_curves(NULL, 0);
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
}

/* Method table */
static luaL_Reg group_methods[] = {
  /* Object methods */
  {"dup",                   openssl_group_dup},
  {"generator",             openssl_group_generator},
  {"order",                 openssl_group_order},
  {"cofactor",              openssl_group_cofactor},
  {"degree",                openssl_group_degree},
  {"curve_name",            openssl_group_curve_name},
  {"asn1_flag",             openssl_group_asn1_flag},
  {"point_conversion_form", openssl_group_point_conversion_form},
  {"curve",                 openssl_group_curve},
  {"seed",                  openssl_group_seed},
  {"parse",                 openssl_group_parse},
  {"equal",                 openssl_group_equal},
  
  /* Point operations on group */
  {"point_new",             openssl_group_point_new},
  {"point_dup",             openssl_group_point_dup},
  {"point_equal",           openssl_group_point_equal},
  {"point2oct",             openssl_group_point2oct},
  {"oct2point",             openssl_group_oct2point},
  {"point2bn",              openssl_group_point2bn},
  {"bn2point",              openssl_group_bn2point},
  {"point2hex",             openssl_group_point2hex},
  {"hex2point",             openssl_group_hex2point},
  {"affine_coordinates",    openssl_group_affine_coordinates},
  {"generate_key",          openssl_group_generate_key},
  
  /* Metamethods */
  {"__eq",                  openssl_group_equal},
  {"__gc",                  openssl_group_free},
  {"__tostring",            openssl_group_tostring},
  
  {NULL,                    NULL}
};

/* Module functions */
static luaL_Reg group_functions[] = {
  {"new",  openssl_group_new},
  {"list", openssl_group_list},
  
  {NULL,   NULL}
};

/***
Open the EC group library.

@function luaopen_group
*/
int luaopen_group(lua_State *L)
{
  auxiliar_newclass(L, MYTYPE, group_methods);
  
  lua_newtable(L);
  luaL_setfuncs(L, group_functions, 0);
  
  lua_pushliteral(L, "version");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  
  return 1;
}

#endif /* OPENSSL_NO_EC */
