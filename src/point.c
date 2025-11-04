/***
EC_POINT module for Lua OpenSSL binding.

This module provides a complete wrapper for OpenSSL's EC_POINT operations,
enabling elliptic curve point mathematical operations.

@module point
@usage
  point = require('openssl').point
*/

#include "openssl.h"
#include "private.h"

#if !defined(OPENSSL_NO_EC)
#include <openssl/ec.h>
#include <openssl/bn.h>

#define MYNAME "point"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2024"
#define MYTYPE "openssl.ec_point"

/* Forward declaration for point conversion form helper */
static point_conversion_form_t openssl_to_point_conversion_form(lua_State *L, int i, const char *defval);

/***
Create a new EC point on a given group.

@function new
@tparam ec_group group the EC group
@treturn ec_point new elliptic curve point (at infinity)
@usage
  group = require('openssl').group
  point = require('openssl').point
  g = group.new('prime256v1')
  p = point.new(g)
*/
static int openssl_point_new(lua_State *L)
{
  EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_POINT *point = EC_POINT_new(group);
  
  if (point) {
    PUSH_OBJECT(point, MYTYPE);
    return 1;
  }
  
  return 0;
}

/***
Duplicate an EC point.

@function dup
@tparam ec_group group the EC group
@tparam ec_point point the EC point to duplicate
@treturn ec_point duplicated EC point
*/
static int openssl_point_dup(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  EC_POINT *dup = EC_POINT_dup(point, group);
  
  if (dup) {
    PUSH_OBJECT(dup, MYTYPE);
    return 1;
  }
  
  return 0;
}

/***
Copy one EC point to another.

@function copy
@tparam ec_point dest destination point
@tparam ec_point src source point
@treturn ec_point destination point (self)
*/
static int openssl_point_copy(lua_State *L)
{
  EC_POINT *dest = CHECK_OBJECT(1, EC_POINT, MYTYPE);
  const EC_POINT *src = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  
  if (EC_POINT_copy(dest, src)) {
    lua_pushvalue(L, 1);
    return 1;
  }
  
  return 0;
}

/***
Set EC point to infinity.

@function set_to_infinity
@tparam ec_group group the EC group
@treturn ec_point self
*/
static int openssl_point_set_to_infinity(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  
  if (EC_POINT_set_to_infinity(group, point)) {
    lua_pushvalue(L, 2);
    return 1;
  }
  
  return 0;
}

/***
Check if EC point is at infinity.

@function is_at_infinity
@tparam ec_group group the EC group
@treturn boolean true if at infinity, false otherwise
*/
static int openssl_point_is_at_infinity(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  
  lua_pushboolean(L, EC_POINT_is_at_infinity(group, point));
  return 1;
}

/***
Check if EC point is on the curve.

@function is_on_curve
@tparam ec_group group the EC group
@treturn boolean true if on curve, false otherwise
*/
static int openssl_point_is_on_curve(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  BN_CTX *ctx = BN_CTX_new();
  int ret = EC_POINT_is_on_curve(group, point, ctx);
  BN_CTX_free(ctx);
  
  lua_pushboolean(L, ret);
  return 1;
}

/***
Compare two EC points for equality.

@function equal
@tparam ec_group group the EC group
@tparam ec_point a first EC point
@tparam ec_point b second EC point
@treturn boolean true if equal, false otherwise
*/
static int openssl_point_equal(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *a = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  const EC_POINT *b = CHECK_OBJECT(3, EC_POINT, MYTYPE);
  BN_CTX *ctx = BN_CTX_new();
  int ret = EC_POINT_cmp(group, a, b, ctx);
  BN_CTX_free(ctx);
  
  lua_pushboolean(L, ret == 0);
  return 1;
}

/***
Get or set affine coordinates of an EC point.

@function affine_coordinates
@tparam ec_group group the EC group
@tparam[opt] bn x x coordinate (for setting)
@tparam[opt] bn y y coordinate (for setting)
@treturn bn x coordinate (when getting)
@treturn bn y coordinate (when getting)
*/
static int openssl_point_affine_coordinates(lua_State *L)
{
  EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  
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
      lua_pushvalue(L, 2);
      return 1;
    }
    
    return luaL_error(L, "EC_POINT_set_affine_coordinates failed");
  }
}

/***
Add two EC points.

@function add
@tparam ec_group group the EC group
@tparam ec_point a first point
@tparam ec_point b second point
@treturn ec_point result point (a + b)
*/
static int openssl_point_add(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *a = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  const EC_POINT *b = CHECK_OBJECT(3, EC_POINT, MYTYPE);
  EC_POINT *r = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_POINT_add(group, r, a, b, ctx)) {
    BN_CTX_free(ctx);
    PUSH_OBJECT(r, MYTYPE);
    return 1;
  }
  
  BN_CTX_free(ctx);
  EC_POINT_free(r);
  return 0;
}

/***
Double an EC point.

@function dbl
@tparam ec_group group the EC group
@treturn ec_point result point (2 * point)
*/
static int openssl_point_dbl(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  EC_POINT *r = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_POINT_dbl(group, r, point, ctx)) {
    BN_CTX_free(ctx);
    PUSH_OBJECT(r, MYTYPE);
    return 1;
  }
  
  BN_CTX_free(ctx);
  EC_POINT_free(r);
  return 0;
}

/***
Invert an EC point.

@function invert
@tparam ec_group group the EC group
@treturn ec_point self (inverted)
*/
static int openssl_point_invert(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  BN_CTX *ctx = BN_CTX_new();
  
  if (EC_POINT_invert(group, point, ctx)) {
    BN_CTX_free(ctx);
    lua_pushvalue(L, 2);
    return 1;
  }
  
  BN_CTX_free(ctx);
  return 0;
}

/***
Multiply EC point by a scalar.

@function mul
@tparam ec_group group the EC group
@tparam bn|number n scalar multiplier
@tparam[opt] ec_point q optional point for double scalar multiplication
@tparam[opt] bn m optional second scalar for double scalar multiplication
@treturn ec_point result point (n * point) or (n * point + m * q)
*/
static int openssl_point_mul(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
  BIGNUM *n = NULL;
  const EC_POINT *q = NULL;
  const BIGNUM *m = NULL;
  EC_POINT *r = EC_POINT_new(group);
  BN_CTX *ctx = BN_CTX_new();
  int ret;
  
  /* Get scalar n */
  if (lua_isnumber(L, 3)) {
    n = BN_new();
    BN_set_word(n, lua_tointeger(L, 3));
  } else {
    n = CHECK_OBJECT(3, BIGNUM, "openssl.bn");
  }
  
  /* Check for double scalar multiplication */
  if (!lua_isnone(L, 4)) {
    q = CHECK_OBJECT(4, EC_POINT, MYTYPE);
    m = CHECK_OBJECT(5, BIGNUM, "openssl.bn");
    ret = EC_POINT_mul(group, r, NULL, point, n, ctx);
    if (ret) {
      EC_POINT *temp = EC_POINT_new(group);
      ret = EC_POINT_mul(group, temp, NULL, q, m, ctx);
      if (ret) {
        ret = EC_POINT_add(group, r, r, temp, ctx);
      }
      EC_POINT_free(temp);
    }
  } else {
    ret = EC_POINT_mul(group, r, NULL, point, n, ctx);
  }
  
  if (lua_isnumber(L, 3)) {
    BN_free(n);
  }
  BN_CTX_free(ctx);
  
  if (ret) {
    PUSH_OBJECT(r, MYTYPE);
    return 1;
  }
  
  EC_POINT_free(r);
  return 0;
}

/***
Convert octet string to EC point.

@function oct2point
@tparam ec_group group the EC group
@tparam string oct octet string representation
@treturn ec_point|nil the resulting EC point or nil on failure
*/
static int openssl_point_oct2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  size_t size = 0;
  const unsigned char *oct = (const unsigned char *)luaL_checklstring(L, 2, &size);
  EC_POINT *point = EC_POINT_new(group);
  
  if (EC_POINT_oct2point(group, point, oct, size, NULL) == 1) {
    PUSH_OBJECT(point, MYTYPE);
    return 1;
  }
  
  EC_POINT_free(point);
  lua_pushnil(L);
  return 1;
}

/***
Convert EC point to octet string.

@function point2oct
@tparam ec_group group the EC group
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil octet string representation or nil on failure
*/
static int openssl_point_point2oct(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
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
Convert BIGNUM to EC point.

@function bn2point
@tparam ec_group group the EC group
@tparam bn bn the BIGNUM to convert
@treturn ec_point|nil the resulting EC point or nil on failure
*/
static int openssl_point_bn2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const BIGNUM *bn = CHECK_OBJECT(2, BIGNUM, "openssl.bn");
  EC_POINT *point = EC_POINT_bn2point(group, bn, NULL, NULL);
  
  if (point) {
    PUSH_OBJECT(point, MYTYPE);
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert EC point to BIGNUM.

@function point2bn
@tparam ec_group group the EC group
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn bn|nil the resulting BIGNUM or nil on failure
*/
static int openssl_point_point2bn(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
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
Convert hexadecimal string to EC point.

@function hex2point
@tparam ec_group group the EC group
@tparam string hex hexadecimal string representation
@treturn ec_point|nil the resulting EC point or nil on failure
*/
static int openssl_point_hex2point(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const char *hex = luaL_checkstring(L, 2);
  EC_POINT *point = EC_POINT_hex2point(group, hex, NULL, NULL);
  
  if (point) {
    PUSH_OBJECT(point, MYTYPE);
    return 1;
  }
  
  lua_pushnil(L);
  return 1;
}

/***
Convert EC point to hexadecimal string.

@function point2hex
@tparam ec_group group the EC group
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil hexadecimal string representation or nil on failure
*/
static int openssl_point_point2hex(lua_State *L)
{
  const EC_GROUP *group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *point = CHECK_OBJECT(2, EC_POINT, MYTYPE);
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
Free the EC point (internal, called by __gc).

@function free
*/
static int openssl_point_free(lua_State *L)
{
  EC_POINT *point = CHECK_OBJECT(1, EC_POINT, MYTYPE);
  EC_POINT_free(point);
  return 0;
}

/***
Convert EC point to string (internal, called by __tostring).

@function tostring
@treturn string string representation
*/
static int openssl_point_tostring(lua_State *L)
{
  lua_pushfstring(L, "openssl.ec_point: %p", lua_touserdata(L, 1));
  return 1;
}

/* Helper function */
static point_conversion_form_t openssl_to_point_conversion_form(lua_State *L, int i, const char *defval)
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

/* Method table */
static luaL_Reg point_methods[] = {
  /* Object methods */
  {"dup",                  openssl_point_dup},
  {"copy",                 openssl_point_copy},
  {"set_to_infinity",      openssl_point_set_to_infinity},
  {"is_at_infinity",       openssl_point_is_at_infinity},
  {"is_on_curve",          openssl_point_is_on_curve},
  {"equal",                openssl_point_equal},
  {"affine_coordinates",   openssl_point_affine_coordinates},
  {"add",                  openssl_point_add},
  {"dbl",                  openssl_point_dbl},
  {"invert",               openssl_point_invert},
  {"mul",                  openssl_point_mul},
  {"oct2point",            openssl_point_oct2point},
  {"point2oct",            openssl_point_point2oct},
  {"bn2point",             openssl_point_bn2point},
  {"point2bn",             openssl_point_point2bn},
  {"hex2point",            openssl_point_hex2point},
  {"point2hex",            openssl_point_point2hex},
  
  /* Metamethods */
  {"__gc",                 openssl_point_free},
  {"__tostring",           openssl_point_tostring},
  
  {NULL,                   NULL}
};

/* Module functions */
static luaL_Reg point_functions[] = {
  {"new",                  openssl_point_new},
  {"dup",                  openssl_point_dup},
  {"equal",                openssl_point_equal},
  {"set_to_infinity",      openssl_point_set_to_infinity},
  {"is_at_infinity",       openssl_point_is_at_infinity},
  {"is_on_curve",          openssl_point_is_on_curve},
  {"affine_coordinates",   openssl_point_affine_coordinates},
  {"add",                  openssl_point_add},
  {"dbl",                  openssl_point_dbl},
  {"invert",               openssl_point_invert},
  {"mul",                  openssl_point_mul},
  {"oct2point",            openssl_point_oct2point},
  {"point2oct",            openssl_point_point2oct},
  {"bn2point",             openssl_point_bn2point},
  {"point2bn",             openssl_point_point2bn},
  {"hex2point",            openssl_point_hex2point},
  {"point2hex",            openssl_point_point2hex},
  
  {NULL,                   NULL}
};

/***
Open the EC point library.

@function luaopen_point
*/
int luaopen_point(lua_State *L)
{
  auxiliar_newclass(L, MYTYPE, point_methods);
  
  lua_newtable(L);
  luaL_setfuncs(L, point_functions, 0);
  
  lua_pushliteral(L, "version");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  
  return 1;
}

#endif /* OPENSSL_NO_EC */
