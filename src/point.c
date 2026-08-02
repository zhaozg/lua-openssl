/***
EC_POINT module for Lua OpenSSL binding.

This module provides a complete wrapper for OpenSSL's EC_POINT operations,
enabling elliptic curve point mathematical operations.

@module ec.point
@usage
  point = require('openssl').ec.point
*/

/* This file is included in ec.c */

#define MYTYPE_POINT "openssl.ec_point"
#define MYVERSION_POINT MYTYPE_POINT " library for " LUA_VERSION " / Nov 2024"

/***
Create a new EC point on a given group.

@function new
@tparam openssl.ec_group group the EC group
@treturn openssl.ec_point new elliptic curve point (at infinity)
@usage
  group = require('openssl').group
  point = require('openssl').point
  g = group.new('prime256v1')
  p = point.new(g)
*/

/***
Copy one EC point to another.

@function copy
@tparam openssl.ec_point dest destination point
@tparam openssl.ec_point src source point
@treturn openssl.ec_point destination point (self)
*/
int openssl_point_copy(lua_State *L)
{
  EC_POINT *dest = CHECK_OBJECT(1, EC_POINT, MYTYPE_POINT);
  const EC_POINT *src = CHECK_OBJECT(2, EC_POINT, MYTYPE_POINT);

  if (EC_POINT_copy(dest, src)) {
    lua_pushvalue(L, 1);
    return 1;
  }

  return 0;
}

int openssl_point_free(lua_State *L)
{
  EC_POINT *point = CHECK_OBJECT(1, EC_POINT, MYTYPE_POINT);
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

/* Method table */
static luaL_Reg point_methods[] = {

/***
Duplicate an EC point on this group.

@function dup
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point to duplicate
@treturn openssl.ec_point duplicated EC point
*/
/***
Compare two EC points for equality.

@function equal
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point a first EC point
@tparam openssl.ec_point b second EC point
@treturn boolean true if equal, false otherwise
*/
/***
Add two EC points on this group.

@function add
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point a first point
@tparam openssl.ec_point b second point
@treturn openssl.ec_point result point (a + b)
*/
/***
Double an EC point on this group.

@function dbl
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point to double
@treturn openssl.ec_point result point (2 * point)
*/
/***
Invert an EC point in place on this group.

@function invert
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point to invert
@treturn openssl.ec_point self (inverted)
*/
/***
Multiply an EC point by a scalar on this group.

@function mul
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@tparam bn|number n scalar multiplier
@tparam[opt] openssl.ec_point q optional point for double scalar multiplication
@tparam[opt] openssl.bn m optional second scalar for double scalar multiplication
@treturn openssl.ec_point result point (n * point) or (n * point + m * q)
*/
/***
Check if an EC point is at infinity.

@function is_at_infinity
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@treturn boolean true if at infinity, false otherwise
*/
/***
Check if an EC point lies on the curve of this group.

@function is_on_curve
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@treturn boolean true if on curve, false otherwise
*/
/***
Set an EC point to infinity in place.

@function set_to_infinity
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@treturn openssl.ec_point self
*/
/***
Convert an EC point to an octet string.

@function point2oct
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil octet string representation or nil on failure
*/
/***
Convert an octet string to an EC point.

@function oct2point
@tparam openssl.ec_group group the EC group
@tparam string oct octet string representation
@treturn openssl.ec_point|nil the resulting EC point or nil on failure
*/
/***
Convert an EC point to a BIGNUM.

@function point2bn
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn openssl.bn|nil the resulting BIGNUM or nil on failure
*/
/***
Convert a BIGNUM to an EC point.

@function bn2point
@tparam openssl.ec_group group the EC group
@tparam openssl.bn bn the BIGNUM to convert
@treturn openssl.ec_point|nil the resulting EC point or nil on failure
*/
/***
Convert an EC point to a hexadecimal string.

@function point2hex
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@tparam[opt] string form point conversion form ("compressed", "uncompressed", or "hybrid")
@treturn string|nil hexadecimal string representation or nil on failure
*/
/***
Convert a hexadecimal string to an EC point.

@function hex2point
@tparam openssl.ec_group group the EC group
@tparam string hex hexadecimal string representation
@treturn openssl.ec_point|nil the resulting EC point or nil on failure
*/
/***
Get or set the affine coordinates of an EC point.

@function affine_coordinates
@tparam openssl.ec_group group the EC group
@tparam openssl.ec_point point the EC point
@tparam[opt] openssl.bn x x coordinate (for setting)
@tparam[opt] openssl.bn y y coordinate (for setting)
@treturn openssl.bn x coordinate (when getting)
@treturn[2] openssl.bn y coordinate (when getting)
*/

  /* Object methods */
  {"copy",                 openssl_point_copy},

  /* Metamethods */
  {"__gc",                 openssl_point_free},
  {"__tostring",           auxiliar_tostring},

  {NULL,                   NULL}
};

/* Module functions */
static luaL_Reg point_functions[] = {
  {"new",                  openssl_group_point_new},
  {"dup",                  openssl_group_point_dup},
  {"equal",                openssl_group_point_equal},
  {"add",                  openssl_point_add},
  {"dbl",                  openssl_point_dbl},
  {"invert",               openssl_point_invert},
  {"mul",                  openssl_point_mul},

  {"is_at_infinity",       openssl_point_is_at_infinity},
  {"is_on_curve",          openssl_point_is_on_curve},

  {"point2oct",            openssl_group_point2oct},
  {"oct2point",            openssl_group_oct2point},
  {"point2bn",             openssl_group_point2bn},
  {"bn2point",             openssl_group_bn2point},
  {"point2hex",            openssl_group_point2hex},
  {"hex2point",            openssl_group_hex2point},

  {"affine_coordinates",   openssl_group_affine_coordinates},
  {"set_to_infinity",      openssl_point_set_to_infinity},

  {NULL,                   NULL}
};

int
luaopen_ec_point(lua_State *L) {
  auxiliar_newclass(L, MYTYPE_POINT, point_methods);
  lua_newtable(L);
  luaL_setfuncs(L, point_functions, 0);
  return 1;
}

