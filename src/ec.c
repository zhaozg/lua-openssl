/*=========================================================================*\
* ec.c
* EC routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

#define MYNAME    "ec"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

#define lua_boxpointer(L,u) \
  (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define PUSH_BN(x) \
lua_boxpointer(L,x);  \
luaL_getmetatable(L,"openssl.bn");  \
lua_setmetatable(L,-2);


#ifndef OPENSSL_NO_EC

static int openssl_ecpoint_affine_coordinates(lua_State *L)
{
  EC_GROUP* g = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_POINT* p = CHECK_OBJECT(2, EC_POINT, "openssl.ec_point");
  int ret = 0;
  if (lua_gettop(L) == 2)
  {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(g, p, x, y, NULL) == 1)
    {
      PUSH_BN(x);
      PUSH_BN(y);
      ret = 2;
    };
  }
  else
  {
    BIGNUM* x = CHECK_OBJECT(3, BIGNUM, "openssl.bn");
    BIGNUM* y = CHECK_OBJECT(4, BIGNUM, "openssl.bn");
    ret = EC_POINT_set_affine_coordinates_GFp(g, p, x, y, NULL);
    if (ret == 0)
      luaL_error(L, "EC_POINT_set_affine_coordinates_GFp fail");
    ret = 0;
  }
  return ret;
}

static int openssl_eckey_group(lua_State *L)
{
  int nid = NID_undef;
  const EC_GROUP* g = NULL;
  if (lua_isnumber(L, 1))
    nid = lua_tointeger(L, 1);
  else if (lua_isstring(L, 1))
  {
    const char* name = luaL_checkstring(L, 1);
    nid = OBJ_sn2nid(name);
  }
  else if (lua_isuserdata(L, 1))
  {
    if (auxiliar_isclass(L, "openssl.evp_pkey", 1))
    {
      EVP_PKEY* pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
      EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
      if (ec_key)
      {
        g = EC_KEY_get0_group(ec_key);
        EC_KEY_free(ec_key);
      }
    }
    else if (auxiliar_isclass(L, "openssl.ec_key", 1))
    {
      EC_KEY* ec_key = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
      g = EC_KEY_get0_group(ec_key);
    }
    if (g)
      g = EC_GROUP_dup(g);
  }
  if (nid != NID_undef)
    g = EC_GROUP_new_by_curve_name(nid);

  if (g)
  {
    const EC_POINT* p = EC_GROUP_get0_generator(g);
    p = EC_POINT_dup(p, g);
    PUSH_OBJECT(g, "openssl.ec_group");
    PUSH_OBJECT(p, "openssl.ec_point");
    return 2;
  }
  return 0;
};

static int openssl_ec_group_parse(lua_State*L)
{
  const EC_GROUP* group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  const EC_POINT *generator = EC_GROUP_get0_generator(group);
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM *a, *b, *p, *order, *cofactor;

  lua_newtable(L);
  if (generator)
  {
    generator = EC_POINT_dup(generator, group);
    AUXILIAR_SETOBJECT(L, generator, "openssl.ec_point", -1, "generator");
  }

  order = BN_new();
  EC_GROUP_get_order(group, order, ctx);
  AUXILIAR_SETOBJECT(L, order, "openssl.bn", -1, "order");

  cofactor = BN_new();
  EC_GROUP_get_cofactor(group, cofactor, ctx);
  AUXILIAR_SETOBJECT(L, cofactor, "openssl.bn", -1, "cofactor");

  AUXILIAR_SET(L, -1, "asn1_flag", EC_GROUP_get_asn1_flag(group), integer);
  AUXILIAR_SET(L, -1, "degree", EC_GROUP_get_degree(group), integer);
  AUXILIAR_SET(L, -1, "curve_name", EC_GROUP_get_curve_name(group), integer);
  AUXILIAR_SET(L, -1, "conversion_form", EC_GROUP_get_point_conversion_form(group), integer);

  AUXILIAR_SETLSTR(L, -1, "seed", EC_GROUP_get0_seed(group), EC_GROUP_get_seed_len(group));

  a = BN_new();
  b = BN_new();
  p = BN_new();
  EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
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
static int openssl_ec_group_free(lua_State*L)
{
  EC_GROUP* group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  EC_GROUP_free(group);
  return 0;
}

static luaL_Reg ec_group_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"affine_coordinates", openssl_ecpoint_affine_coordinates},
  {"parse", openssl_ec_group_parse},
  {"__gc", openssl_ec_group_free},

  { NULL, NULL }
};


static int openssl_ecdsa_sign(lua_State*L)
{
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t l;
  const char* s = luaL_checklstring(L, 2, &l);
  ECDSA_SIG* sig = ECDSA_do_sign((const unsigned char*)s, l, ec);
  if (sig)
  {
    PUSH_BN(BN_dup(sig->r));
    PUSH_BN(BN_dup(sig->s));
    ECDSA_SIG_free(sig);
    return 2;
  }
  return 0;
}

static int openssl_ecdsa_verify(lua_State*L)
{
  size_t l;
  int ret;
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  const char* dgst = luaL_checklstring(L, 2, &l);
  BIGNUM *r = CHECK_OBJECT(3, BIGNUM, "openssl.bn");
  BIGNUM *s = CHECK_OBJECT(4, BIGNUM, "openssl.bn");

  ECDSA_SIG* sig = ECDSA_SIG_new();
  BN_copy(sig->r, r);
  BN_copy(sig->s, s);

  ret = ECDSA_do_verify((const unsigned char*)dgst, l, sig, ec);
  if (ret == -1)
    lua_pushnil(L);
  else
    lua_pushboolean(L, ret);
  ECDSA_SIG_free(sig);
  return 1;
}

static int openssl_ec_point_free(lua_State*L)
{
  EC_POINT* p = CHECK_OBJECT(1, EC_POINT, "openssl.ec_point");
  EC_POINT_free(p);
  return 0;
}

static int openssl_ec_key_free(lua_State*L)
{
  EC_KEY* p = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  EC_KEY_free(p);
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  return 0;
}

static int openssl_ec_key_parse(lua_State*L)
{
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  int basic = luaL_opt(L,lua_toboolean, 2, 0);
  const EC_POINT* point = EC_KEY_get0_public_key(ec);
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  const BIGNUM *priv = EC_KEY_get0_private_key(ec);
  lua_newtable(L);
  if (basic)
  {
    AUXILIAR_SET(L, -1, "enc_flag", EC_KEY_get_enc_flags(ec), integer);
    AUXILIAR_SET(L, -1, "conv_form", EC_KEY_get_conv_form(ec), integer);
    AUXILIAR_SET(L, -1, "curve_name", EC_GROUP_get_curve_name(group), integer);

    AUXILIAR_SETOBJECT(L, BN_dup(priv), "openssl.bn", -1, "d");

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL) == 1)
    {
      AUXILIAR_SETOBJECT(L, x, "openssl.bn", -1, "x");
      AUXILIAR_SETOBJECT(L, y, "openssl.bn", -1, "y");
    };
  }
  else
  {
    AUXILIAR_SET(L, -1, "enc_flag", EC_KEY_get_enc_flags(ec), integer);
    AUXILIAR_SET(L, -1, "conv_form", EC_KEY_get_conv_form(ec), integer);

    point = EC_POINT_dup(point, group);
    AUXILIAR_SETOBJECT(L, point, "openssl.ec_point", -1, "pub_key");
    group = EC_GROUP_dup(group);
    AUXILIAR_SETOBJECT(L, group, "openssl.ec_group", -1, "group");

    OPENSSL_PKEY_GET_BN(priv, priv_key);
  }
  return 1;
};

static luaL_Reg ec_key_funs[] =
{
  {"parse",       openssl_ec_key_parse},
  {"sign",        openssl_ecdsa_sign},
  {"verify",      openssl_ecdsa_verify},
  {"__gc",        openssl_ec_key_free},
  {"__tostring",  auxiliar_tostring},

  { NULL, NULL }
};

static luaL_Reg ec_point_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"__gc", openssl_ec_point_free},

  { NULL, NULL }
};


static LUA_FUNCTION(openssl_ec_list_curve_name)
{
  size_t n = 0;
  size_t crv_len = EC_get_builtin_curves(NULL, 0);
  EC_builtin_curve *curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));

  if (curves == NULL)
    return 0;

  if (!EC_get_builtin_curves(curves, crv_len))
  {
    OPENSSL_free(curves);
    return 0;
  }

  lua_newtable(L);
  for (n = 0; n < crv_len; n++)
  {
    const char *comment;
    const char *sname;
    comment = curves[n].comment;
    sname   = OBJ_nid2sn(curves[n].nid);
    if (comment == NULL) comment = "CURVE DESCRIPTION NOT AVAILABLE";
    if (sname == NULL)  sname = "";

    AUXILIAR_SET(L, -1, sname, comment, string);
  }

  OPENSSL_free(curves);
  return 1;
};

static luaL_Reg R[] =
{
  {"list", openssl_ec_list_curve_name},
  {"group", openssl_eckey_group},

  { NULL, NULL }
};

int luaopen_ec(lua_State *L)
{
  auxiliar_newclass(L, "openssl.ec_point",   ec_point_funs);
  auxiliar_newclass(L, "openssl.ec_group",   ec_group_funs);
  auxiliar_newclass(L, "openssl.ec_key",   ec_key_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}

#endif

