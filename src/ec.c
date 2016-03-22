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
  const EC_GROUP* g = openssl_get_ec_group(L, 1, 2, 3);
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

static int openssl_ec_group_asn1_flag(lua_State*L)
{
  EC_GROUP* group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  int asn1_flag = 0;
  if (lua_isnone(L, 2))
  {
    asn1_flag = EC_GROUP_get_asn1_flag(group);
    if (asn1_flag == 0)
      lua_pushstring(L, "explicit");
    else if (asn1_flag == OPENSSL_EC_NAMED_CURVE)
      lua_pushstring(L, "named_curve");
    else
      lua_pushnil(L);
    lua_pushinteger(L, asn1_flag);
    return 2;
  }
  else if (lua_isstring(L, 2))
  {
    /* OPENSSL_EC_NAMED_CURVE,   0 */
    const char* const options[] = {"named_curve", "explicit", NULL};
    asn1_flag = luaL_checkoption(L, 2, NULL, options);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
  }
  else if (lua_isnumber(L, 2))
  {
    asn1_flag = luaL_checkint(L, 2);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
  }
  else
    luaL_argerror(L, 2, "not accept type of asn1 flag");

  return 0;
}

static int openssl_ec_group_point_conversion_form(lua_State*L)
{
  EC_GROUP* group = CHECK_OBJECT(1, EC_GROUP, "openssl.ec_group");
  point_conversion_form_t form = 0;
  if (lua_isnone(L, 2))
  {
    form = EC_GROUP_get_point_conversion_form(group);
    if (form == POINT_CONVERSION_COMPRESSED)
      lua_pushstring(L, "compressed");
    else if (form == POINT_CONVERSION_UNCOMPRESSED)
      lua_pushstring(L, "uncompressed");
    else if (form == POINT_CONVERSION_HYBRID)
      lua_pushstring(L, "hybrid");
    else
      lua_pushnil(L);
    lua_pushinteger(L, form);
    return 2;
  }
  else if (lua_isstring(L, 2))
  {
    const char* options[] = {"compressed", "uncompressed", "hybrid", NULL};
    int f = luaL_checkoption(L, 2, NULL, options);
    if (f == 0)
      form = POINT_CONVERSION_COMPRESSED;
    else if (f == 1)
      form = POINT_CONVERSION_UNCOMPRESSED;
    else if (f == 2)
      form = POINT_CONVERSION_HYBRID;
    else
      luaL_argerror(L, 2, "not accept value point_conversion_form");
    EC_GROUP_set_point_conversion_form(group, form);
  }
  else if (lua_isnumber(L, 2))
  {
    form = luaL_checkint(L, 2);
    EC_GROUP_set_point_conversion_form(group, form);
  }
  else
    luaL_argerror(L, 2, "not accept type of point_conversion_form");
  return 0;
}


EC_GROUP* openssl_get_ec_group(lua_State* L, int ec_name_idx, int param_enc_idx,
                               int conv_form_idx)
{
  int nid = NID_undef;
  EC_GROUP* g = NULL;
  if (lua_isnumber(L, ec_name_idx))
    nid = lua_tointeger(L, ec_name_idx);
  else if (lua_isstring(L, ec_name_idx))
  {
    const char* name = luaL_checkstring(L, ec_name_idx);
    nid = OBJ_sn2nid(name);
  }
  else if (lua_isuserdata(L, ec_name_idx))
  {
    if (auxiliar_isclass(L, "openssl.evp_pkey", ec_name_idx))
    {
      EVP_PKEY* pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
      EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
      if (ec_key)
      {
        g = (EC_GROUP*)EC_KEY_get0_group(ec_key);
        EC_KEY_free(ec_key);
      }
    }
    else if (auxiliar_isclass(L, "openssl.ec_key", ec_name_idx))
    {
      EC_KEY* ec_key = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
      g = (EC_GROUP*)EC_KEY_get0_group(ec_key);
    }
    if (g)
      g = EC_GROUP_dup(g);
  }

  if (g == NULL && nid != NID_undef)
    g = EC_GROUP_new_by_curve_name(nid);

  if (g)
  {
    if (param_enc_idx)
    {
      int form = 0;
      if (lua_isstring(L, param_enc_idx))
      {
        const char* options[] = {"compressed", "uncompressed", "hybrid", NULL};
        int f = luaL_checkoption(L, param_enc_idx, NULL, options);
        if (f == 0)
          form = POINT_CONVERSION_COMPRESSED;
        else if (f == 1)
          form = POINT_CONVERSION_UNCOMPRESSED;
        else if (f == 2)
          form = POINT_CONVERSION_HYBRID;
        else
          luaL_argerror(L, param_enc_idx, "not accept value point_conversion_form");
        EC_GROUP_set_point_conversion_form(g, form);
      }
      else if (lua_isnumber(L, param_enc_idx))
      {
        form = luaL_checkint(L, param_enc_idx);
        EC_GROUP_set_point_conversion_form(g, form);
      }
      else if (lua_isnoneornil(L, param_enc_idx))
      {
        EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_UNCOMPRESSED);
      }
      else
        luaL_argerror(L, param_enc_idx, "not accept type of point_conversion_form");
    }
    else
      EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_UNCOMPRESSED);

    if (conv_form_idx)
    {
      int asn1_flag = 0;
      if (lua_isstring(L, conv_form_idx))
      {
        /* OPENSSL_EC_NAMED_CURVE,   0 */
        const char* const options[] = {"named_curve", "explicit", NULL};
        asn1_flag = luaL_checkoption(L, conv_form_idx, NULL, options);
        EC_GROUP_set_asn1_flag(g, asn1_flag);
      }
      else if (lua_isnumber(L, conv_form_idx))
      {
        asn1_flag = luaL_checkint(L, conv_form_idx);
        EC_GROUP_set_asn1_flag(g, asn1_flag);
      }
      else if (lua_isnoneornil(L, conv_form_idx))
      {
        EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
      }
      else
        luaL_argerror(L, conv_form_idx, "not accept type of asn1 flag");
    }
    else
      EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
  }

  return g;
}

static luaL_Reg ec_group_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"affine_coordinates", openssl_ecpoint_affine_coordinates},
  {"parse", openssl_ec_group_parse},
  {"asn1_flag", openssl_ec_group_asn1_flag},
  {"point_conversion_form", openssl_ec_group_point_conversion_form},

  {"__gc", openssl_ec_group_free},

  { NULL, NULL }
};


static int openssl_ecdsa_sign(lua_State*L)
{
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t l;
  const char* s = luaL_checklstring(L, 2, &l);
  ECDSA_SIG* sig = ECDSA_do_sign((const unsigned char*)s, l, ec);
	int der = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L, 3);
	int ret = 0;

	if (der)
	{
		unsigned char*p = NULL;
		l = i2d_ECDSA_SIG(sig, &p);
		if (l > 0)
		{
			lua_pushlstring(L, (const char*)p, l);
			OPENSSL_free(p);
			ret = 1;
		}
	}
	else {
		BIGNUM *bn = BN_dup(sig->r);
		PUSH_OBJECT(bn, "openssl.bn");
		bn = BN_dup(sig->s);
		PUSH_OBJECT(bn, "openssl.bn");
		ret = 2;
	}
	ECDSA_SIG_free(sig);
  return ret;
}

static int openssl_ecdsa_verify(lua_State*L)
{
  size_t l, sigl;
  int ret;
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  const char* dgst = luaL_checklstring(L, 2, &l);
	int top = lua_gettop(L);
	if (top == 3)
	{
		const char* s = luaL_checklstring(L, 3, &sigl);;
		ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&s, sigl);
		ret = ECDSA_do_verify((const unsigned char*)dgst, l, sig, ec);
		if (ret == -1)
			ret = openssl_pushresult(L, -1);
		else 
		{
			lua_pushboolean(L, ret);
			ret = 1;
		}
		ECDSA_SIG_free(sig);
		return ret;
	}
	else
	{
		BIGNUM *r = BN_get(L, 3);
		BIGNUM *s = BN_get(L, 4);
		ECDSA_SIG* sig = ECDSA_SIG_new();
		BN_copy(sig->r, r);
		BN_copy(sig->s, s);
		ret = ECDSA_do_verify((const unsigned char*)dgst, l, sig, ec);
		if (ret == -1)
			ret = openssl_pushresult(L, -1);
		else
		{
			lua_pushboolean(L, ret);
			ret = 1;
		}
		ECDSA_SIG_free(sig);
		return ret;
	}
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
  return 0;
}

static int openssl_ec_key_parse(lua_State*L)
{
  EC_KEY* ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  int basic = luaL_opt(L, lua_toboolean, 2, 0);
  const EC_POINT* point = EC_KEY_get0_public_key(ec);
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  const BIGNUM *priv = EC_KEY_get0_private_key(ec);
  lua_newtable(L);
  if (basic)
  {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    AUXILIAR_SET(L, -1, "enc_flag", EC_KEY_get_enc_flags(ec), integer);
    AUXILIAR_SET(L, -1, "conv_form", EC_KEY_get_conv_form(ec), integer);
    AUXILIAR_SET(L, -1, "curve_name", EC_GROUP_get_curve_name(group), integer);

    priv = BN_dup(priv);
    AUXILIAR_SETOBJECT(L, priv, "openssl.bn", -1, "d");

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
  size_t i = 0;
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
  for (i = 0; i < crv_len; i++)
  {
    const char *comment;
    const char *sname;
    comment = curves[i].comment;
    sname   = OBJ_nid2sn(curves[i].nid);
    if (comment == NULL) comment = "CURVE DESCRIPTION NOT AVAILABLE";
    if (sname == NULL)  sname = "";

    AUXILIAR_SET(L, -1, sname, comment, string);
  }

  OPENSSL_free(curves);
  return 1;
};

static luaL_Reg R[] =
{
  {"list",     openssl_ec_list_curve_name},
  {"group",    openssl_eckey_group},

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

