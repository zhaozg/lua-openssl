/***
 * pkey new module
 * Generate or create EVP_PKEY from parameters
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* ========================================================================
 * EC_KEY_generate_key_part - helper for EC key generation
 * ======================================================================== */

#ifndef OPENSSL_NO_EC
static int
EC_KEY_generate_key_part(EC_KEY *eckey)
{
  int             ok = 0;
  BN_CTX         *ctx = NULL;
  BIGNUM         *priv_key = NULL, *order = NULL;
  EC_POINT       *pub_key = NULL;
  const EC_GROUP *group;

  group = EC_KEY_get0_group(eckey);

  if ((order = BN_new()) == NULL) goto err;
  if ((ctx = BN_CTX_new()) == NULL) goto err;
  priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);

  if (priv_key == NULL) goto err;

  if (!EC_GROUP_get_order(group, order, ctx)) goto err;

  if (BN_is_zero(priv_key)) goto err;

  pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);

  if (pub_key == NULL) {
    pub_key = EC_POINT_new(group);
    if (pub_key == NULL) goto err;
    EC_KEY_set_public_key(eckey, pub_key);
    EC_POINT_free(pub_key);
    pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);
  }

  if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) goto err;

  EC_POINT_make_affine(EC_KEY_get0_group(eckey), pub_key, NULL);

  ok = 1;

err:
  if (order) BN_free(order);
  if (ctx != NULL) BN_CTX_free(ctx);

  return (ok);
}
#endif

/* ========================================================================
 * EC_GET_FIELD macro
 * ======================================================================== */

#define EC_GET_FIELD(_name)                                                                        \
  {                                                                                                \
    lua_getfield(L, -1, #_name);                                                                   \
    if (lua_isstring(L, -1)) {                                                                     \
      size_t      l = 0;                                                                           \
      const char *bn = luaL_checklstring(L, -1, &l);                                               \
      if (_name == NULL) _name = BN_new();                                                         \
      BN_bin2bn((const unsigned char *)bn, l, _name);                                              \
    } else if (auxiliar_getclassudata(L, "openssl.bn", -1)) {                                      \
      const BIGNUM *bn = CHECK_OBJECT(-1, BIGNUM, "openssl.bn");                                   \
      if (_name == NULL) _name = BN_new();                                                         \
      BN_copy(_name, bn);                                                                          \
    } else if (!lua_isnil(L, -1))                                                                  \
      luaL_error(L, "parameters must have \"%s\" field string or openssl.bn", #_name);             \
    lua_pop(L, 1);                                                                                 \
  }

/* ========================================================================
 * openssl_pkey_new
 * ======================================================================== */

/***
 * generate a new ec keypair
 * @function new
 * @tparam string alg alg must be 'ec'
 * @tparam string|number curvename this can be integer as curvename NID
 * @tparam[opt] integer flags when alg is ec need this.
 * @treturn openssl.evp_pkey object with mapping to EVP_PKEY in openssl
 */

/***
 * generate a new keypair
 * @function new
 * @tparam[opt='rsa'] string alg accept `rsa`,`dsa`,`dh`
 * @tparam[opt=2048|512] integer bits `rsa` with 2048, `dh` or `dsa` with 1024
 * @tparam[opt] integer e when alg is `rsa` give e value default is 0x10001,
 *  when alg is `dh` give generator value default is 2,
 *  when alg is `dsa` give string type seed value default is none.
 * @tparam[opt] openssl.engine eng
 * @treturn openssl.evp_pkey object with mapping to EVP_PKEY in openssl
 */

/***
 * create a new keypair by factors of keypair or get public key only
 * @function new
 * @tparam table factors create private/public key, key alg only accept accept 'rsa','dsa','dh','ec'
 * and must exist<\/br>
 * when arg is rsa, table may with key n,e,d,p,q,dmp1,dmq1,iqmp, both are binary string or openssl.bn<br>
 * when arg is dsa, table may with key p,q,g,priv_key,pub_key, both are binary string or openssl.bn<br>
 * when arg is dh, table may with key p,g,priv_key,pub_key, both are binary string or openssl.bn<br>
 * when arg is ec, table may with d,x,y,z,both are binary string or openssl.bn, and with curve_name,
 * enc_flag, conv_form<br>
 *
 * @treturn openssl.evp_pkey object with mapping to EVP_PKEY in openssl
 * @usage
 *  --create rsa public key
 *    pubkey = new({alg='rsa',n=...,e=...}
 *  --create new rsa
 *    rsa = new({alg='rsa',n=...,q=...,e=...,...}
 */
int
openssl_pkey_new(lua_State *L)
{
  EVP_PKEY   *pkey = NULL;
  const char *alg = "rsa";

  if (lua_isnoneornil(L, 1) || lua_isstring(L, 1)) {
    alg = luaL_optstring(L, 1, alg);
#ifndef OPENSSL_NO_RSA
    if (strcasecmp(alg, "rsa") == 0) {
      int     bits = luaL_optint(L, 2, 2048);
      int     e = luaL_optint(L, 3, 65537);
      ENGINE *eng = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
      BIGNUM *E = BN_new();

      luaL_argcheck(L, e > 0, 3, "e must be positive integer");
      BN_set_word(E, e);

      RSA *rsa = eng ? RSA_new_method(eng) : RSA_new();
      if (RSA_generate_key_ex(rsa, bits, E, NULL)) {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
      } else
        RSA_free(rsa);

      BN_free(E);
    } else
#endif
#ifndef OPENSSL_NO_DSA
      if (strcasecmp(alg, "dsa") == 0)
    {
      int         bits = luaL_optint(L, 2, 1024);
      size_t      seed_len = 0;
      const char *seed = luaL_optlstring(L, 3, NULL, &seed_len);
      ENGINE     *eng = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");

      DSA *dsa = eng ? DSA_new_method(eng) : DSA_new();
      if (DSA_generate_parameters_ex(dsa, bits, (byte *)seed, seed_len, NULL, NULL, NULL)
          && DSA_generate_key(dsa))
      {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(pkey, dsa);
      } else
        DSA_free(dsa);
    } else
#endif
#ifndef OPENSSL_NO_DH
      if (strcasecmp(alg, "dh") == 0)
    {
      int     bits = luaL_optint(L, 2, 1024);
      int     generator = luaL_optint(L, 3, 2);
      ENGINE *eng = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
      DH     *dh = eng ? DH_new_method(eng) : DH_new();
      if (DH_generate_parameters_ex(dh, bits, generator, NULL)) {
        if (DH_generate_key(dh)) {
          pkey = EVP_PKEY_new();
          EVP_PKEY_assign_DH(pkey, dh);
        } else
          DH_free(dh);
      } else
        DH_free(dh);
    } else
#endif
#ifndef OPENSSL_NO_EC
      if (strcasecmp(alg, "ec") == 0)
    {
      EC_GROUP *group = openssl_get_ec_group(L, 2, 3, 4);
      if (!group) luaL_error(L, "failed to get ec_group object");

      EC_KEY *ec = NULL;
      ec = EC_KEY_new();
      if (ec) {
        EC_KEY_set_group(ec, group);
        EC_GROUP_free(group);
        if (EC_KEY_generate_key(ec)) {
#if OPENSSL_VERSION_NUMBER > 0x30000000L
          EC_KEY_generate_key_part(ec);
#endif
          pkey = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(pkey, ec);
        } else
          EC_KEY_free(ec);
      } else
        EC_GROUP_free(group);
    }
#endif
    else
    {
      luaL_error(L, "not support %s!!!!", alg);
    }
  } else if (lua_istable(L, 1)) {
    /* contruct key from factors in Lua table */
    lua_getfield(L, 1, "alg");
    alg = luaL_optstring(L, -1, alg);
    lua_pop(L, 1);
#ifndef OPENSSL_NO_RSA
    if (strcasecmp(alg, "rsa") == 0) {
      BIGNUM *n = NULL, *e = NULL, *d = NULL;
      BIGNUM *p = NULL, *q = NULL;
      BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

      lua_getfield(L, 1, "n");
      n = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "e");
      e = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "d");
      d = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "p");
      p = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "q");
      q = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "dmp1");
      dmp1 = BN_get(L, -1);
      lua_pop(L, 1);
      lua_getfield(L, 1, "dmq1");
      dmq1 = BN_get(L, -1);
      lua_pop(L, 1);
      lua_getfield(L, 1, "iqmp");
      iqmp = BN_get(L, -1);
      lua_pop(L, 1);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      pkey = openssl_new_pkey_rsa_with(n, e, d,
                                       p, q, dmp1, dmq1, iqmp);
      BN_free(n);
      BN_free(e);
      BN_free(d);
      BN_free(p);
      BN_free(q);
      BN_free(dmp1);
      BN_free(dmq1);
      BN_free(iqmp);
#else
      pkey = EVP_PKEY_new();
      if (pkey) {
        RSA *rsa = RSA_new();
        if (rsa) {
          if (RSA_set0_key(rsa, n, e, d) == 1 && (p == NULL || RSA_set0_factors(rsa, p, q) == 1)
              && (dmp1 == NULL || RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) == 1))
          {
            if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
              RSA_free(rsa);
              rsa = NULL;
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          } else {
            RSA_free(rsa);
            rsa = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
#endif
    } else
#endif
#ifndef OPENSSL_NO_DSA
      if (strcasecmp(alg, "dsa") == 0)
    {
      BIGNUM *p = NULL, *q = NULL, *g = NULL;
      BIGNUM *priv_key = NULL, *pub_key = NULL;

      lua_getfield(L, 1, "p");
      p = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "q");
      q = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "g");
      g = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "priv_key");
      priv_key = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "pub_key");
      pub_key = BN_get(L, -1);
      lua_pop(L, 1);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      pkey = openssl_new_pkey_dsa_with(p, q, g, pub_key, priv_key);
      BN_free(p);
      BN_free(q);
      BN_free(g);
      BN_free(pub_key);
      BN_free(priv_key);
#else
      pkey = EVP_PKEY_new();
      if (pkey) {
        DSA *dsa = DSA_new();
        if (dsa) {
          if (DSA_set0_key(dsa, pub_key, priv_key) == 1 && DSA_set0_pqg(dsa, p, q, g)) {
            if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
              DSA_free(dsa);
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          } else {
            DSA_free(dsa);
            dsa = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
#endif
    } else
#endif
#ifndef OPENSSL_NO_DH
      if (strcasecmp(alg, "dh") == 0)
    {
      BIGNUM *p = NULL, *q = NULL, *g = NULL;
      BIGNUM *priv_key = NULL, *pub_key = NULL;

      lua_getfield(L, 1, "p");
      p = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "q");
      q = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "g");
      g = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "priv_key");
      priv_key = BN_get(L, -1);
      lua_pop(L, 1);

      lua_getfield(L, 1, "pub_key");
      pub_key = BN_get(L, -1);
      lua_pop(L, 1);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      pkey = openssl_new_pkey_dh_with(p, q, g, pub_key, priv_key);
      BN_free(p);
      BN_free(q);
      BN_free(g);
      BN_free(pub_key);
      BN_free(priv_key);
#else
      pkey = EVP_PKEY_new();
      if (pkey) {
        DH *dh = DH_new();
        if (dh) {
          if (DH_set0_key(dh, pub_key, priv_key) == 1 && DH_set0_pqg(dh, p, q, g)) {
            if (!EVP_PKEY_assign_DH(pkey, dh)) {
              DH_free(dh);
              dh = NULL;
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          } else {
            DH_free(dh);
            dh = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
#endif
    } else
#endif
#ifndef OPENSSL_NO_EC
      if (strcasecmp(alg, "ec") == 0)
    {
      BIGNUM   *d = NULL;
      BIGNUM   *x = NULL;
      BIGNUM   *y = NULL;
      BIGNUM   *z = NULL;
      EC_GROUP *group = NULL;

      lua_getfield(L, -1, "ec_name");
      if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, -1, "curve_name");
      }
      lua_getfield(L, -2, "conv_form");
      if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, -2, "param_enc");
      }
      lua_getfield(L, -3, "enc_flag");
      if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, -3, "asn1_flag");
      }
      group = openssl_get_ec_group(L, -3, -2, -1);
      lua_pop(L, 3);
      if (!group) luaL_error(L, "get openssl.ec_group fail");

      EC_GET_FIELD(d);
      EC_GET_FIELD(x);
      EC_GET_FIELD(y);
      EC_GET_FIELD(z);
      if (z) luaL_error(L, "only accpet affine co-ordinates");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      pkey = openssl_new_pkey_ec_with(group, x, y, d);
#else
      pkey = EVP_PKEY_new();
      if (pkey) {
        EC_KEY *ec = EC_KEY_new();
        if (ec) {
          EC_KEY_set_group(ec, group);
          if (d) EC_KEY_set_private_key(ec, d);
          if (x != NULL && y != NULL) {
            EC_POINT *pnt = EC_POINT_new(group);
            EC_POINT_set_affine_coordinates(group, pnt, x, y, NULL);

            EC_KEY_set_public_key(ec, pnt);
            EC_POINT_free(pnt);
          } else
            EC_KEY_generate_key_part(ec);

          if ((d != NULL && EC_KEY_check_key(ec) == 0)
            || EVP_PKEY_assign_EC_KEY(pkey, ec) == 0)  {
            EC_KEY_free(ec);
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
#endif
      BN_free(d);
      BN_free(x);
      BN_free(y);
      BN_free(z);
      EC_GROUP_free(group);
    }
#endif
  } else
#ifndef OPENSSL_NO_RSA
    if (auxiliar_getclassudata(L, "openssl.rsa", 1))
  {
    RSA *rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);
  } else
#endif
#ifndef OPENSSL_NO_EC
    if (auxiliar_getclassudata(L, "openssl.ec_key", 1))
  {
    EC_KEY *ec = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ec);
  } else
#endif
#ifndef OPENSSL_NO_DH
    if (auxiliar_getclassudata(L, "openssl.dh", 1))
  {
    DH *dh = CHECK_OBJECT(1, DH, "openssl.dh");
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_DH(pkey, dh);
  } else
#endif
#ifndef OPENSSL_NO_DSA
    if (auxiliar_getclassudata(L, "openssl.dsa", 1))
  {
    DSA *dsa = CHECK_OBJECT(1, DSA, "openssl.dsa");
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_DSA(pkey, dsa);
  }
#endif

  if (pkey && EVP_PKEY_id(pkey) != NID_undef) {
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
    return 1;
  } else
    EVP_PKEY_free(pkey);
  return 0;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
