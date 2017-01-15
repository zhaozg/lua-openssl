/*=========================================================================*\
* pkey.c
* pkey module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>

#define MYNAME    "pkey"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static int openssl_pkey_bits(lua_State *L)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  lua_Integer ret = EVP_PKEY_bits(pkey);
  lua_pushinteger(L, ret);
  return  1;
};

int openssl_pkey_is_private(EVP_PKEY* pkey)
{
  int ret = 1;
  int typ;
  assert(pkey != NULL);
  typ = EVP_PKEY_type(EVP_PKEY_id(pkey));
  switch (typ)
  {
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA:
  {
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    const BIGNUM *d = NULL;

    RSA_get0_key(rsa, NULL, NULL, &d);
    ret = d != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA:
  {
    DSA *dsa = EVP_PKEY_get0_DSA(pkey);
    const BIGNUM *p = NULL;
    DSA_get0_key(dsa, NULL, &p);
    ret = p != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_DH
  case EVP_PKEY_DH:
  {
    DH *dh = EVP_PKEY_get0_DH(pkey);
    const BIGNUM *p = NULL;
    DH_get0_key(dh, NULL, &p);
    ret = p != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
  {
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    const BIGNUM *p = EC_KEY_get0_private_key(ec);
    ret = p != NULL;
    break;
  }
#endif
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int openssl_pkey_read(lua_State*L)
{
  EVP_PKEY * key = NULL;
  BIO* in = load_bio_object(L, 1);
  int priv = lua_isnoneornil(L, 2) ? 0 : auxiliar_checkboolean(L, 2);
  int fmt = luaL_checkoption(L, 3, "auto", format);
  const char* passphrase = luaL_optstring(L, 4, NULL);
  int type = -1;
  if (passphrase)
  {
    if (strcmp(passphrase, "rsa") == 0 || strcmp(passphrase, "RSA") == 0)
      type = EVP_PKEY_RSA;
    else if (strcmp(passphrase, "dsa") == 0 || strcmp(passphrase, "DSA") == 0)
      type = EVP_PKEY_DSA;
    else if (strcmp(passphrase, "ec") == 0 || strcmp(passphrase, "EC") == 0)
      type = EVP_PKEY_EC;
    else if (strcmp(passphrase, "dh") == 0 || strcmp(passphrase, "DH") == 0)
      type = EVP_PKEY_DH;
  }

  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }

  if (!priv)
  {
    if (fmt == FORMAT_PEM)
    {
      switch (type)
      {
      case EVP_PKEY_RSA:
      {
        RSA* rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);
        if (rsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
      case EVP_PKEY_DSA:
      {
        DSA* dsa = PEM_read_bio_DSA_PUBKEY(in, NULL, NULL, NULL);
        if (dsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
      case EVP_PKEY_DH:
      {
        DH *dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
        if (dh)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DH(key, dh);
        }
        break;
      }
      case EVP_PKEY_EC:
      {
        EC_KEY *ec = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        if (ec)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
      default:
      {
        key = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
        break;
      }
      }
      BIO_reset(in);
    }
    else if (fmt == FORMAT_DER)
    {
      switch (type)
      {
      case EVP_PKEY_RSA:
      {
        RSA *rsa = d2i_RSAPublicKey_bio(in, NULL);
        if (rsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
      case EVP_PKEY_DSA:
      case EVP_PKEY_DH:
      case EVP_PKEY_EC:
      {
        char * bio_mem_ptr;
        long bio_mem_len;
        const unsigned char **pp;
        bio_mem_len = BIO_get_mem_data(in, &bio_mem_ptr);
        pp = (const unsigned char **)&bio_mem_ptr;

        key = d2i_PublicKey(type, NULL, pp, bio_mem_len);
      }
      /*
      case EVP_PKEY_DSA:
      {
        DSA *dsa = d2i_DSA_PUBKEY_bio(in, NULL);
        if (dsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
      case EVP_PKEY_DH:
      {
        DH *dh = d2i_DHparams_bio(in, NULL);
        if (dh)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DH(key, dh);
        }
        break;
      }
      case EVP_PKEY_EC:
      {
        EC_KEY *ec = d2i_EC_PUBKEY_bio(in, NULL);
        if (ec)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
      */
      default:
        key = d2i_PUBKEY_bio(in, NULL);
        break;
      }
      BIO_reset(in);
    }
  }
  else
  {
    if (fmt == FORMAT_PEM)
    {
      key = PEM_read_bio_PrivateKey(in, NULL, NULL, (void*)passphrase);
      BIO_reset(in);
    }
    else if (fmt == FORMAT_DER)
    {
      switch (type)
      {
      case EVP_PKEY_RSA:
      {
        RSA *rsa = d2i_RSAPrivateKey_bio(in, NULL);
        if (rsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
      case EVP_PKEY_DSA:
      {
        DSA *dsa = d2i_DSAPrivateKey_bio(in, NULL);
        if (dsa)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
      case EVP_PKEY_DH:
      {
        DH *dh = d2i_DHparams_bio(in, NULL);
        if (dh)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DH(key, dh);
        }
      }
      case EVP_PKEY_EC:
      {
        EC_KEY *ec = d2i_ECPrivateKey_bio(in, NULL);
        if (ec)
        {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
      default:
      {
        if (passphrase)
          key = d2i_PKCS8PrivateKey_bio(in, NULL, NULL, (void*)passphrase);
        else
          key = d2i_PrivateKey_bio(in, NULL);
        break;
      }
      }
      BIO_reset(in);
    }
  }
  BIO_free(in);
  if (key)
  {
    PUSH_OBJECT(key, "openssl.evp_pkey");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int EC_KEY_generate_key_part(EC_KEY *eckey)
{
  int ok = 0;
  BN_CTX  *ctx = NULL;
  BIGNUM  *priv_key = NULL, *order = NULL;
  EC_POINT *pub_key = NULL;
  const EC_GROUP *group;

  if (!eckey)
  {
    return 0;
  }
  group = EC_KEY_get0_group(eckey);

  if ((order = BN_new()) == NULL) goto err;
  if ((ctx = BN_CTX_new()) == NULL) goto err;
  priv_key = (BIGNUM*)EC_KEY_get0_private_key(eckey);

  if (priv_key == NULL)
  {
    goto err;
  }

  if (!EC_GROUP_get_order(group, order, ctx))
    goto err;

  if (BN_is_zero(priv_key))
    goto err;
  pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);

  if (pub_key == NULL)
  {
    pub_key = EC_POINT_new(group);
    if (pub_key == NULL)
      goto err;
    EC_KEY_set_public_key(eckey, pub_key);
    EC_POINT_free(pub_key);
    pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);
  }

  if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
    goto err;
  EC_POINT_make_affine(EC_KEY_get0_group(eckey),
                       pub_key,
                       NULL);
  ok = 1;

err:
  if (order)
    BN_free(order);

  if (ctx != NULL)
    BN_CTX_free(ctx);
  return (ok);
}


#define EC_GET_FIELD(_name)        {                                                  \
  lua_getfield(L, -1, #_name);                                                        \
  if (lua_isstring(L, -1)) {                                                          \
    size_t l = 0; const char* bn = luaL_checklstring(L, -1, &l);                      \
    if (_name == NULL)  _name = BN_new();                                             \
    BN_bin2bn((const unsigned char *)bn, l, _name);                                   \
  } else if (auxiliar_isclass(L, "openssl.bn", -1)) {                                 \
    const BIGNUM* bn = CHECK_OBJECT(-1, BIGNUM, "openssl.bn");                        \
    if (_name == NULL)  _name = BN_new();                                             \
    BN_copy(_name, bn);                                                               \
  } else if (!lua_isnil(L, -1))                                                       \
    luaL_error(L, "parameters must have \"%s\" field string or openssl.bn", #_name);  \
  lua_pop(L, 1);                                                                      \
}

static LUA_FUNCTION(openssl_pkey_new)
{
  EVP_PKEY *pkey = NULL;
  const char* alg = "rsa";

  if (lua_isnoneornil(L, 1) || lua_isstring(L, 1))
  {
    alg = luaL_optstring(L, 1, alg);

    if (strcasecmp(alg, "rsa") == 0)
    {
      int bits = luaL_optint(L, 2, 1024);
      int e = luaL_optint(L, 3, 65537);
      RSA* rsa = RSA_new();

      BIGNUM *E = BN_new();
      BN_set_word(E, e);
      if (RSA_generate_key_ex(rsa, bits, E, NULL))
      {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
      }
      else
        RSA_free(rsa);
      BN_free(E);
    }
    else if (strcasecmp(alg, "dsa") == 0)
    {
      int bits = luaL_optint(L, 2, 1024);
      size_t seed_len = 0;
      const char* seed = luaL_optlstring(L, 3, NULL, &seed_len);

      DSA *dsa = DSA_new();
      if (DSA_generate_parameters_ex(dsa, bits, (byte*)seed, seed_len, NULL, NULL, NULL)
          && DSA_generate_key(dsa))
      {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(pkey, dsa);
      }
      else
        DSA_free(dsa);
    }
    else if (strcasecmp(alg, "dh") == 0)
    {
      int bits = luaL_optint(L, 2, 512);
      int generator = luaL_optint(L, 3, 2);

      DH* dh = DH_new();
      if (DH_generate_parameters_ex(dh, bits, generator, NULL))
      {
        if (DH_generate_key(dh))
        {
          pkey = EVP_PKEY_new();
          EVP_PKEY_assign_DH(pkey, dh);
        }
        else
          DH_free(dh);
      }
      else
        DH_free(dh);
    }
#ifndef OPENSSL_NO_EC
    else if (strcasecmp(alg, "ec") == 0)
    {
      EC_KEY *ec = NULL;
      EC_GROUP *group = openssl_get_ec_group(L, 2, 3, 4);
      if (!group)
        luaL_error(L, "failed to get ec_group object");
      ec = EC_KEY_new();
      if (ec)
      {
        EC_KEY_set_group(ec, group);
        EC_GROUP_free(group);
        if (EC_KEY_generate_key(ec))
        {
          pkey = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(pkey, ec);
        }
        else
          EC_KEY_free(ec);
      }
      else
        EC_GROUP_free(group);

    }
#endif
    else
    {
      luaL_error(L, "not support %s!!!!", alg);
    }
  }
  else if (lua_istable(L, 1))
  {
    lua_getfield(L, 1, "alg");
    alg = luaL_optstring(L, -1, alg);
    lua_pop(L, 1);
    if (strcasecmp(alg, "rsa") == 0)
    {
      pkey = EVP_PKEY_new();
      if (pkey)
      {
        RSA *rsa = RSA_new();
        if (rsa)
        {
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

          if (RSA_set0_key(rsa, n, e, d) == 1
              && (p == NULL || RSA_set0_factors(rsa, p, q) == 1)
              && (dmp1 == NULL || RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) == 1) )
          {
            if (!EVP_PKEY_assign_RSA(pkey, rsa))
            {
              RSA_free(rsa);
              rsa = NULL;
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          }
          else
          {
            RSA_free(rsa);
            rsa = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
    }
    else if (strcasecmp(alg, "dsa") == 0)
    {
      pkey = EVP_PKEY_new();
      if (pkey)
      {
        DSA *dsa = DSA_new();
        if (dsa)
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

          if (DSA_set0_key(dsa, pub_key, priv_key) == 1
              && DSA_set0_pqg(dsa, p, q, g))
          {
            if (!EVP_PKEY_assign_DSA(pkey, dsa))
            {
              DSA_free(dsa);
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          }
          else
          {
            DSA_free(dsa);
            dsa = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
    }
    else if (strcasecmp(alg, "dh") == 0)
    {

      pkey = EVP_PKEY_new();
      if (pkey)
      {
        DH *dh = DH_new();
        if (dh)
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

          if (DH_set0_key(dh, pub_key, priv_key) == 1
              && DH_set0_pqg(dh, p, q, g))
          {
            if (!EVP_PKEY_assign_DH(pkey, dh))
            {
              DH_free(dh);
              dh = NULL;
              EVP_PKEY_free(pkey);
              pkey = NULL;
            }
          }
          else
          {
            DH_free(dh);
            dh = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }
        }
      }
    }
    else if (strcasecmp(alg, "ec") == 0)
    {
      BIGNUM *d = NULL;
      BIGNUM *x = NULL;
      BIGNUM *y = NULL;
      BIGNUM *z = NULL;
      EC_GROUP *group = NULL;

      lua_getfield(L, -1, "ec_name");
      lua_getfield(L, -2, "param_enc");
      lua_getfield(L, -3, "conv_form");
      group = openssl_get_ec_group(L, -3, -2, -1);
      lua_pop(L, 3);
      if (!group)
      {
        luaL_error(L, "get openssl.ec_group fail");
      }

      EC_GET_FIELD(d);
      EC_GET_FIELD(x);
      EC_GET_FIELD(y);
      EC_GET_FIELD(z);

      pkey = EVP_PKEY_new();
      if (pkey)
      {
        EC_KEY *ec = EC_KEY_new();
        if (ec)
        {
          EC_KEY_set_group(ec, group);
          if (d)
            EC_KEY_set_private_key(ec, d);
          if (x != NULL && y != NULL)
          {
            EC_POINT *pnt = EC_POINT_new(group);
            if (z == NULL)
              EC_POINT_set_affine_coordinates_GFp(group, pnt, x, y, NULL);
            else
              EC_POINT_set_Jprojective_coordinates_GFp(group, pnt, x, y, z, NULL);

            EC_KEY_set_public_key(ec, pnt);
            EC_POINT_free(pnt);
          }
          else
            EC_KEY_generate_key_part(ec);

          if (EC_KEY_check_key(ec) == 0 || EVP_PKEY_assign_EC_KEY(pkey, ec) == 0)
          {
            EC_KEY_free(ec);
            EVP_PKEY_free(pkey);
            pkey = NULL;
          }

          BN_free(d);
          BN_free(x);
          BN_free(y);
          BN_free(z);
        }
      }
      EC_GROUP_free(group);
    }
  }
  else if (auxiliar_isclass(L, "openssl.rsa", 1))
  {
    RSA* rsa = CHECK_OBJECT(1, RSA, "openssl.rsa");
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
  }

  if (pkey && EVP_PKEY_id(pkey) != NID_undef)
  {
    PUSH_OBJECT(pkey, "openssl.evp_pkey");
    return 1;
  }
  else
    EVP_PKEY_free(pkey);
  return 0;

}

static LUA_FUNCTION(openssl_pkey_export)
{
  EVP_PKEY * key;
  int ispriv = 0;
  int exraw = 0;
  int expem = 1;
  size_t passphrase_len = 0;
  BIO * bio_out = NULL;
  int ret = 0;
  const EVP_CIPHER * cipher;
  const char * passphrase = NULL;

  key = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  ispriv = openssl_pkey_is_private(key);

  if (!lua_isnoneornil(L, 2))
    expem = lua_toboolean(L, 2);
  if (!lua_isnoneornil(L, 3))
    exraw = lua_toboolean(L, 3);
  passphrase = luaL_optlstring(L, 4, NULL, &passphrase_len);

  if (passphrase)
  {
    cipher = (EVP_CIPHER *) EVP_des_ede3_cbc();
  }
  else
  {
    cipher = NULL;
  }

  bio_out = BIO_new(BIO_s_mem());
  if (expem)
  {
    if (exraw == 0)
    {
      ret = ispriv ?
            PEM_write_bio_PrivateKey(bio_out, key, cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL) :
            PEM_write_bio_PUBKEY(bio_out, key);
    }
    else
    {
      /* export raw key format */
      switch (EVP_PKEY_type(EVP_PKEY_id(key)))
      {
      case EVP_PKEY_RSA:
        ret = ispriv ? PEM_write_bio_RSAPrivateKey(bio_out, EVP_PKEY_get0_RSA(key), cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
              : PEM_write_bio_RSAPublicKey(bio_out, EVP_PKEY_get0_RSA(key));
        break;
      case EVP_PKEY_DSA:
      {
        ret = ispriv ? PEM_write_bio_DSAPrivateKey(bio_out, EVP_PKEY_get0_DSA(key), cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
              : PEM_write_bio_DSA_PUBKEY(bio_out, EVP_PKEY_get0_DSA(key));
      }
      break;
      case EVP_PKEY_DH:
        ret = PEM_write_bio_DHparams(bio_out, EVP_PKEY_get0_DH(key));
        break;
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC:
        ret = ispriv ? PEM_write_bio_ECPrivateKey(bio_out, EVP_PKEY_get0_EC_KEY(key), cipher, (unsigned char *)passphrase, passphrase_len, NULL, NULL)
              : PEM_write_bio_EC_PUBKEY(bio_out, EVP_PKEY_get0_EC_KEY(key));
        break;
#endif
      default:
        ret = 0;
        break;
      }
    }
  }
  else
  {
    /* out put der */
    if (exraw == 0)
    {
      ret = ispriv ?
            (passphrase == NULL ? i2d_PrivateKey_bio(bio_out, key) :
             i2d_PKCS8PrivateKey_bio(bio_out, key, cipher, (char *)passphrase, passphrase_len, NULL, NULL))
            : i2d_PUBKEY_bio(bio_out, key);
    }
    else
    {
      /* output raw key, rsa, ec, dh, dsa */
      if (ispriv)
      {
        switch (EVP_PKEY_type(EVP_PKEY_id(key)))
        {
        case EVP_PKEY_RSA:
          ret = ispriv ? i2d_RSAPrivateKey_bio(bio_out, EVP_PKEY_get0_RSA(key))
                : i2d_RSAPublicKey_bio(bio_out, EVP_PKEY_get0_RSA(key));
          break;
        case EVP_PKEY_DSA:
        {
          ret = ispriv ? i2d_DSAPrivateKey_bio(bio_out, EVP_PKEY_get0_DSA(key))
                : i2d_DSA_PUBKEY_bio(bio_out, EVP_PKEY_get0_DSA(key));
        }
        break;
        case EVP_PKEY_DH:
          ret = i2d_DHparams_bio(bio_out, EVP_PKEY_get0_DH(key));
          break;
#ifndef OPENSSL_NO_EC
        case EVP_PKEY_EC:
          ret = ispriv ? i2d_ECPrivateKey_bio(bio_out, EVP_PKEY_get0_EC_KEY(key))
                : i2d_EC_PUBKEY_bio(bio_out, EVP_PKEY_get0_EC_KEY(key));

          break;
#endif
        default:
          ret = 0;
          break;
        }
      }
      else
      {
        int l = i2d_PublicKey(key, NULL);
        if (l > 0)
        {
          unsigned char* p = malloc(l);
          unsigned char* pp = p;
          l = i2d_PublicKey(key, &pp);
          if (l > 0)
          {
            BIO_write(bio_out, p, l);
            ret = 1;
          }
          else
            ret = 0;
          free(p);
        }
        else
          ret = 0;
      }
    }
  }

  if (ret)
  {
    char * bio_mem_ptr;
    long bio_mem_len;

    bio_mem_len = BIO_get_mem_data(bio_out, &bio_mem_ptr);

    lua_pushlstring(L, bio_mem_ptr, bio_mem_len);
    ret  = 1;
  }

  if (bio_out)
  {
    BIO_free(bio_out);
  }
  return ret;
}

static LUA_FUNCTION(openssl_pkey_free)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  EVP_PKEY_free(pkey);
  return 0;
}

static LUA_FUNCTION(openssl_pkey_parse)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  if (EVP_PKEY_id(pkey) != NID_undef)
  {
    lua_newtable(L);

    AUXILIAR_SET(L, -1, "bits", EVP_PKEY_bits(pkey), integer);
    AUXILIAR_SET(L, -1, "size", EVP_PKEY_size(pkey), integer);

    switch (EVP_PKEY_type(EVP_PKEY_id(pkey)))
    {
    case EVP_PKEY_RSA:
    {
      RSA* rsa = EVP_PKEY_get1_RSA(pkey);
      PUSH_OBJECT(rsa, "openssl.rsa");
      lua_setfield(L, -2, "rsa");

      AUXILIAR_SET(L, -1, "type", "rsa", string);
    }

    break;
    case EVP_PKEY_DSA:
    {
      DSA* dsa = EVP_PKEY_get1_DSA(pkey);
      PUSH_OBJECT(dsa, "openssl.dsa");
      lua_setfield(L, -2, "dsa");

      AUXILIAR_SET(L, -1, "type", "dsa", string);
    }
    break;
    case EVP_PKEY_DH:
    {
      DH* dh = EVP_PKEY_get1_DH(pkey);
      PUSH_OBJECT(dh, "openssl.dh");
      lua_rawseti(L, -2, 0);

      AUXILIAR_SET(L, -1, "type", "dh", string);
    }

    break;
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
    {
      const EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
      PUSH_OBJECT(ec, "openssl.ec_key");
      lua_setfield(L, -2, "ec");

      AUXILIAR_SET(L, -1, "type", "ec", string);
    }

    break;
#endif
    default:
      break;
    };
    return 1;
  }
  else
    luaL_argerror(L, 1, "not assign any keypair");
  return 0;
};
/* }}} */

static LUA_FUNCTION(openssl_pkey_encrypt)
{
  size_t dlen = 0;
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char *data = luaL_checklstring(L, 2, &dlen);
  int padding = openssl_get_padding(L, 3, "pkcs1");
  ENGINE *engine = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
  size_t clen = EVP_PKEY_size(pkey);
  EVP_PKEY_CTX *ctx = NULL;
  int ret = 0;
  int typ = EVP_PKEY_type(EVP_PKEY_id(pkey));

  if (typ != EVP_PKEY_RSA && typ != EVP_PKEY_RSA2)
  {
    luaL_argerror(L, 2, "EVP_PKEY must be of type RSA or RSA2");
    return ret;
  }

  ctx = EVP_PKEY_CTX_new(pkey, engine);
  if (EVP_PKEY_encrypt_init(ctx) == 1)
  {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) == 1)
    {
      byte* buf = malloc(clen);
      if (EVP_PKEY_encrypt(ctx, buf, &clen, (const unsigned char*)data, dlen) == 1)
      {
        lua_pushlstring(L, (const char*)buf, clen);
        ret = 1;
      }
      else
        ret = openssl_pushresult(L, 0);
      free(buf);
    }
    else
      ret = openssl_pushresult(L, 0);
  }
  else
    ret = openssl_pushresult(L, 0);
  EVP_PKEY_CTX_free(ctx);

  return ret;
}

static LUA_FUNCTION(openssl_pkey_decrypt)
{
  size_t dlen = 0;
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char *data = luaL_checklstring(L, 2, &dlen);
  int padding = openssl_get_padding(L, 3, "pkcs1");
  ENGINE *engine = lua_isnoneornil(L, 4) ? NULL : CHECK_OBJECT(4, ENGINE, "openssl.engine");
  size_t clen = EVP_PKEY_size(pkey);
  EVP_PKEY_CTX *ctx = NULL;
  int ret = 0;
  int type = EVP_PKEY_type(EVP_PKEY_id(pkey));

  if (type != EVP_PKEY_RSA && type != EVP_PKEY_RSA2)
  {
    luaL_argerror(L, 2, "EVP_PKEY must be of type RSA or RSA2");
    return ret;
  }
  ctx = EVP_PKEY_CTX_new(pkey, engine);
  if (EVP_PKEY_decrypt_init(ctx) == 1)
  {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) == 1)
    {
      byte* buf = malloc(clen);

      if (EVP_PKEY_decrypt(ctx, buf, &clen, (const unsigned char*)data, dlen) == 1)
      {
        lua_pushlstring(L, (const char*)buf, clen);
        ret = 1;
      }
      else
        ret = openssl_pushresult(L, 0);
      free(buf);
    }
    else
      ret = openssl_pushresult(L, 0);
  }
  else
    ret = openssl_pushresult(L, 0);
  EVP_PKEY_CTX_free(ctx);
  return ret;
}

LUA_FUNCTION(openssl_pkey_is_private1)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int private = openssl_pkey_is_private(pkey);
  if (private == 0)
    lua_pushboolean(L, 0);
  else if (private == 1)
    lua_pushboolean(L, 1);
  else
    luaL_error(L, "openssl.evp_pkey is not support");
  return 1;
}

static LUA_FUNCTION(openssl_pkey_get_public)
{
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  int ret = 0;
  BIO* bio = BIO_new(BIO_s_mem());
  if (i2d_PUBKEY_bio(bio, pkey))
  {
    EVP_PKEY *pub = d2i_PUBKEY_bio(bio, NULL);
    PUSH_OBJECT(pub, "openssl.evp_pkey");
    ret = 1;
  }
  BIO_free(bio);
  return ret;
}

static LUA_FUNCTION(openssl_ec_userId)
{
  EVP_PKEY* pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  ENGINE* engine = CHECK_OBJECT(2, ENGINE, "openssl.engine");
  EC_KEY *ec = NULL;

  int ret = 0;
  if (!pkey || EVP_PKEY_type(EVP_PKEY_id(pkey)) != EVP_PKEY_EC
      || (ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL )
  {
    luaL_argerror(L, 1, "only support EC key");
  }
  if (!engine)
    luaL_argerror(L, 1, "EC key must have engine field");

  if (lua_gettop(L) == 2)
  {
    ASN1_OCTET_STRING *s = ASN1_OCTET_STRING_new();
    ret = ENGINE_ctrl(engine, 0x474554, 0x4944, ec, (void(*)(void))s);
    if (ret == 1)
      lua_pushlstring(L, (const char*) ASN1_STRING_data(s), ASN1_STRING_length(s));
    else
      ret = openssl_pushresult(L, ret);
    return ret;
  }
  else
  {
    ASN1_OCTET_STRING *s = ASN1_OCTET_STRING_new();
    size_t l;
    const char* data = luaL_checklstring(L, 3, &l);
    ASN1_OCTET_STRING_set(s, (const unsigned char*) data, l);
    ret = ENGINE_ctrl(engine, 0x534554, 0x4944, ec, (void(*)(void))s);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_dh_compute_key)
{
  BIGNUM *pub;
  char *data;
  int len;
  int ret = 0;

  EVP_PKEY* pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  size_t pub_len;
  const char* pub_str = luaL_checklstring(L, 2, &pub_len);
  DH *dh = NULL;

  if (!pkey || EVP_PKEY_type(EVP_PKEY_id(pkey)) != EVP_PKEY_DH
      || (dh = EVP_PKEY_get0_DH(pkey)) == NULL)
  {
    luaL_argerror(L, 1, "only support DH private key");
  }

  pub = BN_bin2bn((unsigned char*)pub_str, pub_len, NULL);

  data = malloc(DH_size(dh) + 1);
  len = DH_compute_key((unsigned char*)data, pub, dh);

  if (len >= 0)
  {
    data[len] = 0;
    lua_pushlstring(L, data, len);
    ret = 1;
  }
  else
  {
    free(data);
    ret = 0;
  }

  BN_free(pub);
  return ret;
}

static LUA_FUNCTION(openssl_sign)
{
  size_t data_len;
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char * data = luaL_checklstring(L, 2, &data_len);
  int top = lua_gettop(L);

  const EVP_MD *mdtype = NULL;
  if (top > 2)
  {
    mdtype = get_digest(L, 3);
  }
  else
    mdtype = EVP_get_digestbyname("sha1");
  if (mdtype)
  {
    int ret = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    ret = EVP_DigestSignInit(ctx, NULL, mdtype, NULL, pkey);
    if (ret == 1)
    {
      ret = EVP_DigestSignUpdate(ctx, data, data_len);
      if (ret == 1)
      {
        size_t siglen = 0;
        unsigned char *sigbuf = NULL;
        ret = EVP_DigestSignFinal(ctx, NULL, &siglen);
        if (ret == 1)
        {
          siglen += 2;
          sigbuf = OPENSSL_malloc(siglen);
          ret = EVP_DigestSignFinal(ctx, sigbuf, &siglen);
          if (ret == 1)
          {
            lua_pushlstring(L, (char *)sigbuf, siglen);
          }
          else
            ret = openssl_pushresult(L, ret);
          OPENSSL_free(sigbuf);
        }
        else
          ret = openssl_pushresult(L, ret);
      }
      else
        ret = openssl_pushresult(L, ret);
    }
    else
      ret = openssl_pushresult(L, ret);

    EVP_MD_CTX_destroy(ctx);
    return ret;
  }
  else
    luaL_argerror(L, 3, "Not support digest alg");

  return 0;
}

static LUA_FUNCTION(openssl_verify)
{
  size_t data_len, signature_len;
  EVP_PKEY *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  const char* data = luaL_checklstring(L, 2, &data_len);
  const char* signature = luaL_checklstring(L, 3, &signature_len);
  const EVP_MD *mdtype = NULL;
  int top = lua_gettop(L);
  if (top > 3)
  {
    mdtype = get_digest(L, 4);
  }
  else
    mdtype = EVP_get_digestbyname("sha1");
  if (mdtype)
  {
    int ret;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    ret = EVP_DigestVerifyInit(ctx, NULL, mdtype, NULL, pkey);
    if (ret == 1)
    {
      ret = EVP_DigestVerifyUpdate(ctx, data, data_len);
      if (ret == 1)
      {
        ret = EVP_DigestVerifyFinal(ctx, (unsigned char *)signature, signature_len);
        if (ret == 1)
        {
          lua_pushboolean(L, ret == 1);
        }
        else
          ret = openssl_pushresult(L, ret);
      }
      else
        ret = openssl_pushresult(L, ret);
    }
    else
      ret = openssl_pushresult(L, ret);

    EVP_MD_CTX_destroy(ctx);
    return ret;
  }
  else
    luaL_argerror(L, 4, "Not support digest alg");

  return 0;
}

static LUA_FUNCTION(openssl_seal)
{
  size_t data_len;
  const char *data = NULL;
  int nkeys = 0;
  const EVP_CIPHER *cipher = NULL;

  if (lua_istable(L, 1))
  {
    nkeys = lua_rawlen(L, 1);
    if (!nkeys)
    {
      luaL_argerror(L, 1, "empty array");
    }
  }
  else if (auxiliar_isclass(L, "openssl.evp_pkey", 1))
  {
    nkeys = 1;
  }
  else
    luaL_argerror(L, 1, "must be openssl.evp_pkey or unemtpy table");

  data = luaL_checklstring(L, 2, &data_len);

  cipher = get_cipher(L, 3, "rc4");

  if (cipher)
  {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ret = 0;
    EVP_PKEY **pkeys;
    unsigned char **eks;
    int *eksl;
    int i;
    int len1, len2;
    unsigned char *buf;
    char iv[EVP_MAX_MD_SIZE] = {0};

    pkeys = malloc(nkeys * sizeof(EVP_PKEY *));
    eksl = malloc(nkeys * sizeof(int));
    eks = malloc(nkeys * sizeof(char*));

    memset(eks, 0, sizeof(char*) * nkeys);

    /* get the public keys we are using to seal this data */
    if (lua_istable(L, 1))
    {
      for (i = 0; i < nkeys; i++)
      {
        lua_rawgeti(L, 1, i + 1);

        pkeys[i] =  CHECK_OBJECT(-1, EVP_PKEY, "openssl.evp_pkey");
        if (pkeys[i] == NULL)
        {
          luaL_argerror(L, 1, "table with gap");
        }
        eksl[i] = EVP_PKEY_size(pkeys[i]);
        eks[i] = malloc(eksl[i]);

        lua_pop(L, 1);
      }
    }
    else
    {
      pkeys[0] = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
      eksl[0] = EVP_PKEY_size(pkeys[0]);
      eks[0] = malloc(eksl[0]);
    }
    EVP_CIPHER_CTX_init(ctx);

    /* allocate one byte extra to make room for \0 */
    len1 = data_len + EVP_CIPHER_block_size(cipher) + 1;
    buf = malloc(len1);


    if (!EVP_SealInit(ctx, cipher, eks, eksl, (unsigned char*) iv, pkeys, nkeys)
        || !EVP_SealUpdate(ctx, buf, &len1, (unsigned char *)data, data_len))
    {
      luaL_error(L, "EVP_SealInit failed");
    }

    EVP_SealFinal(ctx, buf + len1, &len2);

    if (len1 + len2 > 0)
    {
      lua_pushlstring(L, (const char*)buf, len1 + len2);
      if (lua_istable(L, 1))
      {
        lua_newtable(L);
        for (i = 0; i < nkeys; i++)
        {
          lua_pushlstring(L, (const char*)eks[i], eksl[i]);
          free(eks[i]);
          lua_rawseti(L, -2, i + 1);
        }
      }
      else
      {
        lua_pushlstring(L, (const char*)eks[0], eksl[0]);
        free(eks[0]);
      }
      lua_pushlstring(L, iv, EVP_CIPHER_CTX_iv_length(ctx));

      ret = 3;
    }

    free(buf);
    free(eks);
    free(eksl);
    free(pkeys);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
  }
  else
    luaL_argerror(L, 3, "Not support cipher alg");
  return 0;
}


static LUA_FUNCTION(openssl_seal_init)
{
  int nkeys = 0;
  const EVP_CIPHER *cipher = NULL;

  if (lua_istable(L, 1))
  {
    nkeys = lua_rawlen(L, 1);
    if (!nkeys)
    {
      luaL_argerror(L, 1, "empty array");
    }
  }
  else if (auxiliar_isclass(L, "openssl.evp_pkey", 1))
  {
    nkeys = 1;
  }
  else
    luaL_argerror(L, 1, "must be openssl.evp_pkey or unemtpy table");

  cipher = get_cipher(L, 2, "rc4");

  if (cipher)
  {
    EVP_PKEY **pkeys;
    unsigned char **eks;
    int *eksl;
    EVP_CIPHER_CTX *ctx = NULL;

    int i;
    char iv[EVP_MAX_MD_SIZE] = {0};

    pkeys = malloc(nkeys * sizeof(*pkeys));
    eksl = malloc(nkeys * sizeof(*eksl));
    eks = malloc(nkeys * sizeof(*eks));


    memset(eks, 0, sizeof(*eks) * nkeys);

    /* get the public keys we are using to seal this data */
    if (lua_istable(L, 1))
    {
      for (i = 0; i < nkeys; i++)
      {
        lua_rawgeti(L, 1, i + 1);

        pkeys[i] =  CHECK_OBJECT(-1, EVP_PKEY, "openssl.evp_pkey");
        if (pkeys[i] == NULL)
        {
          luaL_argerror(L, 1, "table with gap");
        }
        eksl[i] = EVP_PKEY_size(pkeys[i]);
        eks[i] = malloc(eksl[i]);

        lua_pop(L, 1);
      }
    }
    else
    {
      pkeys[0] = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
      eksl[0] = EVP_PKEY_size(pkeys[0]);
      eks[0] = malloc(eksl[0]);
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit(ctx, cipher, NULL, NULL))
    {
      luaL_error(L, "EVP_EncryptInit failed");
    }
    if (!EVP_SealInit(ctx, cipher, eks, eksl, (unsigned char*) iv, pkeys, nkeys))
    {
      luaL_error(L, "EVP_SealInit failed");
    }
    PUSH_OBJECT(ctx, "openssl.evp_cipher_ctx");
    if (lua_istable(L, 1))
    {
      lua_newtable(L);
      for (i = 0; i < nkeys; i++)
      {
        lua_pushlstring(L, (const char*)eks[i], eksl[i]);
        free(eks[i]);
        lua_rawseti(L, -2, i + 1);
      }
    }
    else
    {
      lua_pushlstring(L, (const char*)eks[0], eksl[0]);
      free(eks[0]);
    }
    lua_pushlstring(L, iv, EVP_CIPHER_CTX_iv_length(ctx));

    free(eks);
    free(eksl);
    free(pkeys);
    return 3;
  }
  else
  {
    luaL_argerror(L, 2, "Not support cipher alg");
  }
  return 0;
}

static LUA_FUNCTION(openssl_seal_update)
{
  EVP_CIPHER_CTX* ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  size_t data_len;
  const char *data = luaL_checklstring(L, 2, &data_len);
  int len = data_len + EVP_CIPHER_CTX_block_size(ctx);
  unsigned char *buf =  malloc(len);

  if (!EVP_SealUpdate(ctx, buf, &len, (unsigned char *)data, data_len))
  {
    free(buf);
    luaL_error(L, "EVP_SealUpdate fail");
  }

  lua_pushlstring(L, (const char*)buf, len);
  free(buf);
  return 1;
}

static LUA_FUNCTION(openssl_seal_final)
{
  EVP_CIPHER_CTX* ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  int len = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char *buf = malloc(len);


  if (!EVP_SealFinal(ctx, buf, &len))
  {
    free(buf);
    luaL_error(L, "EVP_SealFinal fail");
  }

  lua_pushlstring(L, (const char*)buf, len);
  return 1;
}

static LUA_FUNCTION(openssl_open)
{
  EVP_PKEY *pkey =  CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  size_t data_len, ekey_len, iv_len;
  const char *data = luaL_checklstring(L, 2, &data_len);
  const char *ekey = luaL_checklstring(L, 3, &ekey_len);
  const char *iv = luaL_checklstring(L, 4, &iv_len);

  int ret = 0;
  int len1, len2 = 0;
  unsigned char *buf;

  const EVP_CIPHER *cipher = NULL;

  cipher = get_cipher(L, 5, "rc4");

  if (cipher)
  {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    len1 = data_len + 1;
    buf = malloc(len1);

    EVP_CIPHER_CTX_init(ctx);
    if (EVP_OpenInit(ctx, cipher, (unsigned char *)ekey, ekey_len, (const unsigned char *)iv, pkey)
        && EVP_OpenUpdate(ctx, buf, &len1, (unsigned char *)data, data_len))
    {
      len2 = data_len - len1;
      if (!EVP_OpenFinal(ctx, buf + len1, &len2) || (len1 + len2 == 0))
      {
        luaL_error(L, "EVP_OpenFinal() failed.");
        ret = 0;
      }
    }
    else
    {
      luaL_error(L, "EVP_OpenInit() failed.");
      ret = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    lua_pushlstring(L, (const char*)buf, len1 + len2);
    free(buf);
    ret = 1;
  }
  else
    luaL_argerror(L, 5, "Not support cipher alg");

  return ret;
}


static LUA_FUNCTION(openssl_open_init)
{
  EVP_PKEY *pkey =  CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  size_t ekey_len, iv_len;
  const char *ekey = luaL_checklstring(L, 2, &ekey_len);
  const char *iv = luaL_checklstring(L, 3, &iv_len);

  const EVP_CIPHER *cipher = NULL;

  cipher = get_cipher(L, 4, "rc4");

  if (cipher)
  {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);
    if (EVP_OpenInit(ctx, cipher, (unsigned char *)ekey, ekey_len, (const unsigned char *)iv, pkey))
    {
      PUSH_OBJECT(ctx, "openssl.evp_cipher_ctx");
      return 1;
    }
    else
    {
      luaL_error(L, "EVP_OpenInit fail");
    }
  }
  else
    luaL_argerror(L, 5, "Not support cipher alg");
  return 0;
};

static LUA_FUNCTION(openssl_open_update)
{
  EVP_CIPHER_CTX* ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  size_t data_len;
  const char* data = luaL_checklstring(L, 2, &data_len);

  int len = EVP_CIPHER_CTX_block_size(ctx) + data_len;
  unsigned char *buf = malloc(len);

  if (EVP_OpenUpdate(ctx, buf, &len, (unsigned char *)data, data_len))
  {
    lua_pushlstring(L, (const char*)buf, len);
  }
  else
    luaL_error(L, "EVP_OpenUpdate fail");

  free(buf);
  return 1;
}

static LUA_FUNCTION(openssl_open_final)
{
  EVP_CIPHER_CTX* ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  int len = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char *buf = malloc(len);
  int ret = EVP_OpenFinal(ctx, buf, &len);
  if (ret == 1)
  {
    lua_pushlstring(L, (const char*)buf, len);
  }
  free(buf);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

static luaL_Reg pkey_funcs[] =
{
  {"is_private",    openssl_pkey_is_private1},
  {"get_public",    openssl_pkey_get_public},

  {"export",        openssl_pkey_export},
  {"parse",         openssl_pkey_parse},
  {"bits",          openssl_pkey_bits},

  {"encrypt",       openssl_pkey_encrypt},
  {"decrypt",       openssl_pkey_decrypt},
  {"sign",          openssl_sign},
  {"verify",        openssl_verify},

  {"seal",          openssl_seal},
  {"open",          openssl_open},

  {"compute_key",   openssl_dh_compute_key},
  {"ec_userId",     openssl_ec_userId},

  {"__gc",          openssl_pkey_free},
  {"__tostring",    auxiliar_tostring},

  {NULL,            NULL},
};

static const luaL_Reg R[] =
{
  {"read",          openssl_pkey_read},
  {"new",           openssl_pkey_new},

  {"seal",          openssl_seal},
  {"seal_init",     openssl_seal_init},
  {"seal_update",   openssl_seal_update},
  {"seal_final",    openssl_seal_final},
  {"open",          openssl_open},
  {"open_init",     openssl_open_init},
  {"open_update",   openssl_open_update},
  {"open_final",    openssl_open_final},

  {"get_public",    openssl_pkey_get_public},
  {"is_private",    openssl_pkey_is_private1},
  {"export",        openssl_pkey_export},
  {"parse",         openssl_pkey_parse},
  {"bits",          openssl_pkey_bits},

  {"encrypt",       openssl_pkey_encrypt},
  {"decrypt",       openssl_pkey_decrypt},
  {"sign",          openssl_sign},
  {"verify",        openssl_verify},

  {"compute_key",   openssl_dh_compute_key},

  {NULL,  NULL}
};

int luaopen_pkey(lua_State *L)
{
  auxiliar_newclass(L, "openssl.evp_pkey", pkey_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
