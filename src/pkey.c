/***
 * pkey module - integration layer
 *
 * This file integrates all pkey sub-modules from src/pkey/ directory.
 * It includes the sub-module source files to maintain a single compilation unit,
 * ensuring all internal function references are resolved correctly.
 *
 * @module pkey
 * @usage
 *   pkey = require'openssl'.pkey
 */
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include "openssl.h"
#include "private.h"

/* Suppress deprecation warnings for low-level key APIs in OpenSSL 3.0+ */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif

/* ========================================================================
 * Compatibility layer (stays in pkey.c for cross-module access)
 * ======================================================================== */

/* Compatibility layer for low-level key access migration to OpenSSL 3.0+ PARAM API */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

/* Helper: check if private key exists using PARAM API */
static int
pkey_has_private(EVP_PKEY *pkey)
{
  BIGNUM *bn = NULL;
  int ret = 0;
  size_t priv_len = 0;

  int typ = EVP_PKEY_type(EVP_PKEY_id(pkey));

  switch (typ) {
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA: {
    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bn);
    break;
  }
#endif
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA: {
    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn);
    if (!ret || bn == NULL) {
      /*OpenSSL 3.0 DSA priv key param not working, Fallback to legacy way */
      DSA* dsa = (DSA*)EVP_PKEY_get0_DSA(pkey);
      if (dsa) {
        const BIGNUM* priv_key = NULL;
        DSA_get0_key(dsa, NULL, &priv_key);
        if (priv_key) {
          bn = BN_dup(priv_key);
          ret = 1;
        }
      }
    }
    break;
  }
#endif
#ifndef OPENSSL_NO_DH
  case EVP_PKEY_DH: {
    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn);
    break;
  }
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
#ifdef EVP_PKEY_SM2
  case EVP_PKEY_SM2:
#endif
  {
    ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn);
    break;
  }
#endif
#ifndef OPENSSL_NO_ED25519
  case EVP_PKEY_ED25519: {
    ret = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &priv_len);
    break;
  }
#endif
#ifndef OPENSSL_NO_ED448
  case EVP_PKEY_ED448: {
    ret = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &priv_len);
    break;
  }
#endif
#ifndef OPENSSL_NO_EX25519
  case EVP_PKEY_X25519: {
    ret = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &priv_len);
    break;
  }
#endif
  default:
  {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (EVP_PKEY_private_check(ctx))
      ret = 1;
    EVP_PKEY_CTX_free(ctx);
    return ret;
  }
  }

  if (ret && bn != NULL) {
    ret = !BN_is_zero(bn);
    BN_free(bn);
  } else if (ret && priv_len > 0) {
    ret = 1;
  }

  return ret;
}

/* Helper: check if key matches expected type */
static int
pkey_is_type(EVP_PKEY *pkey, int expected_type)
{
  /* In OpenSSL 3.0+, if EVP_PKEY_id returns the expected type, the key exists */
  return pkey != NULL && EVP_PKEY_type(EVP_PKEY_id(pkey)) == expected_type;
}
#endif

int
openssl_pkey_is_private(EVP_PKEY *pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
  return pkey_has_private(pkey);
#else
  /* OpenSSL 1.x way */
  int ret = 0;
  int typ = EVP_PKEY_type(EVP_PKEY_id(pkey));

  switch (typ) {
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA: {
    RSA          *rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
    const BIGNUM *d = NULL;

    RSA_get0_key(rsa, NULL, NULL, &d);
    ret = d != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA: {
    DSA          *dsa = (DSA *)EVP_PKEY_get0_DSA(pkey);
    const BIGNUM *p = NULL;
    DSA_get0_key(dsa, NULL, &p);
    ret = p != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_DH
  case EVP_PKEY_DH: {
    DH           *dh = (DH *)EVP_PKEY_get0_DH(pkey);
    const BIGNUM *p = NULL;
    DH_get0_key(dh, NULL, &p);
    ret = p != NULL;
    break;
  }
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
#ifdef EVP_PKEY_SM2
  case EVP_PKEY_SM2:
#endif
  {
    EC_KEY       *ec = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
    const BIGNUM *p = EC_KEY_get0_private_key(ec);
    ret = p != NULL;
    break;
  }
#endif
  default:
    break;
  }

  return ret;
#endif
}

#if defined(OPENSSL_SUPPORT_SM2)
static int
openssl_pkey_is_sm2(const EVP_PKEY *pkey)
{
  int id;
#if OPENSSL_VERSION_NUMBER > 0x30000000
  id = EVP_PKEY_get_id(pkey);
  if (id == NID_sm2) return 1;
#else
  id = EVP_PKEY_id(pkey);
  if (id == EVP_PKEY_SM2) return 1;
#endif

  id = EVP_PKEY_base_id(pkey);
  if (id == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    /* OpenSSL 3.0+ way: use PARAM API to get curve name */
    char curve_name[256];
    size_t curve_name_len = sizeof(curve_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve_name, sizeof(curve_name), &curve_name_len)) {
      /* Check if the group name is SM2 */
      if (strcmp(curve_name, "SM2") == 0) {
        return 1;
      }
      /* Convert group name to NID and check */
      int curve = OBJ_sn2nid(curve_name);
      return curve == NID_sm2;
    }
#else
    /* OpenSSL 1.x way */
    const EC_KEY   *ec = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)pkey);
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    int             curve = EC_GROUP_get_curve_name(grp);
    return curve == NID_sm2;
#endif
  }
  return 0;
}
#endif

/* ========================================================================
 * Include sub-modules
 * ======================================================================== */

#include "pkey/read.c"
#include "pkey/new.c"
#include "pkey/sign.c"
#include "pkey/derive.c"
#include "pkey/seal.c"
#include "pkey/kem.c"
#include "pkey/engine.c"
#include "pkey/sm2.c"
#include "pkey/core.c"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
