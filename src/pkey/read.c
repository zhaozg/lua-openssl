/***
 * pkey read module
 * Read public/private key from data
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/***
 * read public/private key from data
 * @function read
 * @tparam string|openssl.bio input string data or bio object
 * @tparam[opt=false] boolean priv prikey set true when input is private key
 * @tparam[opt='auto'] string format format or encoding of input, support 'auto','pem','der'
 * @tparam[opt] string passhprase when input is private key, or key types 'ec','rsa','dsa','dh'
 * @treturn openssl.evp_pkey public key
 * @treturn[2] nil
 * @treturn[2] string error message
 *
 * For PQC algorithms (ML-DSA, ML-KEM, SLH-DSA, etc.), uses generic
 * SubjectPublicKeyInfo (PEM_read_bio_PUBKEY/d2i_PUBKEY_bio) for public keys
 * and PKCS#8 PrivateKeyInfo (d2i_PKCS8PrivateKey_bio/d2i_PrivateKey_bio)
 * for private keys.
 * @see pkey
 */
int
openssl_pkey_read(lua_State *L)
{
  EVP_PKEY   *key = NULL;
  BIO        *in = load_bio_object(L, 1);
  int         priv = lua_isnone(L, 2) ? 0 : auxiliar_checkboolean(L, 2);
  int         fmt = luaL_checkoption(L, 3, "auto", format);
  const char *passphrase = luaL_optstring(L, 4, NULL);
  int         type = passphrase != NULL ? evp_pkey_name2type(passphrase) : -1;

  if (fmt == FORMAT_AUTO) {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }

  if (!priv) {
    if (fmt == FORMAT_PEM) {
      switch (type) {
#ifndef OPENSSL_NO_RSA
      case EVP_PKEY_RSA: {
        RSA *rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);
        if (rsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_DSA
      case EVP_PKEY_DSA: {
        DSA *dsa = PEM_read_bio_DSA_PUBKEY(in, NULL, NULL, NULL);
        if (dsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC: {
        EC_KEY *ec = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        if (ec) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
#endif
      default: {
        /* For unknown types (including PQC), use generic SubjectPublicKeyInfo */
        key = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
        break;
      }
      }
      (void)BIO_reset(in);
    } else if (fmt == FORMAT_DER) {
      switch (type) {
#ifndef OPENSSL_NO_RSA
      case EVP_PKEY_RSA: {
        RSA *rsa = d2i_RSAPublicKey_bio(in, NULL);
        if (rsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_DSA
      case EVP_PKEY_DSA: {
        DSA *dsa = d2i_DSA_PUBKEY_bio(in, NULL);
        if (dsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC: {
        EC_KEY *ec = d2i_EC_PUBKEY_bio(in, NULL);
        if (ec) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
#endif
      default:
        /* For unknown types (including PQC), use generic SubjectPublicKeyInfo */
        key = d2i_PUBKEY_bio(in, NULL);
        break;
      }
      (void)BIO_reset(in);
    }
  } else {
    if (fmt == FORMAT_PEM) {
      key = PEM_read_bio_PrivateKey(in, NULL, NULL, (void *)passphrase);
      (void)BIO_reset(in);
    } else if (fmt == FORMAT_DER) {
      switch (type) {
#ifndef OPENSSL_NO_RSA
      case EVP_PKEY_RSA: {
        RSA *rsa = d2i_RSAPrivateKey_bio(in, NULL);
        if (rsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_RSA(key, rsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_DSA
      case EVP_PKEY_DSA: {
        DSA *dsa = d2i_DSAPrivateKey_bio(in, NULL);
        if (dsa) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_DSA(key, dsa);
        }
        break;
      }
#endif
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC: {
        EC_KEY *ec = d2i_ECPrivateKey_bio(in, NULL);
        if (ec) {
          key = EVP_PKEY_new();
          EVP_PKEY_assign_EC_KEY(key, ec);
        }
        break;
      }
#endif
      default: {
        /* For unknown types (including PQC), try PKCS#8 or generic PrivateKeyInfo */
        if (passphrase)
          key = d2i_PKCS8PrivateKey_bio(in, NULL, NULL, (void *)passphrase);
        else
          key = d2i_PrivateKey_bio(in, NULL);
        break;
      }
      }
      (void)BIO_reset(in);
    }
  }
  BIO_free(in);
  if (key) PUSH_OBJECT(key, "openssl.evp_pkey");

  return key ? 1 : openssl_pushresult(L, 0);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
