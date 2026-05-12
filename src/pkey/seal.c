/***
 * pkey seal/open module
 * Seal (encrypt with public key + symmetric key) and Open (decrypt)
 */
#include "pkey.h"

/* Suppress deprecation warnings */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/***
 * seal and encrypt message with one public key
 * data be encrypt with secret key, secret key be encrypt with public key
 * @function seal
 * @tparam string data data to be encrypted
 * @tparam[opt='RC4'] cipher|string alg
 * @treturn string data encrypted
 * @treturn string skey secret key encrypted by public key
 * @treturn string iv
 */
int
openssl_seal(lua_State *L)
{
  int         i, ret = 0, nkeys = 0;
  size_t      data_len;
  const char *data = NULL;

  EVP_CIPHER_CTX   *ctx = EVP_CIPHER_CTX_new();
  EVP_PKEY        **pkeys;
  unsigned char   **eks;
  int              *eksl;
  int               len1, len2;
  unsigned char    *buf;
  char              iv[EVP_MAX_MD_SIZE] = { 0 };
  const EVP_CIPHER *cipher = NULL;

  luaL_argcheck(L,
                lua_istable(L, 1) || auxiliar_getclassudata(L, "openssl.evp_pkey", 1),
                1,
                "must be openssl.evp_pkey or array");

  if (lua_istable(L, 1)) {
    nkeys = lua_rawlen(L, 1);
    luaL_argcheck(L, nkeys != 0, 1, "empty array");
  } else if (auxiliar_getclassudata(L, "openssl.evp_pkey", 1)) {
    nkeys = 1;
  }

  data = luaL_checklstring(L, 2, &data_len);
  cipher = get_cipher(L, 3, "aes-128-cbc");

  pkeys = malloc(nkeys * sizeof(EVP_PKEY *));
  eksl = malloc(nkeys * sizeof(int));
  eks = malloc(nkeys * sizeof(char *));

  memset(eks, 0, sizeof(char *) * nkeys);

  /* get the public keys we are using to seal this data */
  if (lua_istable(L, 1)) {
    for (i = 0; i < nkeys; i++) {
      lua_rawgeti(L, 1, i + 1);

      pkeys[i] = CHECK_OBJECT(-1, EVP_PKEY, "openssl.evp_pkey");
      if (pkeys[i] == NULL) {
        luaL_argerror(L, 1, "table with gap");
      }
      eksl[i] = EVP_PKEY_size(pkeys[i]);
      eks[i] = malloc(eksl[i]);

      lua_pop(L, 1);
    }
  } else {
    pkeys[0] = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
    eksl[0] = EVP_PKEY_size(pkeys[0]);
    eks[0] = malloc(eksl[0]);
  }
  EVP_CIPHER_CTX_reset(ctx);

  /* allocate one byte extra to make room for \0 */
  len1 = data_len + EVP_CIPHER_block_size(cipher) + 1;
  buf = malloc(len1);

  ret = EVP_SealInit(ctx, cipher, eks, eksl, (unsigned char *)iv, pkeys, nkeys);
  if (ret > 0) {
    ret = EVP_SealUpdate(ctx, buf, &len1, (unsigned char *)data, data_len);
    if (ret == 1) {
      ret = EVP_SealFinal(ctx, buf + len1, &len2);
      if (ret == 1) lua_pushlstring(L, (const char *)buf, len1 + len2);
    }
  }

  if (lua_istable(L, 1)) {
    if (ret == 1) lua_newtable(L);
    for (i = 0; i < nkeys; i++) {
      if (ret == 1) {
        lua_pushlstring(L, (const char *)eks[i], eksl[i]);
        lua_rawseti(L, -2, i + 1);
      }
      free(eks[i]);
    }
  } else {
    if (ret == 1) lua_pushlstring(L, (const char *)eks[0], eksl[0]);
    free(eks[0]);
  }
  if (ret == 1) lua_pushlstring(L, iv, EVP_CIPHER_CTX_iv_length(ctx));

  free(buf);
  free(eks);
  free(eksl);
  free(pkeys);
  EVP_CIPHER_CTX_free(ctx);

  return ret == 1 ? 3 : 0;
}

/***
 * open and decrypt message with private key
 * pair with seal
 * @function open
 * @tparam string data data to be decrypted
 * @tparam string skey secret key encrypted by public key
 * @tparam string iv
 * @tparam[opt='RC4'] cipher|string alg
 * @treturn string decrypted data
 */
int
openssl_open(lua_State *L)
{
  EVP_PKEY   *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  size_t      data_len, ekey_len, iv_len;
  const char *data = luaL_checklstring(L, 2, &data_len);
  const char *ekey = luaL_checklstring(L, 3, &ekey_len);
  const char *iv = luaL_checklstring(L, 4, &iv_len);

  int            ret = 0;
  int            len1, len2 = 0;
  unsigned char *buf;

  const EVP_CIPHER *cipher = NULL;

  cipher = get_cipher(L, 5, "aes-128-cbc");

  if (cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    len1 = data_len + 1;
    buf = malloc(len1);

    EVP_CIPHER_CTX_reset(ctx);

    ret
      = EVP_OpenInit(ctx, cipher, (unsigned char *)ekey, ekey_len, (const unsigned char *)iv, pkey);
    if (ret > 0) {
      ret = EVP_OpenUpdate(ctx, buf, &len1, (unsigned char *)data, data_len);
      if (ret == 1) {
        len2 = data_len - len1;
        ret = EVP_OpenFinal(ctx, buf + len1, &len2);
        if (ret == 1) {
          lua_pushlstring(L, (const char *)buf, len1 + len2);
        }
      }
    }
    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    ret = 1;
  }

  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

/***
 * seal_init - initialize seal operation
 * @function seal_init
 * @tparam openssl.evp_pkey pkey public key
 * @tparam[opt='RC4'] cipher|string alg
 * @treturn string skey secret key encrypted by public key
 * @treturn string iv
 */
int
openssl_seal_init(lua_State *L)
{
  int             i, ret = 0, nkeys = 0;
  EVP_PKEY      **pkeys;
  unsigned char **eks;
  int            *eksl;
  EVP_CIPHER_CTX *ctx = NULL;

  char              iv[EVP_MAX_MD_SIZE] = { 0 };
  const EVP_CIPHER *cipher = NULL;

  luaL_argcheck(L,
                lua_istable(L, 1) || auxiliar_getclassudata(L, "openssl.evp_pkey", 1),
                1,
                "must be openssl.evp_pkey or array");

  if (lua_istable(L, 1)) {
    nkeys = lua_rawlen(L, 1);
    luaL_argcheck(L, nkeys != 0, 1, "empty array");
  } else if (auxiliar_getclassudata(L, "openssl.evp_pkey", 1)) {
    nkeys = 1;
  }

  cipher = get_cipher(L, 2, "aes-128-cbc");

  pkeys = malloc(nkeys * sizeof(*pkeys));
  eksl = malloc(nkeys * sizeof(*eksl));
  eks = malloc(nkeys * sizeof(*eks));

  memset(eks, 0, sizeof(*eks) * nkeys);

  /* get the public keys we are using to seal this data */
  if (lua_istable(L, 1)) {
    for (i = 0; i < nkeys; i++) {
      lua_rawgeti(L, 1, i + 1);

      pkeys[i] = CHECK_OBJECT(-1, EVP_PKEY, "openssl.evp_pkey");
      if (pkeys[i] == NULL) {
        luaL_argerror(L, 1, "table with gap");
      }
      eksl[i] = EVP_PKEY_size(pkeys[i]);
      eks[i] = malloc(eksl[i]);

      lua_pop(L, 1);
    }
  } else {
    pkeys[0] = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
    eksl[0] = EVP_PKEY_size(pkeys[0]);
    eks[0] = malloc(eksl[0]);
  }

  ctx = EVP_CIPHER_CTX_new();
  ret = EVP_SealInit(ctx, cipher, eks, eksl, (unsigned char *)iv, pkeys, nkeys);
  if (ret == 1) {
    PUSH_OBJECT(ctx, "openssl.evp_cipher_ctx");
  }

  if (lua_istable(L, 1)) {
    if (ret == 1) lua_newtable(L);
    for (i = 0; i < nkeys; i++) {
      if (ret == 1) {
        lua_pushlstring(L, (const char *)eks[i], eksl[i]);
        lua_rawseti(L, -2, i + 1);
      }
      free(eks[i]);
    }
  } else {
    if (ret == 1) lua_pushlstring(L, (const char *)eks[0], eksl[0]);
    free(eks[0]);
  }
  if (ret == 1) lua_pushlstring(L, iv, EVP_CIPHER_CTX_iv_length(ctx));

  free(eks);
  free(eksl);
  free(pkeys);

  return ret == 1 ? 3 : 0;
}

/***
 * seal_update - update seal operation
 * @function seal_update
 * @tparam string data data to encrypt
 * @treturn string encrypted data
 */
int
openssl_seal_update(lua_State *L)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  size_t          data_len;
  const char     *data = luaL_checklstring(L, 2, &data_len);
  int             len = data_len + EVP_CIPHER_CTX_block_size(ctx);
  unsigned char  *buf = malloc(len);
  int             ret = EVP_SealUpdate(ctx, buf, &len, (unsigned char *)data, data_len);

  if (ret == 1) {
    lua_pushlstring(L, (const char *)buf, len);
  }

  free(buf);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

/***
 * seal_final - finalize seal operation
 * @function seal_final
 * @treturn string final encrypted data
 */
int
openssl_seal_final(lua_State *L)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  int             len = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char  *buf = malloc(len);
  int             ret = EVP_SealFinal(ctx, buf, &len);
  if (ret == 1) {
    lua_pushlstring(L, (const char *)buf, len);
  }

  free(buf);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

/***
 * open_init - initialize open operation
 * @function open_init
 * @tparam openssl.evp_pkey pkey private key
 * @tparam string skey secret key encrypted by public key
 * @tparam string iv
 * @tparam[opt='RC4'] cipher|string alg
 * @treturn boolean true for success
 */
int
openssl_open_init(lua_State *L)
{
  EVP_PKEY   *pkey = CHECK_OBJECT(1, EVP_PKEY, "openssl.evp_pkey");
  size_t      ekey_len, iv_len;
  const char *ekey = luaL_checklstring(L, 2, &ekey_len);
  const char *iv = luaL_checklstring(L, 3, &iv_len);

  const EVP_CIPHER *cipher = get_cipher(L, 4, "aes-128-cbc");
  int               ret = 0;

  if (cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_reset(ctx);
    ret
      = EVP_OpenInit(ctx, cipher, (unsigned char *)ekey, ekey_len, (const unsigned char *)iv, pkey);
    if (ret > 0) {
      PUSH_OBJECT(ctx, "openssl.evp_cipher_ctx");
      ret = 1;
    } else
      EVP_CIPHER_CTX_free(ctx);
  }
  return ret == 1 ? ret : openssl_pushresult(L, ret);
};

/***
 * open_update - update open operation
 * @function open_update
 * @tparam string data data to decrypt
 * @treturn string decrypted data
 */
int
openssl_open_update(lua_State *L)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  size_t          data_len;
  const char     *data = luaL_checklstring(L, 2, &data_len);

  int            len = EVP_CIPHER_CTX_block_size(ctx) + data_len;
  unsigned char *buf = malloc(len);

  int ret = EVP_OpenUpdate(ctx, buf, &len, (unsigned char *)data, data_len);
  if (ret == 1) {
    lua_pushlstring(L, (const char *)buf, len);
  }
  free(buf);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

/***
 * open_final - finalize open operation
 * @function open_final
 * @treturn string final decrypted data
 */
int
openssl_open_final(lua_State *L)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  int             len = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char  *buf = malloc(len);
  int             ret = EVP_OpenFinal(ctx, buf, &len);
  if (ret == 1) {
    lua_pushlstring(L, (const char *)buf, len);
  }
  free(buf);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
