/*=========================================================================*\
* cipher.c
* cipher module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME    "cipher"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static LUA_FUNCTION(openssl_cipher_list)
{
  int alias = lua_isnoneornil(L, 1) ? 1 : lua_toboolean(L, 1);
  lua_newtable(L);
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, alias ? openssl_add_method_or_alias : openssl_add_method, L);
  return 1;
}

static LUA_FUNCTION(openssl_cipher_get)
{
  if (!lua_isuserdata(L, 1))
  {
    const EVP_CIPHER* cipher = get_cipher(L, 1, NULL);

    if (cipher)
      PUSH_OBJECT((void*)cipher, "openssl.evp_cipher");
    else
      lua_pushnil(L);
  }
  else
  {
    luaL_argcheck(L, auxiliar_isclass(L, "openssl.evp_cipher", 1), 1, "only accept openssl.evp_cipher object");
    lua_pushvalue(L, 1);
  }
  return 1;
}

static LUA_FUNCTION(openssl_evp_encrypt)
{
  const EVP_CIPHER* cipher = NULL;
  if (lua_istable(L, 1))
  {
    if (lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
    {
      lua_pop(L, 1);
      lua_remove(L, 1);
    }
    else
      luaL_error(L, "call function with invalid state");
  }

  cipher = get_cipher(L, 1, NULL);
  if (cipher)
  {
    size_t input_len = 0;
    const char *input = luaL_checklstring(L, 2, &input_len);
    size_t key_len = 0;
    const char *key = luaL_optlstring(L, 3, NULL, &key_len); /* can be NULL */
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 4, NULL, &iv_len);   /* can be NULL */
    int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
    ENGINE *e = lua_isnoneornil(L, 6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

    int output_len = 0;
    int len = 0;
    char *buffer = NULL;
    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};
    int ret = 0;

    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }

    EVP_CIPHER_CTX_init(c);
    ret = EVP_EncryptInit_ex(c, cipher, e, (const byte*)evp_key, iv_len > 0 ? (const byte*)evp_iv : NULL);
    if (ret == 1)
    {
      ret = EVP_CIPHER_CTX_set_padding(c, pad);
      if (ret == 1)
      {
        buffer = OPENSSL_malloc(input_len + EVP_CIPHER_CTX_block_size(c));
        ret = EVP_EncryptUpdate(c, (byte*) buffer, &len, (const byte*)input, input_len);
        if ( ret == 1 )
        {
          output_len += len;
          ret = EVP_EncryptFinal(c, (byte*)buffer + len, &len);
          if (ret == 1)
          {
            output_len += len;
            lua_pushlstring(L,  buffer, output_len);
          }
        }
        OPENSSL_free(buffer);
      }
    }
    EVP_CIPHER_CTX_cleanup(c);
    EVP_CIPHER_CTX_free(c);
    return (ret == 1) ? ret : openssl_pushresult(L, ret);
  }
  else
    luaL_error(L, "argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");
  return 0;
}

static LUA_FUNCTION(openssl_evp_decrypt)
{
  const EVP_CIPHER* cipher;
  if (lua_istable(L, 1))
  {
    if (lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
    {
      lua_pop(L, 1);
      lua_remove(L, 1);
    }
    else
      luaL_error(L, "call function with invalid state");
  }

  cipher = get_cipher(L, 1, NULL);
  if (cipher)
  {
    size_t input_len = 0;
    const char *input = luaL_checklstring(L, 2, &input_len);
    size_t key_len = 0;
    const char *key = luaL_optlstring(L, 3, NULL, &key_len); /* can be NULL */
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 4, NULL, &iv_len); /* can be NULL */
    int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
    ENGINE *e = lua_isnoneornil(L, 6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

    int output_len = 0;
    int len = 0;
    char *buffer = NULL;
    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};
    int ret;
    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }

    EVP_CIPHER_CTX_init(c);
    ret = EVP_DecryptInit_ex(c, cipher, e, key ? (const byte*)evp_key : NULL, iv_len > 0 ? (const byte*)evp_iv : NULL);
    if (ret == 1)
    {
      ret = EVP_CIPHER_CTX_set_padding(c, pad);
      if (ret == 1)
      {
        buffer = OPENSSL_malloc(input_len);

        ret = EVP_DecryptUpdate(c, (byte*)buffer, &len, (const byte*)input, input_len);
        if (ret == 1)
        {
          output_len += len;
          len = input_len - len;
          ret = EVP_DecryptFinal(c, (byte*)buffer + output_len, &len);
          if (ret == 1)
          {
            output_len += len;
            lua_pushlstring(L, buffer, output_len);
          }
        }
        OPENSSL_free(buffer);
      }
    }
    EVP_CIPHER_CTX_cleanup(c);
    EVP_CIPHER_CTX_free(c);
    return (ret == 1) ? ret : openssl_pushresult(L, ret);
  }
  else
    luaL_argerror(L, 1, "invalid cipher algorithm or openssl.evp_cipher object");
  return 0;
}

static LUA_FUNCTION(openssl_evp_cipher)
{
  const EVP_CIPHER* cipher = NULL;
  if (lua_istable(L, 1))
  {
    if (lua_getmetatable(L, 1) && lua_equal(L, 1, -1))
    {
      lua_pop(L, 1);
      lua_remove(L, 1);
    }
    else
      luaL_error(L, "call function with invalid state");
  }

  cipher = get_cipher(L, 1, NULL);

  if (cipher)
  {
    int enc = lua_toboolean(L, 2);
    size_t input_len = 0;
    const char *input = luaL_checklstring(L, 3, &input_len);
    size_t key_len = 0;
    const char *key = luaL_checklstring(L, 4, &key_len);
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 5, NULL, &iv_len); /* can be NULL */

    int pad = lua_isnone(L, 6) ? 1 : lua_toboolean(L, 6);
    ENGINE *e = lua_isnoneornil(L, 7) ? NULL : CHECK_OBJECT(7, ENGINE, "openssl.engine");

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

    int output_len = 0;
    int len = 0;

    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};

    int ret;

    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }

    EVP_CIPHER_CTX_init(c);
    ret = EVP_CipherInit_ex(c, cipher, e, (const byte*)evp_key, iv_len > 0 ? (const byte*)evp_iv : NULL, enc);
    if (ret == 1)
    {
      ret = EVP_CIPHER_CTX_set_padding(c, pad);
      if (ret == 1)
      {
        char *buffer;
        len = input_len + EVP_MAX_BLOCK_LENGTH;
        buffer = OPENSSL_malloc(len);
        ret = EVP_CipherUpdate(c, (byte*)buffer, &len, (const byte*)input, input_len);
        if (ret == 1)
        {
          output_len += len;
          len = input_len + EVP_MAX_BLOCK_LENGTH - len;
          ret = EVP_CipherFinal(c, (byte*)buffer + output_len, &len);
          if (ret == 1)
          {
            output_len += len;
            lua_pushlstring(L, buffer, output_len);
          }
        }
        OPENSSL_free(buffer);
      }
    }
    EVP_CIPHER_CTX_cleanup(c);
    EVP_CIPHER_CTX_free(c);
    return (ret == 1) ? ret : openssl_pushresult(L, ret);
  }
  else
    luaL_argerror(L, 1, "invvalid cipher algorithm or openssl.evp_cipher object");

  return 0;
}

typedef enum
{
  DO_CIPHER = -1,
  DO_ENCRYPT = 0,
  DO_DECRYPT = 1
} CIPHER_MODE;

static LUA_FUNCTION(openssl_cipher_new)
{
  const EVP_CIPHER* cipher = get_cipher(L, 1, NULL);
  if (cipher)
  {
    int enc = lua_toboolean(L, 2);
    size_t key_len = 0;
    const char *key = luaL_checklstring(L, 3, &key_len);
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 4, NULL, &iv_len);
    int pad = lua_isnoneornil(L, 5) ? 1 : lua_toboolean(L, 5);
    ENGINE *e = lua_isnoneornil(L, 6) ? NULL : CHECK_OBJECT(6, ENGINE, "openssl.engine");
    EVP_CIPHER_CTX *c = NULL;

    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};
    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }
    c = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(c);
    if (!EVP_CipherInit_ex(c, cipher, e, key ? (const byte*)evp_key : NULL, iv_len > 0 ? (const byte*)evp_iv : NULL, enc))
    {
      EVP_CIPHER_CTX_set_padding(c, pad);
      luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
    }
    PUSH_OBJECT(c, "openssl.evp_cipher_ctx");
    lua_pushinteger(L, DO_CIPHER);
    lua_rawsetp(L, LUA_REGISTRYINDEX, c);
  }
  else
    luaL_error(L, "argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");

  return 1;
}

static LUA_FUNCTION(openssl_cipher_encrypt_new)
{
  const EVP_CIPHER* cipher  = get_cipher(L, 1, NULL);
  if (cipher)
  {
    size_t key_len = 0;
    const char *key = luaL_optlstring(L, 2, NULL, &key_len); /* can be NULL */
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 3, NULL, &iv_len); /* can be NULL */
    int pad = lua_isnoneornil(L, 4) ? 1 : lua_toboolean(L, 4);
    ENGINE *e = lua_isnoneornil(L, 5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
    EVP_CIPHER_CTX *c = NULL;

    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};
    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }
    c = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(c);
    if (!EVP_EncryptInit_ex(c, cipher, e, key ? (const byte*)evp_key : NULL, iv_len > 0 ? (const byte*)evp_iv : NULL))
    {
      EVP_CIPHER_CTX_set_padding(c, pad);
      luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
    }
    PUSH_OBJECT(c, "openssl.evp_cipher_ctx");
    lua_pushinteger(L, DO_ENCRYPT);
    lua_rawsetp(L, LUA_REGISTRYINDEX, c);
  }
  else
    luaL_error(L, "argument #1 is not a valid cipher algorithm or openssl.evp_cipher object");

  return 1;
}

static LUA_FUNCTION(openssl_cipher_decrypt_new)
{
  const EVP_CIPHER* cipher = get_cipher(L, 1, NULL);
  if (cipher)
  {
    size_t key_len = 0;
    const char *key = luaL_optlstring(L, 2, NULL, &key_len); /* can be NULL */
    size_t iv_len = 0;
    const char *iv = luaL_optlstring(L, 3, NULL, &iv_len); /* can be NULL */
    int pad = lua_isnoneornil(L, 4) ? 1 : lua_toboolean(L, 4);
    ENGINE *e = lua_isnoneornil(L, 5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
    EVP_CIPHER_CTX *c = NULL;

    char evp_key[EVP_MAX_KEY_LENGTH] = {0};
    char evp_iv[EVP_MAX_IV_LENGTH] = {0};
    int ret;

    if (key)
    {
      key_len = EVP_MAX_KEY_LENGTH > key_len ? key_len : EVP_MAX_KEY_LENGTH;
      memcpy(evp_key, key, key_len);
    }
    if (iv_len > 0 && iv)
    {
      iv_len = EVP_MAX_IV_LENGTH > iv_len ? iv_len : EVP_MAX_IV_LENGTH;
      memcpy(evp_iv, iv, iv_len);
    }
    c = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(c);
    ret = EVP_DecryptInit_ex(c, cipher, e, key ? (const byte*)evp_key : NULL, iv_len > 0 ? (const byte*)evp_iv : NULL);
    if (ret == 1)
    {
      ret = EVP_CIPHER_CTX_set_padding(c, pad);
      if (ret == 1)
      {
        PUSH_OBJECT(c, "openssl.evp_cipher_ctx");
        lua_pushinteger(L, DO_DECRYPT);
        lua_rawsetp(L, LUA_REGISTRYINDEX, c);
        return 1;
      }
      else
      {
        EVP_CIPHER_CTX_free(c);
        luaL_error(L, "EVP_CipherInit_ex failed, please check openssl error");
      }
    }
    EVP_CIPHER_CTX_free(c);
  }
  else
    luaL_argerror(L, 1, "invalid cipher algorithm or openssl.evp_cipher object");

  return 0;
}

/* evp_cipher method */
static LUA_FUNCTION(openssl_cipher_info)
{
  EVP_CIPHER *cipher = CHECK_OBJECT(1, EVP_CIPHER, "openssl.evp_cipher");
  lua_newtable(L);
  AUXILIAR_SET(L, -1, "name", EVP_CIPHER_name(cipher), string);
  AUXILIAR_SET(L, -1, "block_size", EVP_CIPHER_block_size(cipher), integer);
  AUXILIAR_SET(L, -1, "key_length", EVP_CIPHER_key_length(cipher), integer);
  AUXILIAR_SET(L, -1, "iv_length", EVP_CIPHER_iv_length(cipher), integer);
  AUXILIAR_SET(L, -1, "flags", EVP_CIPHER_flags(cipher), integer);
  AUXILIAR_SET(L, -1, "mode", EVP_CIPHER_mode(cipher), integer);
  return 1;
}


static LUA_FUNCTION(openssl_evp_BytesToKey)
{
  EVP_CIPHER* c = CHECK_OBJECT(1, EVP_CIPHER, "openssl.evp_cipher");
  size_t lsalt, lk;
  const char* k = luaL_checklstring(L, 2, &lk);
  const char* salt = luaL_optlstring(L, 3, NULL, &lsalt);
  const EVP_MD* m = lua_isnoneornil(L, 4) ? EVP_get_digestbyname("sha1") : get_digest(L, 4);
  char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  int ret;
  if (salt != NULL && lsalt < PKCS5_SALT_LEN)
  {
    lua_pushfstring(L, "salt must not shorter than %d", PKCS5_SALT_LEN);
    luaL_argerror(L, 3, lua_tostring(L, -1));
  }

  ret = EVP_BytesToKey(c, m, (unsigned char*)salt, (unsigned char*)k, lk, 1, (unsigned char*)key, (unsigned char*)iv);
  if (ret > 1)
  {
    lua_pushlstring(L, key, EVP_CIPHER_key_length(c));
    lua_pushlstring(L, iv, EVP_CIPHER_iv_length(c));
    return 2;
  }
  return openssl_pushresult(L, ret);
}


/* evp_cipher_ctx method */
static LUA_FUNCTION(openssl_evp_cipher_update)
{
  EVP_CIPHER_CTX* c = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  size_t inl;
  const char* in = luaL_checklstring(L, 2, &inl);
  int outl = inl + EVP_MAX_BLOCK_LENGTH;
  char* out = OPENSSL_malloc(outl);
  CIPHER_MODE mode;
  int ret = 0;

  lua_rawgetp(L, LUA_REGISTRYINDEX, c);
  mode = lua_tointeger(L, -1);

  if (mode == DO_CIPHER)
    ret = EVP_CipherUpdate(c, (byte*)out, &outl, (const byte*)in, inl);
  else if (mode == DO_ENCRYPT)
    ret = EVP_EncryptUpdate(c, (byte*)out, &outl, (const byte*)in, inl);
  else if (mode == DO_DECRYPT)
    ret = EVP_DecryptUpdate(c, (byte*)out, &outl, (const byte*)in, inl);
  else
    luaL_error(L, "never go here");
  lua_pop(L, 1);

  if (ret == 1)
  {
    lua_pushlstring(L, out, outl);
  }
  OPENSSL_free(out);

  return (ret == 1 ? ret : openssl_pushresult(L, ret));
}

static LUA_FUNCTION(openssl_evp_cipher_final)
{
  EVP_CIPHER_CTX* c = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  char out[EVP_MAX_BLOCK_LENGTH];
  int outl = sizeof(out);
  CIPHER_MODE mode;
  int ret = 0;

  lua_rawgetp(L, LUA_REGISTRYINDEX, c);
  mode = lua_tointeger(L, -1);

  if (mode == DO_CIPHER)
    ret = EVP_CipherFinal_ex(c, (byte*)out, &outl);
  else if (mode == DO_ENCRYPT)
    ret = EVP_EncryptFinal_ex(c, (byte*)out, &outl);
  else if (mode == DO_DECRYPT)
    ret = EVP_DecryptFinal_ex(c, (byte*)out, &outl);
  else
    luaL_error(L, "never go here");
  lua_pop(L, 1);

  if (ret == 1)
  {
    lua_pushlstring(L, out, outl);
    return 1;
  }
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_cipher_ctx_info)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  lua_newtable(L);
  AUXILIAR_SET(L, -1, "block_size", EVP_CIPHER_CTX_block_size(ctx), integer);
  AUXILIAR_SET(L, -1, "key_length", EVP_CIPHER_CTX_key_length(ctx), integer);
  AUXILIAR_SET(L, -1, "iv_length", EVP_CIPHER_CTX_iv_length(ctx), integer);
  AUXILIAR_SET(L, -1, "flags", EVP_CIPHER_CTX_flags(ctx), integer);
  AUXILIAR_SET(L, -1, "nid", EVP_CIPHER_CTX_nid(ctx), integer);
  AUXILIAR_SET(L, -1, "type", EVP_CIPHER_CTX_mode(ctx), integer);
  AUXILIAR_SET(L, -1, "mode", EVP_CIPHER_CTX_type(ctx), integer);

  AUXILIAR_SETOBJECT(L, EVP_CIPHER_CTX_cipher(ctx), "openssl.evp_cipher", -1, "cipher");
  return 1;
}

static LUA_FUNCTION(openssl_cipher_ctx_free)
{
  EVP_CIPHER_CTX *ctx = CHECK_OBJECT(1, EVP_CIPHER_CTX, "openssl.evp_cipher_ctx");
  lua_pushnil(L);
  lua_rawsetp(L, LUA_REGISTRYINDEX, ctx);
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

static luaL_Reg cipher_funs[] =
{
  {"info",        openssl_cipher_info},
  {"new",         openssl_cipher_new},
  {"encrypt_new", openssl_cipher_encrypt_new},
  {"decrypt_new", openssl_cipher_decrypt_new},

  {"BytesToKey",  openssl_evp_BytesToKey},

  {"encrypt",     openssl_evp_encrypt },
  {"decrypt",     openssl_evp_decrypt },
  {"cipher",      openssl_evp_cipher },

  {"__tostring",  auxiliar_tostring},

  {NULL, NULL}
};

static luaL_Reg cipher_ctx_funs[] =
{
  {"update",      openssl_evp_cipher_update},
  {"final",       openssl_evp_cipher_final},
  {"info",        openssl_cipher_ctx_info},
  {"close",       openssl_cipher_ctx_free},

  {"__gc",        openssl_cipher_ctx_free},
  {"__tostring",  auxiliar_tostring},

  {NULL, NULL}
};

static const luaL_Reg R[] =
{
  { "__call",  openssl_evp_cipher},
  { "list",    openssl_cipher_list},
  { "get",     openssl_cipher_get},
  { "encrypt", openssl_evp_encrypt},
  { "decrypt", openssl_evp_decrypt},
  { "cipher",  openssl_evp_cipher},

  { "new",     openssl_cipher_new},
  { "encrypt_new", openssl_cipher_encrypt_new},
  { "decrypt_new", openssl_cipher_decrypt_new},

  {NULL,  NULL}
};

int luaopen_cipher(lua_State *L)
{
  auxiliar_newclass(L, "openssl.evp_cipher",      cipher_funs);
  auxiliar_newclass(L, "openssl.evp_cipher_ctx",  cipher_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}

