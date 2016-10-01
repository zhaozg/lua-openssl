/*=========================================================================*\
* openssl.c
* lua-openssl binding
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/opensslconf.h>
#include "private.h"

static int openssl_version(lua_State*L)
{
  int num = lua_isnoneornil(L, 1) ? 0 : auxiliar_checkboolean(L, 1);
  if (num)
  {
    lua_pushinteger(L, LOPENSSL_VERSION_NUM);
    lua_pushinteger(L, LUA_VERSION_NUM);
    lua_pushinteger(L, OPENSSL_VERSION_NUMBER);
  }
  else
  {
    lua_pushstring(L, LOPENSSL_VERSION);
    lua_pushstring(L, LUA_VERSION);
    lua_pushstring(L, OPENSSL_VERSION_TEXT);
  }
  return 3;
}

static LUA_FUNCTION(openssl_hex)
{
  size_t l = 0;
  const char* s = luaL_checklstring(L, 1, &l);
  int encode = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  char* h = NULL;

  if (l == 0)
  {
    lua_pushstring(L, "");
    return 1;
  }
  if (encode)
  {
    h = OPENSSL_malloc(2 * l + 1);
    l = bin2hex((const unsigned char *)s, h, l);
  }
  else
  {
    h = OPENSSL_malloc(l / 2 + 1);
    l = hex2bin(s, (unsigned char *)h, l);
  };
  lua_pushlstring(L, (const char*)h, l);
  OPENSSL_free(h);

  return 1;
}

static LUA_FUNCTION(openssl_base64)
{
  BIO *inp = load_bio_object(L, 1);
  int encode = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  int nonl = lua_isnoneornil(L, 3) ? BIO_FLAGS_BASE64_NO_NL
             : (lua_toboolean(L, 3) ? BIO_FLAGS_BASE64_NO_NL : 0);
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *out = BIO_new(BIO_s_mem());
  BUF_MEM* mem = {0};

  BIO_set_flags(b64, nonl);
  if (encode)
  {
    BIO_push(b64, out);
    BIO_get_mem_ptr(inp, &mem);
    BIO_write(b64, mem->data, mem->length);
    BIO_flush(b64);
  }
  else
  {
    char inbuf[512];
    int inlen;
    BIO_push(b64, inp);
    while ((inlen = BIO_read(b64, inbuf, 512)) > 0)
      BIO_write(out, inbuf, inlen);
    BIO_flush(out);
  }

  BIO_get_mem_ptr(out, &mem);
  if (mem->length > 0)
    lua_pushlstring(L, mem->data, mem->length);
  else
    lua_pushnil(L);
  BIO_free_all(b64);
  if (encode)
    BIO_free(inp);
  else
    BIO_free(out);
  return 1;
}

static void list_callback(const OBJ_NAME *obj, void *arg)
{
  lua_State *L = (lua_State *)arg;
  int idx = (int)lua_rawlen(L, -1);
  lua_pushstring(L, obj->name);
  lua_rawseti(L, -2, idx + 1);
}

static LUA_FUNCTION(openssl_list)
{
  static int options[] =
  {
    OBJ_NAME_TYPE_MD_METH,
    OBJ_NAME_TYPE_CIPHER_METH,
    OBJ_NAME_TYPE_PKEY_METH,
    OBJ_NAME_TYPE_COMP_METH
  };
  static const char *names[] = {"digests", "ciphers", "pkeys", "comps", NULL};
  int type = auxiliar_checkoption (L, 1, NULL, names, options);
  lua_createtable(L, 0, 0);
  OBJ_NAME_do_all_sorted(type, list_callback, L);
  return 1;
}

static LUA_FUNCTION(openssl_error_stack)
{
  int flags, line, idx=0;
  const char *data, *file;
  unsigned long code;
  char *errstr, errbuf[256];

  lua_newtable(L);
  code = ERR_get_error_line_data(&file, &line, &data, &flags);
  while (code)
  {
    idx++;
    lua_pushinteger(L, idx);
    lua_newtable(L);
    lua_pushnumber(L, (double) code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, ERR_error_string(code, errbuf));
    lua_setfield(L, -2, "err");
    lua_pushstring(L, file);
    lua_setfield(L, -2, "file");
    lua_pushinteger(L, line);
    lua_setfield(L, -2, "line");
    if (data && (flags & ERR_TXT_STRING))
    {
      lua_pushstring(L, data);
      lua_setfield(L, -2, "data");
    }
    lua_settable(L, -3);
    code = ERR_get_error_line_data(&file, &line, &data, &flags);
  }
  return 1;
}

static LUA_FUNCTION(openssl_error_string)
{
  unsigned long val;
  int clear, ret = 0;
  if (lua_isnumber(L, 1))
  {
    val = (unsigned long)lua_tonumber(L, 1);
    clear = lua_toboolean(L, 2);
  }
  else
  {
    val = ERR_get_error();
    clear = lua_toboolean(L, 1);
  }

  if (val)
  {
    lua_pushinteger(L, val);
    lua_pushstring (L, ERR_reason_error_string(val));
    lua_pushstring (L, ERR_lib_error_string   (val));
    lua_pushstring (L, ERR_func_error_string  (val));
#ifdef ERR_FATAL_ERROR
    lua_pushboolean(L, ERR_FATAL_ERROR        (val));
    ret = 5;
#else
    ret = 4;
#endif
  }

  if (clear)
    ERR_clear_error();

  return ret;
}

static int openssl_random_load(lua_State*L)
{
  const char *file = luaL_optstring(L, 1, NULL);
  char buffer[MAX_PATH];
  int len;

  if (file == NULL)
    file = RAND_file_name(buffer, sizeof buffer);
  else if (RAND_egd(file) > 0)
  {
    /* we try if the given filename is an EGD socket.
       if it is, we don't write anything back to the file. */;
    lua_pushboolean(L, 1);
    return 1;
  }

  len = luaL_optinteger(L, 2, 2048);
  if (file == NULL || !RAND_load_file(file, len))
  {
    return openssl_pushresult(L, 0);
  }

  lua_pushboolean(L, RAND_status());
  return 1;
}

static int openssl_random_write(lua_State *L)
{
  const char *file = luaL_optstring(L, 1, NULL);
  char buffer[MAX_PATH];
  int n;

  if (file==NULL && (file = RAND_file_name(buffer, sizeof buffer))==NULL)
    return openssl_pushresult(L, 0);

  n = RAND_write_file(file);
  return openssl_pushresult(L, 1);
}

static int openssl_random_status(lua_State *L)
{
  lua_pushboolean(L, RAND_status());
  return 1;
}

static int openssl_random_cleanup(lua_State *L)
{
  (void) L;
  RAND_cleanup();
  return 0;
}

static LUA_FUNCTION(openssl_random_bytes)
{
  long length = luaL_checkint(L, 1);
  int strong = lua_isnil(L, 2) ? 0 : lua_toboolean(L, 2);

  char *buffer = NULL;
  int ret = 0;

  if (length <= 0)
  {
    luaL_argerror(L, 1, "must greater than 0");
  }

  buffer = malloc(length + 1);
  if (strong)
  {
    ret = RAND_bytes((byte*)buffer, length);
    if (ret == 1)
    {
      lua_pushlstring(L, buffer, length);
    }
    else
    {
      lua_pushboolean(L, 0);
    }
  }
  else
  {
    ret = RAND_pseudo_bytes((byte*)buffer, length);
    if (ret == 1)
    {
      lua_pushlstring(L, buffer, length);
    }
    else
    {
      lua_pushboolean(L, 0);
    }
  }
  free(buffer);
  return 1;
}

static int openssl_mem_leaks(lua_State*L)
{
  BIO *bio = BIO_new(BIO_s_mem());
  BUF_MEM* mem;

  /* OBJ_cleanup */
  CRYPTO_mem_leaks(bio);
  BIO_get_mem_ptr(bio, &mem);
  lua_pushlstring(L, mem->data, mem->length);
  BIO_free(bio);
  return 1;
}

static const luaL_Reg eay_functions[] =
{
  {"version",     openssl_version},
  {"list",        openssl_list},
  {"hex",         openssl_hex},
  {"base64",      openssl_base64},
  {"mem_leaks",   openssl_mem_leaks},

  {"rand_status", openssl_random_status},
  {"rand_load",   openssl_random_load},
  {"rand_write",  openssl_random_write},
  {"rand_cleanup", openssl_random_cleanup},
  {"random",      openssl_random_bytes},

  {"error",       openssl_error_string},
  {"errors",      openssl_error_stack},
  {"engine",      openssl_engine},

  {NULL, NULL}
};

#if defined(OPENSSL_THREADS)
void CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
#endif

LUALIB_API int luaopen_openssl(lua_State*L)
{
  static int init = 0;
  if (init == 0)
  {
#if defined(OPENSSL_THREADS)
    CRYPTO_thread_setup();
#endif

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    SSL_library_init();

    ERR_load_ERR_strings();
    ERR_load_EVP_strings();
    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE_load_openssl();
#ifdef LOAD_ENGINE_CUSTOM
    LOAD_ENGINE_CUSTOM
#endif
#ifdef OPENSSL_SYS_WINDOWS
    RAND_screen();
#endif
    init = 1;
  }

  lua_newtable(L);
  luaL_setfuncs(L, eay_functions, 0);

  openssl_register_lhash(L);
  openssl_register_engine(L);

  luaopen_bio(L);
  lua_setfield(L, -2, "bio");

  luaopen_asn1(L);
  lua_setfield(L, -2, "asn1");


  luaopen_digest(L);
  lua_setfield(L, -2, "digest");

  luaopen_cipher(L);
  lua_setfield(L, -2, "cipher");

  luaopen_hmac(L);
  lua_setfield(L, -2, "hmac");

  luaopen_pkey(L);
  lua_setfield(L, -2, "pkey");

#ifdef EVP_PKEY_EC
  luaopen_ec(L);
  lua_setfield(L, -2, "ec");
#endif

  luaopen_x509(L);
  lua_setfield(L, -2, "x509");

  luaopen_pkcs7(L);
  lua_setfield(L, -2, "pkcs7");

  luaopen_pkcs12(L);
  lua_setfield(L, -2, "pkcs12");

  luaopen_ocsp(L);
  lua_setfield(L, -2, "ocsp");

#ifdef OPENSSL_HAVE_TS
  /* timestamp handling */
  luaopen_ts(L);
  lua_setfield(L, -2, "ts");
#endif

  luaopen_cms(L);
  lua_setfield(L, -2, "cms");

  luaopen_ssl(L);
  lua_setfield(L, -2, "ssl");

  /* third part */
  luaopen_bn(L);
  lua_setfield(L, -2, "bn");

  luaopen_rsa(L);
  lua_setfield(L, -2, "rsa");
  luaopen_dsa(L);
  lua_setfield(L, -2, "dsa");
  luaopen_dh(L);
  lua_setfield(L, -2, "dh");

#ifdef ENABLE_OPENSSL_GLOBAL
  lua_pushvalue(L, -1);
  lua_setglobal(L, "openssl");
#endif

  return 1;
}

