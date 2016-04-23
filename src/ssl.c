/*=========================================================================*\
* ssl.c
* SSL modules for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <stdint.h>
#include "ssl_options.h"

#define MYNAME    "ssl"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

#include <openssl/ssl.h>

static int openssl_ssl_ctx_new(lua_State*L)
{
  const char* meth = luaL_optstring(L, 1, "TLSv1");
#if OPENSSL_VERSION_NUMBER >= 0x01000000L
  const
#endif
  SSL_METHOD* method = NULL;
  const char* ciphers;
  SSL_CTX* ctx;
  if (strcmp(meth, "SSLv3") == 0)
    method = SSLv3_method();    /* SSLv3 */
  else if (strcmp(meth, "SSLv3_server") == 0)
    method = SSLv3_server_method(); /* SSLv3 */
  else if (strcmp(meth, "SSLv3_client") == 0)
    method = SSLv3_client_method(); /* SSLv3 */
  else if (strcmp(meth, "SSLv23") == 0)
    method = SSLv23_method();   /* SSLv3 but can rollback to v2 */
  else if (strcmp(meth, "SSLv23_server") == 0)
    method = SSLv23_server_method();  /* SSLv3 but can rollback to v2 */
  else if (strcmp(meth, "SSLv23_client") == 0)
    method = SSLv23_client_method();  /* SSLv3 but can rollback to v2 */

  else if (strcmp(meth, "TLSv1_1") == 0)
    method = TLSv1_1_method();    /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_1_server") == 0)
    method = TLSv1_1_server_method(); /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_1_client") == 0)
    method = TLSv1_1_client_method(); /* TLSv1.0 */

  else if (strcmp(meth, "TLSv1_2") == 0)
    method = TLSv1_2_method();    /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_2_server") == 0)
    method = TLSv1_2_server_method(); /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_2_client") == 0)
    method = TLSv1_2_client_method(); /* TLSv1.0 */

  else if (strcmp(meth, "TLSv1") == 0)
    method = TLSv1_method();    /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_server") == 0)
    method = TLSv1_server_method(); /* TLSv1.0 */
  else if (strcmp(meth, "TLSv1_client") == 0)
    method = TLSv1_client_method(); /* TLSv1.0 */

  else if (strcmp(meth, "DTLSv1") == 0)
    method = DTLSv1_method();   /* DTLSv1.0 */
  else if (strcmp(meth, "DTLSv1_server") == 0)
    method = DTLSv1_server_method();  /* DTLSv1.0 */
  else if (strcmp(meth, "DTLSv1_client") == 0)
    method = DTLSv1_client_method();  /* DTLSv1.0 */
#ifndef OPENSSL_NO_SSL2
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  else if (strcmp(meth, "SSLv2") == 0)
    method = SSLv2_method();    /* SSLv2 */
  else if (strcmp(meth, "SSLv2_server") == 0)
    method = SSLv2_server_method(); /* SSLv2 */
  else if (strcmp(meth, "SSLv2_client") == 0)
    method = SSLv2_client_method();
#endif
#endif
#ifdef LOAD_SSL_CUSTOM
  LOAD_SSL_CUSTOM
#endif
  else
    luaL_error(L, "#1:%s not supported\n"
               "Maybe SSLv3 SSLv23 TLSv1 TLSv1_1 TLSv1_2 DTLSv1 [SSLv2], option followed by _client or _server\n",
               "default is SSLv3",
               meth);
  ciphers = luaL_optstring(L, 2, SSL_DEFAULT_CIPHER_LIST);
  ctx = SSL_CTX_new(method);
  if (!ctx)
    luaL_error(L, "#1:%s not supported\n"
               "Maybe SSLv3 SSLv23 TLSv1 TLSv1_1 TLSv1_2 DTLSv1 [SSLv2], option followed by _client or _server\n",
               "default is SSLv3",
               meth);
  openssl_newvalue(L, ctx);
  SSL_CTX_set_cipher_list(ctx, ciphers);
  PUSH_OBJECT(ctx, "openssl.ssl_ctx");
  SSL_CTX_set_app_data(ctx, L);

  return 1;
}

static int openssl_ssl_alert_string(lua_State*L)
{
  int v = luaL_checkint(L, 1);
  int _long = lua_isnoneornil(L, 2) ? 0 : auxiliar_checkboolean(L, 2);
  const char* val;

  if (_long)
    val = SSL_alert_type_string_long(v);
  else
    val = SSL_alert_type_string(v);
  lua_pushstring(L, val);

  if (_long)
    val = SSL_alert_desc_string_long(v);
  else
    val = SSL_alert_desc_string(v);
  lua_pushstring(L, val);

  return 2;
}

/****************************SSL CTX********************************/
static int openssl_ssl_ctx_use(lua_State*L)
{
  int ret;
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  X509* cert = CHECK_OBJECT(3, X509, "openssl.x509");

  ret = SSL_CTX_use_certificate(ctx, cert);
  if (ret == 1)
  {
    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    if (ret == 1)
    {
      ret = SSL_CTX_check_private_key(ctx);
    }
  }
  return openssl_pushresult(L, ret);
}

static int openssl_ssl_ctx_add(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
  int ret = SSL_CTX_add_client_CA(ctx, x);
  if (ret == 1 && !lua_isnoneornil(L, 3))
  {
    size_t i;
    luaL_checktable(L, 3);

    for (i = 1; ret == 1 && i <= lua_rawlen(L, 3); i++ )
    {
      lua_rawgeti(L, 3, i);
      x = CHECK_OBJECT(2, X509, "openssl.x509");
      lua_pop(L, 1);
      CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
      ret = SSL_CTX_add_extra_chain_cert(ctx, x);
    }
  }
  return openssl_pushresult(L, ret);
}

static int openssl_ssl_ctx_gc(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  /*
  X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
  if (ctx)
  {
    int ref = openssl_refrence(L, ctx, -1);
    if (ref==0)
      openssl_xstore_free(cert_store);
    SSL_CTX_set_cert_store(ctx, NULL);
  }
  */
  openssl_freevalue(L, ctx);
  SSL_CTX_free(ctx);

  return 0;
}

static int openssl_ssl_ctx_timeout(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  long t;
  if (!lua_isnoneornil(L, 2))
  {
    t = SSL_CTX_set_timeout(ctx, luaL_checkint(L, 2));
    lua_pushinteger(L, t);
    return 1;
  }
  t = SSL_CTX_get_timeout(ctx);
  lua_pushinteger(L, t);
  return 1;
}

static const int iMode_options[] =
{
  SSL_MODE_ENABLE_PARTIAL_WRITE,
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
  SSL_MODE_AUTO_RETRY,
  SSL_MODE_NO_AUTO_CHAIN,
#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_MODE_RELEASE_BUFFERS,
#endif
  0
};

static const char* sMode_options[] =
{
  "enable_partial_write",
  "accept_moving_write_buffer",
  "auto_retry",
  "no_auto_chain",
#ifdef SSL_MODE_RELEASE_BUFFERS
  "release_buffers",
#endif
  NULL
};

static int openssl_ssl_ctx_mode(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  int mode = 0;
  int ret;
  int i;
  if (!lua_isnoneornil(L, 2))
  {
    int clear = lua_isboolean(L, 2) ? lua_toboolean(L, 2) : 0;
    i =  lua_isboolean(L, 2) ? 3 : 2;
    while (i <= lua_gettop(L))
    {
      mode = mode | auxiliar_checkoption(L, i++, NULL, sMode_options, iMode_options);
    }
    if (clear != 0)
      mode = SSL_CTX_set_mode(ctx, mode);
    else
      mode = SSL_CTX_clear_mode(ctx, mode);
  }
  else
    mode = SSL_CTX_get_mode(ctx);
  ret = 0;
  for (i = 0; i < sizeof(iMode_options) / sizeof(int); i++)
  {
    if (mode & iMode_options[i])
    {
      lua_pushstring(L, sMode_options[i]);
      ret++;
    }
  }
  return ret;
};


static int openssl_ssl_ctx_options(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  long options = 0;
  int ret;
  int i;
  if (!lua_isnoneornil(L, 2))
  {
    int top = lua_gettop(L);
    int clear = lua_isboolean(L, 2) ? lua_toboolean(L, 2) : 0;
    i = lua_isboolean(L, 2) ? 3 : 2;
    for (; i <= top; i++)
    {
      if (lua_isnumber(L, i))
        options |= (long)luaL_checkinteger(L, i);
      else
      {
        const char* s = luaL_checkstring(L, i);
        int j;
        for (j = 0; ssl_options[j].name; j++)
        {
          LuaL_Enum e = ssl_options[j];
          if (strcasecmp(s, e.name) == 0)
          {
            options |= e.val;
            break;
          }
        }
      }
    }


    if (clear != 0)
      options = SSL_CTX_clear_options(ctx, options);
    else
      options = SSL_CTX_set_options(ctx, options);
  }
  else
    options = SSL_CTX_get_options(ctx);

  lua_newtable(L);
  ret = 0;
  for (i = 0; ssl_options[i].name; i++)
  {
    LuaL_Enum e = ssl_options[i];
    if (options & e.val)
    {
      lua_pushstring(L, e.name);
      ret++;
      lua_rawseti(L, -2, ret);
    }
  }
  return 1;
}

static int openssl_ssl_ctx_quiet_shutdown(lua_State*L)
{
  SSL_CTX* s = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  if (lua_isnoneornil(L, 2))
  {
    int m = SSL_CTX_get_quiet_shutdown(s);
    lua_pushinteger(L, m);
    return 1;
  }
  else
  {
    int m = luaL_checkint(L, 2);
    SSL_CTX_set_quiet_shutdown(s, m);
    return 0;
  }
};

static int openssl_ssl_ctx_load_verify_locations(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  const char* CAfile = luaL_checkstring(L, 2);
  const char* CApath = luaL_optstring(L, 3, NULL);
  int ret = SSL_CTX_load_verify_locations(ctx, CAfile, CApath);
  return openssl_pushresult(L, ret);
}

static int openssl_ssl_ctx_cert_store(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  X509_STORE *store = NULL;
#if OPENSSL_VERSION_NUMBER >  0x10002000L
  if (lua_isnoneornil(L, 2))
  {
    store = SSL_CTX_get_cert_store(ctx);
    CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    PUSH_OBJECT(store, "openssl.x509_store");
    return 1;
  }
  else
  {
    store = CHECK_OBJECT(2, X509_STORE, "openssl.x509_store");
    CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    SSL_CTX_set_cert_store(ctx, store);
    X509_STORE_set_trust(store, 1);
    return 0;
  }
#else
  luaL_error(L, "NYI, openssl below 1.0.2 not fully support this feature");
  return 0;
#endif
}

static int openssl_ssl_ctx_new_ssl(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  int server = 0;
  int mode_idx = 2;
  SSL *ssl = SSL_new(ctx);
  int ret = 1;

  if (auxiliar_isclass(L, "openssl.bio", 2))
  {
    BIO *bi = CHECK_OBJECT(2, BIO, "openssl.bio");
    BIO *bo = bi;
    CRYPTO_add(&bi->references, 1, CRYPTO_LOCK_BIO);
    if (auxiliar_isclass(L, "openssl.bio", 3))
    {
      bo = CHECK_OBJECT(3, BIO, "openssl.bio");
      CRYPTO_add(&bo->references, 1, CRYPTO_LOCK_BIO);
      mode_idx = 4;
    }
    else
      mode_idx = 3;

    SSL_set_bio(ssl, bi, bo);
    ret = 1;
  }
  else if (lua_isnumber(L, 2))
  {
    ret = SSL_set_fd(ssl, luaL_checkint(L, 2));
    mode_idx = 3;
  }

  if (ret == 1 && !lua_isnoneornil(L, mode_idx))
  {
    server = auxiliar_checkboolean(L, mode_idx);
  }

  if (ret == 1)
  {
    if (server)
      SSL_set_accept_state(ssl);
    else
      SSL_set_connect_state(ssl);

    PUSH_OBJECT(ssl, "openssl.ssl");
    openssl_newvalue(L, ssl);
  }
  else
  {
    SSL_free(ssl);
    return openssl_pushresult(L, ret);
  }
  return 1;
}

static int openssl_ssl_ctx_new_bio(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  const char* host_addr = luaL_checkstring(L, 2);
  int server = lua_isnoneornil(L, 3) ? 0 : auxiliar_checkboolean(L, 3);
  int autoretry = lua_isnoneornil(L, 4) ? 1 : auxiliar_checkboolean(L, 4);

  SSL *ssl = NULL;
  BIO *bio = server ? BIO_new_ssl(ctx, 0) : BIO_new_ssl_connect(ctx);
  int ret = BIO_get_ssl(bio, &ssl);
  if (ret == 1 && ssl)
  {
    if (autoretry)
      SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    if (server)
    {
      BIO* acpt = BIO_new_accept((char*)host_addr);
      BIO_set_accept_bios(acpt, bio);
      bio = acpt;
    }
    else
    {
      ret = BIO_set_conn_hostname(bio, host_addr);
    }
    if (ret == 1)
    {
      PUSH_OBJECT(bio, "openssl.bio");
      openssl_newvalue(L, bio);

      lua_pushboolean(L, 1);
      openssl_setvalue(L, bio, "free_all");

      return 1;
    }
    else
      return openssl_pushresult(L, ret);
  }
  else
  {
    BIO_free(bio);
    bio = NULL;
    return 0;
  }
}

static int openssl_ssl_getpeerverification(lua_State *L)
{
  long err;
  SSL* ssl = CHECK_OBJECT(1, SSL, "openssl.ssl");

  err = SSL_get_verify_result(ssl);
  lua_pushboolean(L, err == X509_V_OK);
  openssl_getvalue(L, ssl, "verify_cert");
  return 2;
}

static int openssl_ssl_ctx_verify_depth(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  int depth;
  if (!lua_isnoneornil(L, 2))
  {
    depth = luaL_checkint(L, 2);
    SSL_CTX_set_verify_depth(ctx, depth);
  }
  depth = SSL_CTX_get_verify_depth(ctx);
  lua_pushinteger(L, depth);
  return 1;
}

static const int iVerifyMode_Options[] =
{
  SSL_VERIFY_NONE,
  SSL_VERIFY_PEER,
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
  SSL_VERIFY_CLIENT_ONCE,
  0
};

static const char* sVerifyMode_Options[] =
{
  "none",
  "peer",
  "fail", /* fail_if_no_peer_cert */
  "once",
  NULL
};

static int openssl_ssl_ctx_verify_mode(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  if (lua_gettop(L) > 1)
  {
    int mode = luaL_checkint(L, 2);
    luaL_argcheck(L,
                  mode == SSL_VERIFY_NONE ||
                  (mode & ~(SSL_VERIFY_PEER |
                            SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                            SSL_VERIFY_CLIENT_ONCE)) == 0,
                  2,
                  "must be none or peer(combined with fail, once or none");

    luaL_argcheck(L, lua_isnoneornil(L, 3) || lua_isfunction(L, 3), 3, "must be callback function");

    if (lua_isfunction(L, 3))
    {
      lua_pushvalue(L, 3);
      openssl_setvalue(L, ctx, "verify_cb");
      SSL_CTX_set_verify(ctx, mode, openssl_verify_cb);
    }
    else
    {
      lua_pushnil(L);
      openssl_setvalue(L, ctx, "verify_cb");
      SSL_CTX_set_verify(ctx, mode, openssl_verify_cb);
    }
    return 0;
  }
  else
  {
    int i = 0;
    int mode = SSL_CTX_get_verify_mode(ctx);
    lua_pushinteger(L, mode);
    i += 1;

    if (mode ==  SSL_VERIFY_NONE)
    {
      lua_pushstring(L, "none");
      i += 1;
    }
    else
    {
      if (mode & SSL_VERIFY_PEER)
      {
        lua_pushstring(L, "peer");
        i += 1;

        if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        {
          lua_pushstring(L, "fail");
          i += 1;
        }
        if (mode & SSL_VERIFY_CLIENT_ONCE)
        {
          lua_pushstring(L, "once");
          i += 1;
        }
      }
    }
    return i;
  }
}

#ifndef OPENSSL_NO_ENGINE
static int openssl_ssl_ctx_set_engine(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  ENGINE* eng = CHECK_OBJECT(2, ENGINE,  "openssl.engine");
  int ret = SSL_CTX_set_client_cert_engine(ctx, eng);
  return openssl_pushresult(L, ret);
}
#endif

static int openssl_ssl_ctx_set_cert_verify(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  luaL_argcheck(L,
                lua_isnone(L, 2) || lua_isfunction(L, 2) || lua_istable(L, 2),
                2,
                "need function or table contains flags");
  if (lua_istable(L, 2))
  {
    lua_pushvalue(L, 2);
    openssl_setvalue(L, ctx, "verify_cb_flags");
    SSL_CTX_set_cert_verify_callback(ctx, openssl_cert_verify_cb, L);
  }
  else if (lua_isfunction(L, 2))
  {
    lua_pushvalue(L, 2);
    openssl_setvalue(L, ctx, "cert_verify_cb");
    SSL_CTX_set_cert_verify_callback(ctx, openssl_cert_verify_cb, L);
  }
  else
    SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);
  return 0;
}

static DH *tmp_dh_callback(SSL *ssl, int is_export, int keylength)
{
  BIO *bio;
  DH *dh_tmp = NULL;
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  lua_State *L = SSL_CTX_get_app_data(ctx);
  int ret = 0;
  /* get callback function */
  openssl_getvalue(L, ctx, "tmp_dh_callback");

  /* Invoke the callback */
  lua_pushboolean(L, is_export);
  lua_pushnumber(L, keylength);
  ret = lua_pcall(L, 2, 1, 0);
  if (ret == 0)
  {
    /* Load parameters from returned value */
    if (lua_type(L, -1) != LUA_TSTRING)
    {
      lua_pop(L, 2);  /* Remove values from stack */
      return NULL;
    }
    bio = BIO_new_mem_buf((void*)lua_tostring(L, -1),
                          lua_rawlen(L, -1));
    if (bio)
    {
      dh_tmp = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
  }
  else
  {
    lua_error(L);
  }

  lua_pop(L, 2);    /* Remove values from stack */
  return dh_tmp;
}

static RSA *tmp_rsa_callback(SSL *ssl, int is_export, int keylength)
{
  BIO *bio;
  RSA *rsa_tmp = NULL;
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  lua_State *L = SSL_CTX_get_app_data(ctx);
  int ret = 0;
  /* get callback function */
  openssl_getvalue(L, ctx, "tmp_rsa_callback");

  /* Invoke the callback */
  lua_pushboolean(L, is_export);
  lua_pushnumber(L, keylength);
  ret = lua_pcall(L, 2, 1, 0);
  if (ret == 0)
  {
    /* Load parameters from returned value */
    if (lua_type(L, -1) != LUA_TSTRING)
    {
      lua_pop(L, 2);  /* Remove values from stack */
      return NULL;
    }
    bio = BIO_new_mem_buf((void*)lua_tostring(L, -1), lua_rawlen(L, -1));
    if (bio)
    {
      rsa_tmp = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
  }
  else
  {
    lua_error(L);
  }

  lua_pop(L, 2);    /* Remove values from stack */
  return rsa_tmp;
}


static EC_KEY *tmp_ecdh_callback(SSL *ssl, int is_export, int keylength)
{
  BIO *bio;
  EC_KEY *ec_tmp = NULL;
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  lua_State *L = SSL_CTX_get_app_data(ctx);
  int ret = 0;
  /* get callback function */
  openssl_getvalue(L, ctx, "tmp_ecdh_callback");

  /* Invoke the callback */
  lua_pushboolean(L, is_export);
  lua_pushnumber(L, keylength);
  ret = lua_pcall(L, 2, 1, 0);
  if (ret == 0)
  {
    /* Load parameters from returned value */
    if (lua_type(L, -1) != LUA_TSTRING)
    {
      lua_pop(L, 2);  /* Remove values from stack */
      return NULL;
    }
    bio = BIO_new_mem_buf((void*)lua_tostring(L, -1),
                          lua_rawlen(L, -1));
    if (bio)
    {
      ec_tmp = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
  }
  else
  {
    lua_error(L);
  }

  lua_pop(L, 2);    /* Remove values from stack */
  return ec_tmp;
}

static int openssl_ssl_ctx_set_tmp(lua_State *L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  static const char* which[] =
  {
    "dh",
    "rsa",
    "ecdh",
    NULL
  };

  int nwhich = luaL_checkoption(L, 2, NULL, which);
  int ret = 0;

  if (lua_isfunction(L, 3))
  {
    lua_pushvalue(L, 3);
    ret = 1;
    switch (nwhich)
    {
    case 0:
      openssl_setvalue(L, ctx, "tmp_dh_callback");
      SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_callback);
      break;
    case 1:
      openssl_setvalue(L, ctx, "tmp_rsa_callback");
      SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_callback);
      break;
    case 2:
    {
      luaL_argcheck(L, lua_isstring(L, 4), 4, "must supply curve name");
      openssl_setvalue(L, ctx, "tmp_ecdh_callback");
      SSL_CTX_set_tmp_ecdh_callback(ctx, tmp_ecdh_callback);
      lua_pushvalue(L, 4);
      openssl_setvalue(L, ctx, "curve");
    }
    break;
    }
  }
  else if (lua_isstring(L, 3))
  {
    BIO* bio = load_bio_object(L, 3);
    switch (nwhich)
    {
    case 0:
    {
      DH* dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      if (dh)
        ret = SSL_CTX_set_tmp_dh(ctx, dh);
      else
        luaL_error(L, "generate new tmp dh fail");
    }
    break;
    case 1:
    {
      RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
      if (rsa)
        ret = SSL_CTX_set_tmp_rsa(ctx, rsa);
      else
        luaL_error(L, "generate new tmp rsa fail");
    }
    break;
    case 2:
    {
      int nid = NID_undef;

      EC_KEY* ec = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
      if (ec == NULL)
      {
        nid = OBJ_txt2nid(lua_tostring(L, 3));
        if (nid != NID_undef)
          ec = EC_KEY_new_by_curve_name(nid);
      }
      if (ec)
        ret = SSL_CTX_set_tmp_ecdh(ctx, ec);
      else
        luaL_error(L, "generate new tmp ec_key fail");
    }
    break;
    }
    BIO_free(bio);
  }
  else if (lua_isuserdata(L, 3))
  {
    luaL_argerror(L, 3, "userdata arg NYI");
  }
  else
    luaL_argerror(L, 3, "should be tmp key callback function or pem string or key object");

  return openssl_pushresult(L, ret);
}

static int tlsext_servername_callback(SSL *ssl, int *ad, void *arg)
{
  SSL_CTX *newctx = NULL;
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  lua_State *L = SSL_CTX_get_app_data(ctx);
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  (void) ad;
  (void) arg;
  /* No name, use default context */
  if (!name)
    return SSL_TLSEXT_ERR_NOACK;

  /* Search for the name in the map */
  openssl_getvalue(L, ctx, "tlsext_servername");
  if (lua_istable(L, -1))
  {
    lua_getfield(L, -1, name);
    if (auxiliar_isclass(L, "openssl.ssl_ctx", -1))
    {
      newctx = CHECK_OBJECT(-1, SSL_CTX, "openssl.ssl_ctx");
      SSL_set_SSL_CTX(ssl, newctx);
      lua_pop(L, 2);
      return SSL_TLSEXT_ERR_OK;
    }
  }
  else if (lua_isfunction(L, -1))
  {
  }
  else
  {
  }

  lua_pop(L, 1);
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int openssl_ssl_ctx_set_servername_callback(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  luaL_argcheck(L, lua_istable(L, 2) || lua_isfunction(L, 2), 2, "must be table or function");

  lua_pushvalue(L, 2);
  openssl_setvalue(L, ctx, "tlsext_servername");
  SSL_CTX_set_tlsext_servername_callback(ctx, tlsext_servername_callback);
  return 0;
}

static int openssl_ssl_ctx_flush_sessions(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  long tm = luaL_checkinteger(L, 2);
  SSL_CTX_flush_sessions(ctx, tm);
  return 0;
}

static int openssl_ssl_ctx_sessions(lua_State*L)
{
  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  if (lua_isstring(L, 2))
  {
    size_t s;
    unsigned char* sid_ctx = (unsigned char*)luaL_checklstring(L, 2, &s);
    int ret = SSL_CTX_set_session_id_context(ctx, sid_ctx, s);
    lua_pushboolean(L, ret);
    return 1;
  }
  else
  {
    SSL_SESSION *s = CHECK_OBJECT(2, SSL_SESSION, "openssl.ssl_session");
    int add = 1;
    if (!lua_isnoneornil(L, 3))
      add = auxiliar_checkboolean(L, 3);

    if (add)
      add = SSL_CTX_add_session(ctx, s);
    else
      add = SSL_CTX_remove_session(ctx, s);

    lua_pushboolean(L, add);
    return 1;
  }
}

static int openssl_session_cache_mode(lua_State *L)
{
  static const char* smode[] =
  {
    "off",
    "client",
    "server",
    "both",
    "no_auto_clear",
    NULL
  };
  static const int imode[] =
  {
    SSL_SESS_CACHE_OFF,
    SSL_SESS_CACHE_CLIENT,
    SSL_SESS_CACHE_SERVER,
    SSL_SESS_CACHE_BOTH,
    SSL_SESS_CACHE_NO_AUTO_CLEAR,
    -1
  };

  SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
  int n = lua_gettop(L);
  long mode = 0;
  int i;
  if (n > 1)
  {
    if (lua_isnumber(L, 2))
    {
      mode = luaL_checkinteger(L, 2);
      mode = SSL_CTX_set_session_cache_mode(ctx, mode);
    }
    else
    {
      for (i = 2; i <= n; i++)
      {
        int j = auxiliar_checkoption(L, i, NULL, smode, imode);
        mode |= j;
      }
      mode = SSL_CTX_set_session_cache_mode(ctx, mode);
    }
  }
  else
  {
    mode = SSL_CTX_get_session_cache_mode(ctx);
  };
  lua_newtable(L);
  i = 0;
  if (mode & SSL_SESS_CACHE_NO_AUTO_CLEAR)
  {
    lua_pushstring(L, smode[4]);
    lua_rawseti(L, -2, i++);
  }
  if (mode & SSL_SESS_CACHE_BOTH)
  {
    lua_pushstring(L, smode[3]);
    lua_rawseti(L, -2, i++);
  }
  else if (mode & SSL_SESS_CACHE_SERVER)
  {
    lua_pushstring(L, smode[2]);
    lua_rawseti(L, -2, i++);
  }
  else if (mode & SSL_SESS_CACHE_CLIENT)
  {
    lua_pushstring(L, smode[1]);
    lua_rawseti(L, -2, i++);
  }
  else if (mode & SSL_SESS_CACHE_OFF)
  {
    lua_pushstring(L, smode[0]);
    lua_rawseti(L, -2, i++);
  }
  return 1;
}

#ifdef SSL_CTX_EXT_DEFINE
SSL_CTX_EXT_DEFINE
#endif

static luaL_Reg ssl_ctx_funcs[] =
{
  {"ssl",             openssl_ssl_ctx_new_ssl},
  {"bio",             openssl_ssl_ctx_new_bio},
#ifndef SSL_CTX_USE_EXT
  {"use",             openssl_ssl_ctx_use},
#else
  SSL_CTX_USE_EXT
#endif
  {"add",             openssl_ssl_ctx_add},
  {"mode",            openssl_ssl_ctx_mode},
  {"timeout",         openssl_ssl_ctx_timeout},
  {"options",         openssl_ssl_ctx_options},
  {"quiet_shutdown",  openssl_ssl_ctx_quiet_shutdown},
  {"verify_locations", openssl_ssl_ctx_load_verify_locations},
  {"cert_store",      openssl_ssl_ctx_cert_store},
#ifndef OPENSSL_NO_ENGINE
  {"set_engine",      openssl_ssl_ctx_set_engine},
#endif
  {"verify_mode",     openssl_ssl_ctx_verify_mode },
  {"set_cert_verify", openssl_ssl_ctx_set_cert_verify},

  {"verify_depth",    openssl_ssl_ctx_verify_depth},
  {"set_tmp",         openssl_ssl_ctx_set_tmp},
  {"flush_sessions",  openssl_ssl_ctx_flush_sessions},
  {"session",         openssl_ssl_ctx_sessions},
  {"session_cache_mode",        openssl_session_cache_mode },
  {"set_servername_callback",   openssl_ssl_ctx_set_servername_callback },

  {"__gc",            openssl_ssl_ctx_gc},
  {"__tostring",      auxiliar_tostring},

  {NULL,      NULL},
};

/****************************SSL SESSION********************************/
/*
ECLARE_LHASH_OF(SSL_SESSION);
LHASH_OF(SSL_SESSION) *sessions;
int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
HASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx);
oid SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
nt (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl, SSL_SESSION *sess);
oid SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
oid (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
oid SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy));
SL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl, unsigned char *Data, int len, int *copy);

 These are the ones being used, the ones in SSL_SESSION are
  SSL_SESSION *session;
*/


static int openssl_ssl_session_new(lua_State*L)
{
  SSL_SESSION *ss = SSL_SESSION_new();
  PUSH_OBJECT(ss, "openssl.ssl_session");
  return 1;
}

static int openssl_ssl_session_read(lua_State*L)
{
  BIO *in = load_bio_object(L, 1);
  SSL_SESSION* ss = PEM_read_bio_SSL_SESSION(in, NULL, NULL, NULL);
  if (!ss)
  {
    BIO_reset(in);
    ss = d2i_SSL_SESSION_bio(in, NULL);
  }
  BIO_free(in);
  if (ss)
  {
    PUSH_OBJECT(ss, "openssl.ssl_session");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int openssl_ssl_session_time(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  int time;
  if (!lua_isnoneornil(L, 2))
  {
    time = lua_tointeger(L, 2);
    time = SSL_SESSION_set_time(session, time);
    lua_pushinteger(L, time);
    return 1;
  }
  time = SSL_SESSION_get_time(session);
  lua_pushinteger(L, time);
  return 1;
}


static int openssl_ssl_session_timeout(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  int time;
  if (!lua_isnoneornil(L, 2))
  {
    time = lua_tointeger(L, 2);
    time = SSL_SESSION_set_timeout(session, time);
    lua_pushinteger(L, time);
    return 1;
  }
  time = SSL_SESSION_get_timeout(session);
  lua_pushinteger(L, time);
  return 1;
}

static int openssl_ssl_session_gc(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  SSL_SESSION_free(session);
  return 0;
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_session_peer(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  X509 *x = SSL_SESSION_get0_peer(session);
  PUSH_OBJECT(x, "openssl.x509");
  return 1;
}
#endif
static int openssl_ssl_session_id(lua_State*L)
{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  const
#endif
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");

  if (lua_isnoneornil(L, 2))
  {
    unsigned int len;
    const unsigned char* id = SSL_SESSION_get_id(session, &len);
    lua_pushlstring(L, (const char*)id, len);
    return 1;
  }
  else
  {
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    size_t len;
    const char* id = luaL_checklstring(L, 2, &len);
    int ret = SSL_SESSION_set1_id_context((SSL_SESSION*)session, (const unsigned char*)id, len);
    lua_pushboolean(L, ret);
    return 1;
#else
    return 0;
#endif
  }
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_session_compress_id(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  unsigned int id  = SSL_SESSION_get_compress_id(session);
  lua_pushinteger(L, id);
  return 1;
}
#endif
static int openssl_ssl_session_export(lua_State*L)
{
  SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
  int pem = lua_isnoneornil(L, 2) ? 1 : auxiliar_checkboolean(L, 2);
  BIO* bio = BIO_new(BIO_s_mem());
  BUF_MEM *bio_buf;
  if (pem)
  {
    PEM_write_bio_SSL_SESSION(bio, session);
  }
  else
  {
    i2d_SSL_SESSION_bio(bio, session);
  }

  BIO_get_mem_ptr(bio, &bio_buf);
  lua_pushlstring(L, bio_buf->data, bio_buf->length);
  BIO_free(bio);
  return 1;
}

static luaL_Reg ssl_session_funcs[] =
{
  {"id",        openssl_ssl_session_id},
  {"time",      openssl_ssl_session_time},
  {"timeout",     openssl_ssl_session_timeout},
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  {"compress_id",   openssl_ssl_session_compress_id},
  {"peer",    openssl_ssl_session_peer},
#endif
  {"export",      openssl_ssl_session_export},

  {"__gc",      openssl_ssl_session_gc},
  {"__tostring",    auxiliar_tostring},

  {NULL,      NULL},
};


/***************************SSL**********************************/

/* need more think */
static int openssl_ssl_clear(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  lua_pushboolean(L, SSL_clear(s));
  return 1;
}

static int openssl_ssl_use(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY* pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  int ret;

  ret = SSL_use_PrivateKey(s, pkey);
  if (ret == 1)
  {
    ret = SSL_use_certificate(s, x);
    if (ret == 1)
    {
      ret = SSL_check_private_key(s);
    }
  }
  return openssl_pushresult(L, ret);
}

static int openssl_ssl_peer(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  X509* x = SSL_get_peer_certificate(s);
  STACK_OF(X509) *sk = SSL_get_peer_cert_chain(s);
  PUSH_OBJECT(x, "openssl.x509");
  if (sk)
  {
    openssl_sk_x509_totable(L, sk);
    return 2;
  }
  return 1;
}

static int openssl_ssl_gc(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  openssl_freevalue(L, s);
  SSL_free(s);

  return 0;
}

static int openssl_ssl_want(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int st = SSL_want(s);
  const char* state = NULL;
  if (st == SSL_NOTHING)
    state = "nothing";
  else if (st == SSL_READING)
    state = "reading";
  else if (st == SSL_WRITING)
    state = "writing";
  else if (st == SSL_X509_LOOKUP)
    state = "x509_lookup";

  lua_pushstring(L, state);
  lua_pushinteger(L, st);
  return 2;
}
#ifndef LIBRESSL_VERSION_NUMBER
static int openssl_ssl_current_compression(lua_State *L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  const COMP_METHOD *comp = SSL_get_current_compression(s);
  if (comp)
    lua_pushstring(L, SSL_COMP_get_name(comp));
  else
    lua_pushnil(L);
  return 1;
}
#endif

static int openssl_ssl_current_cipher(lua_State *L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  const SSL_CIPHER* c = SSL_get_current_cipher(s);
  if (c)
  {
    int bits, algbits;
    char err[LUAL_BUFFERSIZE] = {0};;

    lua_newtable(L);

    AUXILIAR_SET(L, -1, "name",     SSL_CIPHER_get_name(c), string);
    AUXILIAR_SET(L, -1, "version",  SSL_CIPHER_get_version(c), string);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
    AUXILIAR_SET(L, -1, "id", SSL_CIPHER_get_id(c), integer);
#endif
    bits = SSL_CIPHER_get_bits(c, &algbits);
    AUXILIAR_SET(L, -1, "bits", bits, integer);
    AUXILIAR_SET(L, -1, "algbits", algbits, integer);

    AUXILIAR_SET(L, -1, "description", SSL_CIPHER_description((SSL_CIPHER*)c, err, sizeof(err)), string);

    return 1;
  }
  return 0;
}

static int openssl_ssl_pending(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  lua_pushinteger(L, SSL_pending(s));
  return 1;
}

/*********************************************/
static int openssl_ssl_pushresult(lua_State* L, SSL*ssl, int ret_code)
{
  int err = SSL_get_error(ssl, ret_code);
  switch (err)
  {
  case SSL_ERROR_NONE:
    lua_pushinteger(L, ret_code);
    return 1;
  case SSL_ERROR_ZERO_RETURN:
    lua_pushboolean(L, 0);
    lua_pushinteger(L, 0);
    return 2;
  case SSL_ERROR_SSL:
    lua_pushnil(L);
    lua_pushstring(L, "ssl");
    return 2;
  case SSL_ERROR_WANT_READ:
    lua_pushboolean(L, 0);
    lua_pushstring(L, "want_read");
    return 2;
  case SSL_ERROR_WANT_WRITE:
    lua_pushboolean(L, 0);
    lua_pushstring(L, "want_write");
    return 2;
  case SSL_ERROR_WANT_X509_LOOKUP:
    lua_pushboolean(L, 0);
    lua_pushstring(L, "want_x509_lookup");
    return 2;
  case SSL_ERROR_SYSCALL:
    lua_pushnil(L);
    lua_pushstring(L, "syscall");
    return 2;
  case SSL_ERROR_WANT_CONNECT:
    lua_pushboolean(L, 0);
    lua_pushstring(L, "want_connect");
    return 2;
  case SSL_ERROR_WANT_ACCEPT:
    lua_pushboolean(L, 0);
    lua_pushstring(L, "want_accept");
    return 2;
  default:
    lua_pushnil(L);
    return 1;
  }
}

static int openssl_ssl_getfd(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  lua_pushinteger(L, SSL_get_fd(s));
  return 1;
}

static int openssl_ssl_get(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int i;
  int top = lua_gettop(L);
  for (i = 2; i <= top; i++)
  {
    const char* what = luaL_checklstring(L, i, NULL);
    if (strcmp(what, "fd") == 0)
    {
      lua_pushinteger(L, SSL_get_fd(s));
    }
    else if (strcmp(what, "rfd") == 0)
    {
      lua_pushinteger(L, SSL_get_rfd(s));
    }
    else if (strcmp(what, "wfd") == 0)
    {
      lua_pushinteger(L, SSL_get_wfd(s));
    }
    else if (strcmp(what, "client_CA_list") == 0)
    {
      STACK_OF(X509_NAME)* sn = SSL_get_client_CA_list(s);
      openssl_sk_x509_name_totable(L, sn);
    }
    else if (strcmp(what, "read_ahead") == 0)
    {
      lua_pushboolean(L, SSL_get_read_ahead(s));
    }
    else if (strcmp(what, "shared_ciphers") == 0)
    {
      char buf[LUAL_BUFFERSIZE] = {0};
      lua_pushstring(L, SSL_get_shared_ciphers(s, buf, sizeof(buf)));
    }
    else if (strcmp(what, "cipher_list") == 0)
    {
      //TODO FIX
      lua_pushstring(L, SSL_get_cipher_list(s, 0));
    }
    else if (strcmp(what, "verify_mode") == 0)
    {
      //FIX
      lua_pushinteger(L, SSL_get_verify_mode(s));
    }
    else if (strcmp(what, "verify_depth") == 0)
    {
      lua_pushinteger(L, SSL_get_verify_depth(s));
    }
    else if (strcmp(what, "state_string") == 0)
    {
      lua_pushstring(L, SSL_state_string(s));
    }
    else if (strcmp(what, "state_string_long") == 0)
    {
      lua_pushstring(L, SSL_state_string_long(s));
    }
    else if (strcmp(what, "rstate_string") == 0)
    {
      lua_pushstring(L, SSL_rstate_string(s));
    }
    else if (strcmp(what, "rstate_string_long") == 0)
    {
      lua_pushstring(L, SSL_rstate_string_long(s));
    }
    else if (strcmp(what, "version") == 0)
    {
      lua_pushstring(L, SSL_get_version(s));
    }
    else if (strcmp(what, "iversion") == 0)
    {
      lua_pushinteger(L, SSL_version(s));
    }
    else if (strcmp(what, "default_timeout") == 0)
    {
      lua_pushinteger(L, SSL_get_default_timeout(s));
    }
    else if (strcmp(what, "certificate") == 0)
    {
      X509* cert = SSL_get_certificate(s);
      PUSH_OBJECT(cert, "openssl.x509");
    }
    else if (strcmp(what, "verify_result") == 0)
    {
      long l = SSL_get_verify_result(s);
      lua_pushinteger(L, l);
    }
    else if (strcmp(what, "version") == 0)
    {
      lua_pushstring(L, SSL_get_version(s));
    }
    else if (strcmp(what, "state") == 0)
    {
      lua_pushinteger(L, SSL_state(s));
    }
    else if (strcmp(what, "hostname") == 0)
    {
      lua_pushstring(L, SSL_get_servername(s, TLSEXT_NAMETYPE_host_name));
    }
    else
      luaL_argerror(L, i, "can't understant");
  }
  return top - 1;
}

static int openssl_ssl_set(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int i;
  int top = lua_gettop(L);
  int ret = 1;
  for (i = 2; i <= top; i += 2)
  {
    const char* what = luaL_checklstring(L, i, NULL);
    if (strcmp(what, "fd") == 0)
    {
      ret = SSL_set_fd(s, luaL_checkint(L, i + 1));
    }
    else if (strcmp(what, "rfd") == 0)
    {
      ret = SSL_set_wfd(s, luaL_checkint(L, i + 1));
    }
    else if (strcmp(what, "wfd") == 0)
    {
      ret = SSL_set_wfd(s, luaL_checkint(L, i + 1));
    }
    else if (strcmp(what, "client_CA") == 0)
    {
      X509* x = CHECK_OBJECT(i + 1, X509, "openssl.x509");
      ret = SSL_add_client_CA(s, x);
    }
    else if (strcmp(what, "read_ahead") == 0)
    {
      int yes = auxiliar_checkboolean(L, i + 1);
      SSL_set_read_ahead(s, yes);
    }
    else if (strcmp(what, "cipher_list") == 0)
    {
      const char* list = lua_tostring(L, i + 1);
      ret = SSL_set_cipher_list(s, list);
    }
    else if (strcmp(what, "verify_depth") == 0)
    {
      int depth = luaL_checkint(L, i + 1);
      SSL_set_verify_depth(s, depth);
    }
    else if (strcmp(what, "purpose") == 0)
    {
      //FIX
      int purpose = luaL_checkint(L, i + 1);
      ret = SSL_set_purpose(s, purpose);
    }
    else if (strcmp(what, "trust") == 0)
    {
      //FIX
      int trust = luaL_checkint(L, i + 1);
      ret = SSL_set_trust(s, trust);
    }
    else if (strcmp(what, "verify_result") == 0)
    {
      int result = luaL_checkint(L, i + 1);
      SSL_set_verify_result(s, result);
    }
    else if (strcmp(what, "hostname") == 0)
    {
      const char* hostname = luaL_checkstring(L, i + 1);
      SSL_set_tlsext_host_name(s, hostname);
    }

#if OPENSSL_VERSION_NUMBER > 0x10000000L
    else if (strcmp(what, "state") == 0)
    {
      int l = luaL_checkint(L, 2);
      SSL_set_state(s, l);
    }
#endif
    else
      luaL_argerror(L, i, "don't understand");

    if (ret != 1)
      return openssl_pushresult(L, ret);
  }
  return 0;
}

static int openssl_ssl_accept(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_accept(s);
  return openssl_ssl_pushresult(L, s, ret);
}

static int openssl_ssl_connect(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_connect(s);
  return openssl_ssl_pushresult(L, s, ret);
}

static int openssl_ssl_read(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int num = luaL_optint(L, 2, SSL_pending(s));
  void* buf;
  int ret;
  num = num ? num : 4096;
  buf = malloc(num);
  ret = SSL_read(s, buf, num);
  if (ret > 0)
  {
    lua_pushlstring(L, buf, ret);
    ret =  1;
  }
  else
  {
    ret = openssl_ssl_pushresult(L, s, ret);
  }
  free(buf);
  return ret;
}

static int openssl_ssl_peek(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int num = luaL_optint(L, 2, SSL_pending(s));
  void* buf;
  int ret;

  num = num ? num : 4096;
  buf = malloc(num);
  ret = SSL_peek(s, buf, num);
  if (ret > 0)
  {
    lua_pushlstring(L, buf, ret);
    ret = 1;
  }
  else
  {
    ret = openssl_ssl_pushresult(L, s, ret);
  }
  free(buf);
  return ret;
}

static int openssl_ssl_write(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  size_t size;
  const char* buf = luaL_checklstring(L, 2, &size);
  int ret = SSL_write(s, buf, size);
  if (ret > 0)
  {
    lua_pushinteger(L, ret);
    return 1;
  }
  else
  {
    return openssl_ssl_pushresult(L, s, ret);
  }
}

static int openssl_ssl_do_handshake(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_do_handshake(s);
  return openssl_ssl_pushresult(L, s, ret);
}

static int openssl_ssl_renegotiate(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_renegotiate(s);
  return openssl_ssl_pushresult(L, s, ret);
}

#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_renegotiate_abbreviated(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_renegotiate_abbreviated(s);
  return openssl_ssl_pushresult(L, s, ret);
}
#endif
static int openssl_ssl_renegotiate_pending(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_renegotiate_pending(s);
  return openssl_ssl_pushresult(L, s, ret);
}

static int openssl_ssl_shutdown(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = 0;
  if (lua_isnoneornil(L, 2))
  {
    ret = SSL_shutdown(s);
    return openssl_ssl_pushresult(L, s, ret);
  }
  else if (lua_isstring(L, 2))
  {
    const static char* sMode[]  = {"read", "write", "quiet", "noquiet", NULL};
    int mode = luaL_checkoption(L, 2, NULL, sMode);
    if (mode == 0)
      SSL_set_shutdown(s, SSL_RECEIVED_SHUTDOWN);
    else if (mode == 1)
      SSL_set_shutdown(s, SSL_SENT_SHUTDOWN);
    else if (mode == 2)
      SSL_set_quiet_shutdown(s, 1);
    else if (mode == 3)
      SSL_set_quiet_shutdown(s, 0);
  }
  else if (lua_isboolean(L, 2))
  {
    int quiet = lua_toboolean(L, 2);
    if (quiet)
      lua_pushboolean(L, SSL_get_quiet_shutdown(s));
    else
    {
      int shut = SSL_get_shutdown(s);
      if (shut == SSL_RECEIVED_SHUTDOWN)
        lua_pushstring(L, "read");
      else if (shut == SSL_SENT_SHUTDOWN)
        lua_pushstring(L, "write");
      else if (shut == 0)
        lua_pushnil(L);
      else
        luaL_error(L, "Can't understand SSL_get_shutdown result");
    }
    return 1;
  }
  else
    luaL_argerror(L, 2, "should be boolean or string[read|write|quiet|noquite]");

  return 0;
};

static int openssl_ssl_set_connect_state(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  SSL_set_connect_state(s);
  return 0;
}

static int openssl_ssl_set_accept_state(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  SSL_set_accept_state(s);
  return 0;
}

static int openssl_ssl_dup(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  SSL* ss = SSL_dup(s);
  PUSH_OBJECT(ss, "openssl.ssl");
  return 1;
}

static int openssl_ssl_session_reused(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_session_reused(s);
  lua_pushboolean(L, ret);
  return 1;
}

#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_cache_hit(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int ret = SSL_cache_hit(s);
  lua_pushboolean(L, ret == 0);
  return 1;
}
static int openssl_ssl_set_debug(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  int debug = luaL_checkint(L, 2);
  SSL_set_debug(s, debug);
  return 0;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090819fL
static int openssl_ssl_ctx(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  if (lua_isnoneornil(L, 2))
  {
    SSL_CTX *ctx = SSL_get_SSL_CTX(s);
    openssl_refrence(L, ctx, +1);
    PUSH_OBJECT(ctx, "openssl.ssl_ctx");
  }
  else
  {
    SSL_CTX *ctx = CHECK_OBJECT(2, SSL_CTX, "openssl.ssl_ctx");
    ctx = SSL_set_SSL_CTX(s, ctx);
    PUSH_OBJECT(ctx, "openssl.ssl_ctx");
  }
  return 1;
}
#endif


static int openssl_ssl_session(lua_State*L)
{
  SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
  SSL_SESSION*ss;

  if (lua_isnoneornil(L, 2))
  {
    ss = SSL_get1_session(s);
    PUSH_OBJECT(ss, "openssl.ssl_session");
  }
  else
  {
    if (lua_isstring(L, 3))
    {
      size_t sz;
      const char* sid_ctx = luaL_checklstring(L, 2, &sz);
      int ret = SSL_set_session_id_context(s, (unsigned char*)sid_ctx, sz);
      lua_pushboolean(L, ret);
    }
    else
    {
      ss = CHECK_OBJECT(2, SSL_SESSION, "openssl.ssl_session");
      if (lua_isnoneornil(L, 3))
      {
        int ret = SSL_set_session(s, ss);
        lua_pushboolean(L, ret);
      }
      else
      {
#ifdef SSL_add_session
        int add = auxiliar_checkboolean(L, 3);
        if (add)
          add = SSL_add_session(s, ss);
        else
          add = SSL_remove_session(s, ss);
        lua_pushboolean(L, add);
#endif
      }
    }
  }
  return 1;
}

static luaL_Reg ssl_funcs[] =
{
  {"set",       openssl_ssl_set},
  {"get",       openssl_ssl_get},
  {"use",       openssl_ssl_use},
  {"peer",      openssl_ssl_peer},
  {"getfd",     openssl_ssl_getfd},

  {"current_cipher",        openssl_ssl_current_cipher},
#ifndef LIBRESSL_VERSION_NUMBER
  {"current_compression",   openssl_ssl_current_compression},
#endif
  {"getpeerverification",   openssl_ssl_getpeerverification},

  {"session",    openssl_ssl_session},

  {"dup",       openssl_ssl_dup},
#if OPENSSL_VERSION_NUMBER >= 0x0090819fL
  {"ctx",       openssl_ssl_ctx},
#endif
  {"clear",     openssl_ssl_clear},
  {"want",      openssl_ssl_want},
  {"pending",   openssl_ssl_pending},
  {"accept",    openssl_ssl_accept},
  {"connect",   openssl_ssl_connect},
  {"read",      openssl_ssl_read},
  {"peek",      openssl_ssl_peek},
  {"write",     openssl_ssl_write},

  {"renegotiate",   openssl_ssl_renegotiate},
  {"handshake",     openssl_ssl_do_handshake},
  {"shutdown",      openssl_ssl_shutdown},

  {"session_reused", openssl_ssl_session_reused},
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  {"set_debug",   openssl_ssl_set_debug},
  {"cache_hit",   openssl_ssl_cache_hit},
  {"renegotiate_abbreviated", openssl_ssl_renegotiate_abbreviated},
#endif
  {"renegotiate_pending",   openssl_ssl_renegotiate_pending},
  {"set_connect_state",     openssl_ssl_set_connect_state},
  {"set_accept_state",      openssl_ssl_set_accept_state},

  {"__gc",          openssl_ssl_gc},
  {"__tostring",    auxiliar_tostring},

  {NULL,      NULL},
};

static luaL_Reg R[] =
{
  {"ctx_new",       openssl_ssl_ctx_new },
  {"alert_string",  openssl_ssl_alert_string },

  {"session_new",   openssl_ssl_session_new},
  {"session_read",  openssl_ssl_session_read},
  {NULL,    NULL}
};

int luaopen_ssl(lua_State *L)
{
  int i;

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  auxiliar_newclass(L, "openssl.ssl_ctx",       ssl_ctx_funcs);
  auxiliar_newclass(L, "openssl.ssl_session",   ssl_session_funcs);
  auxiliar_newclass(L, "openssl.ssl",           ssl_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  for (i = 0; i < sizeof(ssl_options) / sizeof(LuaL_Enum) - 1; i++)
  {
    LuaL_Enum e = ssl_options[i];
    lua_pushinteger(L, e.val);
    lua_setfield(L, -2, e.name);
  }
  for (i = 0; sVerifyMode_Options[i]; i++)
  {
    lua_pushinteger(L, iVerifyMode_Options[i]);
    lua_setfield(L, -2, sVerifyMode_Options[i]);
  }

  return 1;
}
