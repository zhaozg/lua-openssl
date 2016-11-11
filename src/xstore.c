/*=========================================================================*\
* xstore.c
* * x509_store routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME "x509.store"

void openssl_xstore_free(X509_STORE* ctx)
{
  /* hack openssl bugs */
#if OPENSSL_VERSION_NUMBER < 0x10002000L
  if (ctx->references > 1)
    CRYPTO_add(&ctx->references, -1, CRYPTO_LOCK_X509_STORE);
  else
    X509_STORE_free(ctx);
#else
  X509_STORE_free(ctx);
#endif
}

static int openssl_xstore_gc(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  openssl_xstore_free(ctx);
  return 0;
}

static int openssl_xstore_add_lookup(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  const char* path = luaL_checkstring(L, 2);
  const static char* sMode[] = {"file", "dir", NULL};
  int mode = luaL_checkoption(L, 3, "file", sMode);
  const static char* sFormat[] = {"pem", "asn1", "default", NULL};
  int iFormat[] = {X509_FILETYPE_PEM, X509_FILETYPE_ASN1, X509_FILETYPE_DEFAULT, -1};
  int fmt = auxiliar_checkoption(L, 4, "default", sFormat, iFormat);
  int ret = 0;
  X509_LOOKUP *lookup = NULL;
  if (mode == 0)
  {
    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
    if (lookup)
    {
      ret = X509_LOOKUP_load_file(lookup, path, fmt);
    }
  }
  else
  {
    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
    if (lookup)
    {
      ret = X509_LOOKUP_add_dir(lookup, path, fmt);
    }
  }

  return openssl_pushresult(L, ret);
}


static int openssl_xstore_depth(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  int depth = luaL_checkint(L, 2);
  int ret = X509_STORE_set_depth(ctx, depth);
  return openssl_pushresult(L, ret);
}

static int openssl_xstore_flags(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  int flags = luaL_checkint(L, 2);
  int ret = X509_STORE_set_flags(ctx, flags);
  return openssl_pushresult(L, ret);
}

static int openssl_xstore_purpose(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  int purpose = luaL_checkint(L, 2);
  int ret = X509_STORE_set_purpose(ctx, purpose);
  return openssl_pushresult(L, ret);
}

static int openssl_xstore_trust(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  int trust = auxiliar_checkboolean(L, 2);
  int ret = X509_STORE_set_trust(ctx, trust);
  return openssl_pushresult(L, ret);
}

static int openssl_xstore_load(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  const char* file = luaL_optstring(L, 2, NULL);
  const char* dir = luaL_optstring(L, 3, NULL);
  int ret;
  if (file || dir)
  {
    ret = X509_STORE_load_locations (ctx, file, dir);
  }
  else
    ret = X509_STORE_set_default_paths(ctx);

  return openssl_pushresult(L, ret);
}

static int openssl_xstore_add(lua_State* L)
{
  X509_STORE* ctx = CHECK_OBJECT(1, X509_STORE, "openssl.x509_store");
  int n = lua_gettop(L);
  int i;
  int ret = 0;
  for (i = 2; i <= n; i++)
  {
    if (lua_istable(L, i))
    {
      int k = lua_rawlen(L, i);
      int j;
      for (j = 1; j <= k; j++)
      {
        lua_rawgeti(L, i, j);
        if (auxiliar_isclass(L, "openssl.x509", i))
        {
          X509* x = CHECK_OBJECT(i, X509, "openssl.x509");
          ret = X509_STORE_add_cert(ctx, x);
        }
        else if (auxiliar_isclass(L, "openssl.x509_crl", i))
        {
          X509_CRL* c = CHECK_OBJECT(i, X509_CRL, "openssl.x509_crl");
          ret = X509_STORE_add_crl(ctx, c);
        }
        else
        {
          luaL_argerror(L, i, "only accept table with x509 or x509_crl object");
        }
      }
    }
    else if (auxiliar_isclass(L, "openssl.x509", i))
    {
      X509* x = CHECK_OBJECT(i, X509, "openssl.x509");
      ret = X509_STORE_add_cert(ctx, x);
    }
    else if (auxiliar_isclass(L, "openssl.x509_crl", i))
    {
      X509_CRL* c = CHECK_OBJECT(i, X509_CRL, "openssl.x509_crl");
      ret = X509_STORE_add_crl(ctx, c);
    }
    else
    {
      luaL_argerror(L, i, "only accept x509 or x509_crl object or table with x509 or x509_crl object");
    }
    if (ret == 0)
      break;
  }

  return openssl_pushresult(L, ret);
}

static luaL_Reg xname_funcs[] =
{
  {"flags",             openssl_xstore_flags},
  {"purpose",           openssl_xstore_purpose},
  {"depth",             openssl_xstore_depth},
  {"trust",             openssl_xstore_trust},

  {"load",              openssl_xstore_load},
  {"add",               openssl_xstore_add},
  {"add_lookup",        openssl_xstore_add_lookup},

  /*
  {"certs",             openssl_xstore_certs},
  {"crls",              openssl_xstore_crls},
  {"param",             openssl_xstore_param},
  {"verify_cb",         openssl_xstore_verify_cb},
  {"verify",            openssl_xstore_verify},
  {"lookup_crls_cb",    openssl_xstore_lookup_crls_cb},
  */

  {"__tostring",        auxiliar_tostring},
  {"__gc",              openssl_xstore_gc},

  {NULL,          NULL},
};

static int openssl_xstore_new(lua_State*L)
{
  X509_STORE* ctx = X509_STORE_new();
  int i, n;
  luaL_checktable(L, 1);
  n = lua_rawlen(L, 1);
  for (i = 0; i < n; i++)
  {
    X509* x;
    lua_rawgeti(L, 1, i + 1);
    luaL_argcheck(L, auxiliar_isclass(L, "openssl.x509", -1), 1, "only contains x509 object");
    x = CHECK_OBJECT(-1, X509, "openssl.x509");
    lua_pop(L, 1);
    X509_STORE_add_cert(ctx, x);
  }
  if (!lua_isnoneornil(L, 2))
  {
    luaL_checktable(L, 2);

    n = lua_rawlen(L, 2);
    for (i = 0; i < n; i++)
    {
      X509_CRL* c;
      lua_rawgeti(L, 2, i + 1);
      c = CHECK_OBJECT(-1, X509_CRL, "openssl.x509_crl");
      lua_pop(L, 1);
      X509_STORE_add_crl(ctx, c);
    }
  };

  PUSH_OBJECT(ctx, "openssl.x509_store");
  return 1;
};

static luaL_Reg R[] =
{
  {"new",           openssl_xstore_new},

  {NULL,          NULL},
};

int openssl_register_xstore(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_store", xname_funcs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  return 1;
}
