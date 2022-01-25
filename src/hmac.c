/***
hamc module for lua-openssl binding

@module hmac
@author  george zhao <zhaozg(at)gmail.com>
@usage
  hamc = require('openssl').hmac
*/
#include "openssl.h"
#include "private.h"

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
static int openssl_mac(lua_State *L)
{
  const char* algorithm = luaL_checkstring(L, 2);
  const char* properties = luaL_optstring(L, 3, NULL);

  EVP_MAC *mac = EVP_MAC_fetch(NULL, algorithm, properties);
  if (mac)
  {
    PUSH_OBJECT(mac, "openssl.mac");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int openssl_mac_gc(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  EVP_MAC_free(mac);
  return 0;
}

static int openssl_mac_is_a(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  const char* name = luaL_checkstring(L, 2);
  int ret = EVP_MAC_is_a(mac, name);
  return openssl_pushresult(L, ret);
}

static void openssl_mac_names_do(const char *name, void *data)
{
  lua_State *L = data;
  int len = lua_rawlen(L, -1);
  lua_pushstring(L, name);
  lua_rawseti(L, -2, len+1);
}

static int openssl_mac_names(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");

  lua_newtable(L);
  EVP_MAC_names_do_all(mac, openssl_mac_names_do, L);
  return 1;
}

static int openssl_mac_provider(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  const OSSL_PROVIDER *provider = EVP_MAC_get0_provider(mac);
  const char *name = OSSL_PROVIDER_get0_name(provider);
  lua_pushstring(L, name);
  return 1;
}

static int openssl_mac_get_params(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  (void)mac;
  /* TODO:
  int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[])
  */
  lua_pushnil(L);
  lua_pushstring(L, "NYI");
  return 2;
}

static int openssl_mac_ctx_gc(lua_State *L)
{
  EVP_MAC_CTX* ctx = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  EVP_MAC_CTX_free(ctx);
  return 0;
}

static int openssl_mac_ctx_dup(lua_State *L)
{
  EVP_MAC_CTX* ctx = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  EVP_MAC_CTX* clone = EVP_MAC_CTX_dup(ctx);
  PUSH_OBJECT(clone, "openssl.mac_ctx");
  return 1;
}

static int openssl_mac_ctx_mac(lua_State *L)
{
  EVP_MAC_CTX* ctx = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  EVP_MAC* mac = EVP_MAC_CTX_get0_mac(ctx);
  PUSH_OBJECT(mac, "openssl.mac");
  return 1;
}

static int openssl_mac_ctx_params(lua_State *L)
{
  EVP_MAC_CTX* ctx = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  (void)ctx;
  /*
  int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);
  int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);
  */
  lua_pushnil(L);
  lua_pushstring(L, "NYI");
  return 1;
}

static void openssl_mac_entry(EVP_MAC *mac, void *arg)
{
  lua_State *L = arg;
  int i = lua_rawlen(L, -1);

  PUSH_OBJECT(mac, "openssl.mac");
  lua_rawseti(L, -2, i+1);
}

static int openssl_mac_all(lua_State *L)
{
  OSSL_LIB_CTX *ctx = CHECK_OBJECT(1, OSSL_LIB_CTX, "openssl.ctx");
  lua_newtable(L);

  EVP_MAC_do_all_provided(ctx, openssl_mac_entry, L);
  return 1;
}

const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);

#endif

/***
get hamc_ctx object

@function new
@tparam string|integer|asn1_object alg name, nid or object identity
@tparam string key secret key
@tparam[opt] engine engine, nothing with default engine
@treturn hamc_ctx hmac object mapping HMAC_CTX in openssl

@see hmac_ctx
*/
static int openssl_hmac_ctx_new(lua_State *L)
{
  int ret;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  OSSL_PARAM params[2];
  size_t params_n = 0;
  size_t l;

  const EVP_MD *type = get_digest(L, 1, NULL);
  const char *k = luaL_checklstring(L, 2, &l);
  ENGINE* e = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "hmac", NULL);
  EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
  (void)e;

  params[params_n++] =
    OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_name(type), 0);
  params[params_n] = OSSL_PARAM_construct_end();

  ret = EVP_MAC_init(c, k, l, params);
  if (ret==1)
    PUSH_OBJECT(c, "openssl.mac_ctx");
  else
    ret = openssl_pushresult(L, ret);
  EVP_MAC_free(mac);
#else
  const EVP_MD *type = get_digest(L, 1, NULL);
  size_t l;
  const char *k = luaL_checklstring(L, 2, &l);
  ENGINE* e = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, ENGINE, "openssl.engine");

  HMAC_CTX *c = HMAC_CTX_new();
  ret = HMAC_Init_ex(c, k, (int)l, type, e);
  if (ret==1)
    PUSH_OBJECT(c, "openssl.hmac_ctx");
  else
    ret = openssl_pushresult(L, ret);
#endif
  return ret;
}

static int openssl_mac_ctx_free(lua_State *L)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  EVP_MAC_CTX *c = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  if(!c) return 0;
  EVP_MAC_CTX_free(c);
#else
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  if(!c) return 0;
  HMAC_CTX_free(c);
#endif

  FREE_OBJECT(1);
  return 0;
}

/***
compute hmac one step, in module openssl.hamc

@function hmac
@tparam evp_digest|string|nid digest digest alg identity
@tparam string message
@tparam string key
@treturn string result binary string
*/
/***
alias for hmac

@function digest
@tparam evp_digest|string|nid digest digest alg identity
@tparam string message
@tparam string key
@treturn string result binary string
*/
static int openssl_hmac(lua_State *L)
{
  int ret = 0;
  const EVP_MD *type = get_digest(L, 1, NULL);
  size_t len;
  const char *dat = luaL_checklstring(L, 2, &len);
  size_t l;
  const char *k = luaL_checklstring(L, 3, &l);
  int raw = (lua_isnone(L, 4)) ? 0 : lua_toboolean(L, 4);
  ENGINE* e = lua_isnoneornil(L, 5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
  (void)e;

  unsigned char digest[EVP_MAX_MD_SIZE];

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  size_t dlen = EVP_MAX_MD_SIZE;
  EVP_MAC *mac;
  EVP_MAC_CTX *ctx = NULL;

  OSSL_PARAM params[2];
  size_t params_n = 0;

  mac = EVP_MAC_fetch(NULL, "hmac", NULL);
  if (mac)
  {
    params[params_n++] =
      OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_name(type), 0);
    params[params_n] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx)
    {
      ret = EVP_MAC_init(ctx, k, l, params);
      if (ret==1)
      {
        ret = EVP_MAC_update(ctx, (const unsigned char *)dat, len);
        if (ret==1)
          ret = EVP_MAC_final(ctx, digest, &dlen, dlen);
      }
      EVP_MAC_CTX_free(ctx);
    }
    EVP_MAC_free(mac);
  }
#else
  unsigned int dlen = EVP_MAX_MD_SIZE;
  ret = HMAC(type, k, l, (const unsigned char*)dat, (int)len, digest, &dlen)!=NULL;
#endif
  if (ret==0)
    return openssl_pushresult(L, ret);

  if (raw)
    lua_pushlstring(L, (char *)digest, dlen);
  else
  {
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    to_hex((const char*)digest, dlen, hex);
    lua_pushstring(L, hex);
  }

  return 1;
}

/***
openssl.hmac_ctx object
@type hmac_ctx
*/

/***
feed data to do digest

@function update
@tparam string msg data
*/
static int openssl_mac_ctx_update(lua_State *L)
{
  int ret;
  size_t l;
  const char *s;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  EVP_MAC_CTX *c = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  s = luaL_checklstring(L, 2, &l);

  ret = EVP_MAC_update(c, (unsigned char *)s, l);
#else
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  s = luaL_checklstring(L, 2, &l);

  ret = HMAC_Update(c, (unsigned char *)s, l);
#endif
  return openssl_pushresult(L, ret);
}

/***
get result of hmac

@function final
@tparam[opt] string last last part of data
@tparam[opt] boolean raw binary or hex encoded result, default true for binary result
@treturn string val hash result
*/
static int openssl_mac_ctx_final(lua_State *L)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  EVP_MAC_CTX *c = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
#else
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
#endif
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t len = sizeof(digest);
  int raw = 0;
  int ret = 1;

  if (lua_isstring(L, 2))
  {
    size_t l;
    const char *s = luaL_checklstring(L, 2, &l);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    ret = EVP_MAC_update(c, (unsigned char *)s, l);
#else
    ret = HMAC_Update(c, (unsigned char *)s, l);
#endif
    raw = (lua_isnone(L, 3)) ? 0 : lua_toboolean(L, 3);
  }
  else
    raw = (lua_isnone(L, 2)) ? 0 : lua_toboolean(L, 2);

  if (ret==1)
  {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    ret = EVP_MAC_final(c, digest, &len, len);
#else
    ret = HMAC_Final(c, digest, (unsigned int*)&len);
#endif
  }

  if (ret==0)
    return openssl_pushresult(L, ret);

  if (raw)
  {
    lua_pushlstring(L, (char *)digest, len);
  }
  else
  {
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    to_hex((const char*) digest, len, hex);
    lua_pushstring(L, hex);
  }
  return 1;
}

/***
return size of mac value

@function size
@tparam string msg data
*/
static int openssl_mac_ctx_size(lua_State *L)
{
  size_t sz;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  EVP_MAC_CTX *c = CHECK_OBJECT(1, EVP_MAC_CTX, "openssl.mac_ctx");
  sz = EVP_MAC_CTX_get_mac_size(c);
#else
  HMAC_CTX *c = CHECK_OBJECT(1, HMAC_CTX, "openssl.hmac_ctx");
  sz = HMAC_size(c);
#endif
  lua_pushinteger(L, sz);
  return 1;
}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
static luaL_Reg mac_funs[] =
{
  {"is_a",        openssl_mac_is_a},
  {"names",       openssl_mac_names},
  {"provider",    openssl_mac_provider},
  {"get_params",  openssl_mac_get_params},

  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_mac_gc},
  {NULL, NULL}
};
#endif


static luaL_Reg mac_ctx_funs[] =
{
  {"update",      openssl_mac_ctx_update},
  {"final",       openssl_mac_ctx_final},
  {"close",       openssl_mac_ctx_free},
  {"size",        openssl_mac_ctx_size},

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  {"dup",         openssl_mac_ctx_dup},
  {"mac",         openssl_mac_ctx_mac},
  {"params",      openssl_mac_ctx_params},
#endif

  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_mac_ctx_free},
  {NULL, NULL}
};

static const luaL_Reg mac_R[] =
{
  { "new",      openssl_hmac_ctx_new},
  { "hmac",     openssl_hmac},
  { "digest",   openssl_hmac},

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  { "mac",      openssl_mac},
#endif
  {NULL,  NULL}
};

int luaopen_hmac(lua_State *L)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  auxiliar_newclass(L, "openssl.mac", mac_funs);
  auxiliar_newclass(L, "openssl.mac_ctx", mac_ctx_funs);
#else
  auxiliar_newclass(L, "openssl.hmac_ctx", mac_ctx_funs);
#endif

  lua_newtable(L);
  luaL_setfuncs(L, mac_R, 0);

  return 1;
}
