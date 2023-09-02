/***
 *
kdf module perform EVP_KDF operations.
It base on EVP_KDF in OpenSSL v3.

@module kdf
@author  george zhao <zhaozg(at)gmail.com>
@usage
  hamc = require('openssl').kdf
*/
#include "lua.h"
#include "openssl.h"
#include "private.h"
#include "auxiliar.h"

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/kdf.h>
#include <openssl/core_names.h>
/***
get kdf_ctx object

@function new
@tparam string|integer|asn1_object alg name, nid or object identity
@tparam string key secret key
@tparam[opt] engine engine, nothing with default engine
@treturn kdf_ctx object mapping EVP_KDF_CTX in openssl

@see hmac_ctx
*/

static EVP_KDF* get_kdf(lua_State* L, int idx)
{
  EVP_KDF* kdf = NULL;
  switch (lua_type(L, idx))
  {
  case LUA_TSTRING:
    kdf = EVP_KDF_fetch(NULL, lua_tostring(L, idx), NULL);
    break;
#if 0
  case LUA_TNUMBER:
    kdf = EVP_KDF_fetch(NULL, lua_tostring(L, idx), NULL);
    break;
#endif
  case LUA_TUSERDATA:
#if 0
    if (auxiliar_getclassudata(L, "openssl.asn1_object", idx))
      kdf = EVP_get_digestbyobj(CHECK_OBJECT(idx, ASN1_OBJECT, "openssl.asn1_object"));
    else
#endif
    if (auxiliar_getclassudata(L, "openssl.kdf", idx))
      kdf = CHECK_OBJECT(idx, EVP_KDF, "openssl.kdf");
    break;
  }

  if (kdf==NULL)
  {
    luaL_argerror(L, idx, "must be a string for KDF method name");
  }

  return kdf;
}

/***
traverses all openssl.kdf, and calls fn with each openssl.kdf

@function iterator
@tparam function cb(openssl.kdf)
@treturn boolean
*/
static void kdf_iterator_cb(EVP_KDF *kdf, void *data)
{
  lua_State *L = (lua_State *)data;
  int typ = lua_rawgetp(L, LUA_REGISTRYINDEX, (void*)kdf_iterator_cb);
  assert(typ == LUA_TFUNCTION);

  PUSH_OBJECT(kdf, "openssl.kdf");
  if (lua_pcall(L, 1, 1, 0) != 0)
    luaL_error(L, lua_tostring(L, -1));
}

static int openssl_kdf_iterator_kdf(lua_State *L)
{
  luaL_checktype(L, 1, LUA_TFUNCTION);

  lua_pushvalue(L, 1);
  lua_rawsetp(L, LUA_REGISTRYINDEX, (void*)kdf_iterator_cb);

  EVP_KDF_do_all_provided(NULL, kdf_iterator_cb, L);
  lua_pushnil(L);
  lua_rawsetp(L, LUA_REGISTRYINDEX, (void*)kdf_iterator_cb);
  return 0;
}

static int openssl_kdf_fetch(lua_State *L)
{
  const char* name = luaL_checkstring(L, 1);
  EVP_KDF* kdf = EVP_KDF_fetch(NULL, name, NULL);
  PUSH_OBJECT(kdf, "openssl.kdf");

  return 1;
}


static int openssl_kdf_ctx_new(lua_State *L)
{
  EVP_KDF *type = get_kdf(L, 1);
  EVP_KDF_CTX *c = EVP_KDF_CTX_new(type);
  int ret = 1;
  if (c)
    PUSH_OBJECT(c, "openssl.kdf_ctx");
  else
    ret = openssl_pushresult(L, 0);
  return ret;
}


static int openssl_kdf_ctx_free(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  if(!c) return 0;
  EVP_KDF_CTX_free(c);

  FREE_OBJECT(1);
  return 0;
}

/***
compute KDF delive, in module openssl.kdf

@function deilver
@tparam evp_kdf|string kdf
@tparam table array of paramaters
@treturn string result binary string
*/
static int openssl_kdf_derive(lua_State *L)
{
  EVP_KDF *kdf = get_kdf(L, 1);
  OSSL_PARAM *params = openssl_toparams(L, 2);
  unsigned char key[64] = {0};
  size_t sz = luaL_optinteger(L, 3, 16);
  luaL_argcheck(L, sz <= sizeof(key), 3, "out of support range, limited to 64");

  EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

  int ret = EVP_KDF_derive(ctx, key, sz, params);
  if (ret > 0)
  {
    lua_pushlstring(L, (const char*)key, sz);
    ret = 1;
  } else {
    ret = openssl_pushresult(L, ret);
  }
  EVP_KDF_CTX_free(ctx);
  OPENSSL_free(params);
  return ret;
}

/***
openssl.kdf_ctx object
@type kdf_ctx
*/

/***
duplicate kdf_ctx object

@function dup
@treturn openssl.kdf_ctx
*/
static int openssl_kdf_ctx_dup(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  c = EVP_KDF_CTX_dup(c);
  if (c)
    PUSH_OBJECT(c, "openssl.kdf_ctx");
  else
    lua_pushnil(L);
  return 1;
}

/***
reset kdf_ctx object

@function reset
@treturn openssl.kdf_ctx
*/
static int openssl_kdf_ctx_reset(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  EVP_KDF_CTX_reset(c);
  lua_pushvalue(L, 1);
  return 1;
}

/***
derive the key

@function derive
@treturn string|fail
*/
static int openssl_kdf_ctx_derive(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  OSSL_PARAM* params = openssl_toparams(L, 2);
  unsigned char key[64] = {0};
  size_t sz = luaL_optinteger(L, 3, 16);
  luaL_argcheck(L, sz <= sizeof(key), 3, "out of support range, limited to 64");

  int ret = EVP_KDF_derive(c, key, sz, params);
  if (ret > 0)
  {
    lua_pushlstring(L, (const char*)key, sz);
    ret = 1;
  } else {
    ret = openssl_pushresult(L, ret);
  }
  OPENSSL_free(params);
  return ret;
}

/***
get size of openssl.kdf_ctx

@function size
@treturn number
*/
static int openssl_kdf_ctx_size(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  lua_pushinteger(L, EVP_KDF_CTX_get_kdf_size(c));

  return 1;
}

/***
get openssl.kdf of openssl.kdf_ctx

@function kdf
@treturn openssl.kdf
*/
static int openssl_kdf_ctx_kdf(lua_State *L)
{
  EVP_KDF_CTX *c = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  const EVP_KDF *kdf = EVP_KDF_CTX_kdf(c);
  PUSH_OBJECT(kdf, "openssl.kdf");

  return 1;
}

/***
get array that describes the retrievable and settable parameters.

@function gettable_params
@treturn table
*/
static int openssl_kdf_ctx_gettable_params(lua_State *L)
{
  EVP_KDF_CTX *ctx = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  const OSSL_PARAM *params = EVP_KDF_CTX_gettable_params(ctx);
  return openssl_pushparams(L, params);
}

/***
get array with parameters that can be set to the algorithm.

@function settable_ctx_params
@treturn table
*/
static int openssl_kdf_ctx_settable_params(lua_State *L)
{
  EVP_KDF_CTX *ctx = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  const OSSL_PARAM *params = EVP_KDF_CTX_settable_params(ctx);
  return openssl_pushparams(L, params);
}

/***
retrieves parameters

@function get_params
@tparam table
@treturn table
*/
static int openssl_kdf_ctx_get_params(lua_State *L)
{
  EVP_KDF_CTX *ctx = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  OSSL_PARAM* params = openssl_toparams(L, 2);
  int ret = EVP_KDF_CTX_get_params(ctx, params);
  if (ret==1)
    ret = openssl_pushparams(L, params);
  else
  {
    ret = openssl_pushparams(L, params);
    ret += openssl_pushresult(L, ret);
  }
  OPENSSL_free(params);
  return ret;
}

/***
set parameters

@function set_params
@tparam table
@treturn boolean
*/
static int openssl_kdf_ctx_set_params(lua_State *L)
{
  EVP_KDF_CTX *ctx = CHECK_OBJECT(1, EVP_KDF_CTX, "openssl.kdf_ctx");
  OSSL_PARAM* params = openssl_toparams(L, 2);
  int ret = EVP_KDF_CTX_set_params(ctx, params);
  OPENSSL_free(params);
  return openssl_pushresult(L, ret);
}

/***
openssl.kdf object
@type openssl.kdf
*/

/***
get description

@function description
@treturn openssl.kdf_ctx
*/
static int openssl_kdf_description(lua_State *L)
{
  const EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  lua_pushstring(L, EVP_KDF_get0_description(kdf));
  return 1;
}

/***
get description

@function name
@treturn openssl.kdf_ctx
*/
static int openssl_kdf_name(lua_State *L)
{
  const EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  lua_pushstring(L, EVP_KDF_get0_name(kdf));
  return 1;
}

/***
get provider

@function provider
@treturn openssl.kdf_ctx
*/
static int openssl_kdf_provider(lua_State *L)
{
  const EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  lua_pushlightuserdata(L, (void*)EVP_KDF_get0_provider(kdf));
  return 1;
}

/***
check kdf is an implementation of an algorithm that's identifiable with name

@function is_a
@tparam string name an algorithm that's identifiable with name
@treturn boolean
*/
static int openssl_kdf_is_a(lua_State *L)
{
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  const char* name = luaL_checkstring(L, 2);
  lua_pushboolean(L, EVP_KDF_is_a(kdf, name));
  return 1;
}


/***
traverses all names for kdf, and calls fn with each name

@function iterator
@tparam function cb(name)
@treturn boolean
*/
static void iterator_cb(const char *name, void *data)
{
  lua_State *L = (lua_State *)data;
  int typ = lua_rawgetp(L, LUA_REGISTRYINDEX, (void*)iterator_cb);
  assert(typ == LUA_TFUNCTION);

  lua_pushstring(L, name);
  if (lua_pcall(L, 1, 1, 0) != 0)
    luaL_error(L, lua_tostring(L, -1));
}

static int openssl_kdf_iterator(lua_State *L)
{
  int ret;
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  luaL_checktype(L, 2, LUA_TFUNCTION);

  lua_pushvalue(L, 2);
  lua_rawsetp(L, LUA_REGISTRYINDEX, (void*)iterator_cb);

  ret = EVP_KDF_names_do_all(kdf, iterator_cb, L);
  lua_pushboolean(L, ret);
  lua_pushnil(L);
  lua_rawsetp(L, LUA_REGISTRYINDEX, (void*)iterator_cb);
  return 1;
}

/***
get array that describes the retrievable and settable parameters.

@function gettable_params
@treturn table
*/
static int openssl_kdf_gettable_params(lua_State *L)
{
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  const OSSL_PARAM *params = EVP_KDF_gettable_params(kdf);
  return openssl_pushparams(L, params);
}

/***
get array with parameters that can be retrieved from the algorithm.

@function gettable_ctx_params
@treturn table
*/
static int openssl_kdf_gettable_ctx_params(lua_State *L)
{
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  const OSSL_PARAM *params = EVP_KDF_gettable_ctx_params(kdf);
  return openssl_pushparams(L, params);
}

/***
get array with parameters that can be set to the algorithm.

@function settable_ctx_params
@treturn table
*/
static int openssl_kdf_settable_ctx_params(lua_State *L)
{
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  const OSSL_PARAM *params = EVP_KDF_settable_ctx_params(kdf);
  return openssl_pushparams(L, params);
}

/***
retrieves details about the implementation kdf.

@function settable_ctx_params
@treturn table
*/
static int openssl_kdf_get_params(lua_State *L)
{
  EVP_KDF *kdf = CHECK_OBJECT(1, EVP_KDF, "openssl.kdf");
  OSSL_PARAM* params = openssl_toparams(L, 2);
  int ret = EVP_KDF_get_params(kdf, params);
  if (ret == 1)
    ret = openssl_pushparams(L, params);
  else
  {
    ret = openssl_pushparams(L, params);
    ret += openssl_pushresult(L, ret);
  }
  OPENSSL_free(params);
  return ret;
}

static luaL_Reg kdf_ctx_funs[] =
{
  {"dup",         openssl_kdf_ctx_dup},
  {"reset",       openssl_kdf_ctx_reset},
  {"derive",      openssl_kdf_ctx_derive},
  {"size",        openssl_kdf_ctx_size},
  {"kdf",         openssl_kdf_ctx_kdf},

  {"gettable_params", openssl_kdf_ctx_gettable_params},
  {"settable_params", openssl_kdf_ctx_settable_params},
  {"get_params",      openssl_kdf_ctx_get_params},
  {"set_params",      openssl_kdf_ctx_set_params},

  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_kdf_ctx_free},

  {NULL, NULL}
};

static luaL_Reg kdf_funs[] =
{
  {"description", openssl_kdf_description},
  {"name",        openssl_kdf_name},
  {"provider",    openssl_kdf_provider},
  {"is_a",        openssl_kdf_is_a},
  {"iterator",    openssl_kdf_iterator},
  {"derive",      openssl_kdf_derive},
  {"new",         openssl_kdf_ctx_new},

  {"settable_ctx_params", openssl_kdf_settable_ctx_params},
  {"gettable_ctx_params", openssl_kdf_gettable_ctx_params},
  {"get_params", openssl_kdf_get_params},

  {"__tostring",  auxiliar_tostring},

  {NULL,  NULL}
};

static const luaL_Reg kdf_R[] =
{
  {"fetch",     openssl_kdf_fetch},
  {"iterator",  openssl_kdf_iterator_kdf},
  {"derive",    openssl_kdf_derive},

  {NULL,  NULL}
};

int luaopen_kdf(lua_State *L)
{
  auxiliar_newclass(L, "openssl.kdf", kdf_funs);
  auxiliar_newclass(L, "openssl.kdf_ctx", kdf_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, kdf_R, 0);

  lua_pushliteral(L, "names");
  lua_newtable(L);

  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_HKDF, OSSL_KDF_NAME_HKDF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_TLS1_3_KDF, OSSL_KDF_NAME_TLS1_3_KDF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_PBKDF1, OSSL_KDF_NAME_PBKDF1, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_PBKDF2, OSSL_KDF_NAME_PBKDF2, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_SCRYPT, OSSL_KDF_NAME_SCRYPT, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_SSHKDF, OSSL_KDF_NAME_SSHKDF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_SSKDF, OSSL_KDF_NAME_SSKDF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_TLS1_PRF, OSSL_KDF_NAME_TLS1_PRF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_X942KDF_ASN1, OSSL_KDF_NAME_X942KDF_ASN1, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_X942KDF_CONCAT, OSSL_KDF_NAME_X942KDF_CONCAT, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_X963KDF, OSSL_KDF_NAME_X963KDF, string);
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_KBKDF, OSSL_KDF_NAME_KBKDF, string);
#if defined(OSSL_KDF_NAME_KRB5KDF)
  AUXILIAR_SET(L, -1, OSSL_KDF_NAME_KRB5KDF, OSSL_KDF_NAME_KRB5KDF, string);
#endif

  lua_rawset(L, -3);

  return 1;
}
#endif
