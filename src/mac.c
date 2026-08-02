/***
mac module perform Message Authentication Code operations.
It base on EVP_MAC in OpenSSL v3.

@module mac
@author  george zhao <zhaozg(at)gmail.com>
@usage
  mac = require('openssl').mac
*/
#include "openssl.h"
#include "private.h"

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
/***
create new MAC object
@function new
@tparam string algorithm MAC algorithm name (e.g., "HMAC", "CMAC", "GMAC")
@tparam[opt] string properties optional properties string
@treturn mac|nil new MAC object or nil on failure
*/
static int
openssl_mac_new(lua_State *L)
{
  const char *algorithm = luaL_checkstring(L, 2);
  const char *properties = luaL_optstring(L, 3, NULL);

  EVP_MAC *mac = EVP_MAC_fetch(NULL, algorithm, properties);
  if (mac) {
    PUSH_OBJECT(mac, "openssl.mac");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static int
openssl_mac_gc(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  EVP_MAC_free(mac);
  return 0;
}

/***
check if MAC algorithm supports a specific name
@function is_a
@tparam string name algorithm name to check
@treturn boolean true if MAC supports the given name
*/
static int
openssl_mac_is_a(lua_State *L)
{
  EVP_MAC    *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  const char *name = luaL_checkstring(L, 2);
  int         ret = EVP_MAC_is_a(mac, name);
  return openssl_pushresult(L, ret);
}

static void
openssl_mac_names_do(const char *name, void *data)
{
  lua_State *L = data;
  int        len = lua_rawlen(L, -1);
  lua_pushstring(L, name);
  lua_rawseti(L, -2, len + 1);
}

/***
get all names supported by this MAC algorithm
@function names
@treturn table array of supported algorithm names
*/
static int
openssl_mac_names(lua_State *L)
{
  EVP_MAC *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");

  lua_newtable(L);
  EVP_MAC_names_do_all(mac, openssl_mac_names_do, L);
  return 1;
}

/***
get provider name for this MAC algorithm
@function provider
@treturn string name of the provider implementing this MAC
*/
static int
openssl_mac_provider(lua_State *L)
{
  EVP_MAC             *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  const OSSL_PROVIDER *provider = EVP_MAC_get0_provider(mac);
  const char          *name = OSSL_PROVIDER_get0_name(provider);
  lua_pushstring(L, name);
  return 1;
}

static int
openssl_mac_get_params(lua_State *L)
/***
get MAC algorithm parameters
@function get_params
@tparam table params table of OSSL_PARAM definitions (name, type, value)
@treturn table|nil resulting parameters or nil with error message on failure
*/

{
  EVP_MAC    *mac = CHECK_OBJECT(1, EVP_MAC, "openssl.mac");
  OSSL_PARAM *params = openssl_toparams(L, 2);
  int         ret = EVP_MAC_get_params(mac, params);
  if (ret == 1)
    ret = openssl_pushparams(L, params);
  else {
    ret = openssl_pushparams(L, params);
    ret += openssl_pushresult(L, ret);
  }
  OPENSSL_free(params);
  return ret;
}

/* mac_ctx userdata carries a small amount of binding-level state on top of
 * the raw EVP_MAC_CTX. EVP_MAC_final() consumes the context: for CMAC the
 * final operation is destructive, so calling update() or final() again on
 * the same context silently produces a second, meaningless tag. Track a
 * finalized flag and reject any further data-feeding operation; to compute
 * another tag create a fresh mac.ctx (or dup an unfinalized one). */
typedef struct {
  EVP_MAC_CTX *ctx;
  int finalized;
} mac_ctx_ud;

static mac_ctx_ud *
mac_ctx_check(lua_State *L, int idx)
{
  return (mac_ctx_ud *)auxiliar_checkclass(L, "openssl.mac_ctx", idx);
}

static int
mac_ctx_push(lua_State *L, EVP_MAC_CTX *ctx, int finalized)
{
  mac_ctx_ud *ud = (mac_ctx_ud *)lua_newuserdata(L, sizeof(mac_ctx_ud));
  ud->ctx = ctx;
  ud->finalized = finalized;
  auxiliar_setclass(L, "openssl.mac_ctx", -1);
  return 1;
}

static int
mac_ctx_finalized_error(lua_State *L)
{
  lua_pushnil(L);
  lua_pushliteral(L,
    "MAC context already finalized, create a new mac.ctx to compute another tag");
  lua_pushinteger(L, 0);
  return 3;
}

static int
openssl_mac_ctx_gc(lua_State *L)
{
  mac_ctx_ud *ud = mac_ctx_check(L, 1);
  if (ud->ctx) {
    EVP_MAC_CTX_free(ud->ctx);
    ud->ctx = NULL;
  }
  return 0;
}

/***
duplicate MAC context
@function dup
@treturn mac_ctx duplicated MAC context, inherits the finalized state of
  the original (a finalized context cannot be fed again)
*/
static int
openssl_mac_ctx_dup(lua_State *L)
{
  mac_ctx_ud  *ud = mac_ctx_check(L, 1);
  EVP_MAC_CTX *clone = EVP_MAC_CTX_dup(ud->ctx);
  if (clone == NULL)
    return openssl_pushresult(L, 0);
  return mac_ctx_push(L, clone, ud->finalized);
}

/***
get MAC object from MAC context
@function mac
@treturn openssl.mac the MAC object associated with this context
*/
static int
openssl_mac_ctx_mac(lua_State *L)
{
  mac_ctx_ud *ud = mac_ctx_check(L, 1);
  EVP_MAC    *mac = EVP_MAC_CTX_get0_mac(ud->ctx);
  PUSH_OBJECT(mac, "openssl.mac");
  return 1;
}

/***
get or set MAC context parameters (not yet implemented)
@function params
@treturn nil always returns nil (NYI - Not Yet Implemented)
@treturn string error message "NYI"
*/
static int
openssl_mac_ctx_params(lua_State *L)
{
  mac_ctx_ud *ud = mac_ctx_check(L, 1);
  (void)ud;
  /*
  int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[]);
  int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[]);
  */
  lua_pushnil(L);
  lua_pushstring(L, "NYI");
  return 1;
}

static void
openssl_mac_entry(EVP_MAC *mac, void *arg)
{
  lua_State *L = arg;
  int        i = lua_rawlen(L, -1);

  PUSH_OBJECT(mac, "openssl.mac");
  lua_rawseti(L, -2, i + 1);
}

static int
openssl_mac_all(lua_State *L)
{
  OSSL_LIB_CTX *ctx = CHECK_OBJECT(1, OSSL_LIB_CTX, "openssl.ctx");
  lua_newtable(L);

  EVP_MAC_do_all_provided(ctx, openssl_mac_entry, L);
  return 1;
}

const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac);
const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac);

/***
get mac_ctx object

@function ctx
@tparam string|integer|asn1_object alg name, nid or object identity of a digest or cipher algorithm
@tparam[opt] openssl.engine engine nothing with default engine
@treturn mac_ctx object mapping MAC_CTX in openssl
*/
static int
openssl_mac_ctx_new(lua_State *L)
{
  int               ret = 0;
  OSSL_PARAM        params[2];
  size_t            params_n = 0;
  size_t            l;
  const char       *k;
  const EVP_MD     *type_md;
  const EVP_CIPHER *type_c;
  EVP_MAC          *mac;
  EVP_MAC_CTX      *ctx;

  type_c = opt_cipher(L, 1, NULL);
  if (type_c)
    type_md = NULL;
  else
    type_md = opt_digest(L, 1, NULL);

  if (type_md == NULL && type_c == NULL) {
    luaL_argerror(
      L, 1, "must be a string, NID number or asn1_object identity digest/cipher method");
  }

  k = luaL_checklstring(L, 2, &l);

  if (type_md) {
    mac = EVP_MAC_fetch(NULL, "hmac", NULL);
    params[params_n++]
      = OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_name(type_md), 0);
  } else {
    mac = EVP_MAC_fetch(NULL, "cmac", NULL);
    params[params_n++]
      = OSSL_PARAM_construct_utf8_string("cipher", (char *)EVP_CIPHER_name(type_c), 0);
  }
  params[params_n] = OSSL_PARAM_construct_end();

  if (mac) {
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx) {
      ret = EVP_MAC_init(ctx, (const unsigned char *)k, l, params);
      if (ret == 1)
        mac_ctx_push(L, ctx, 0);
      else {
        ret = openssl_pushresult(L, ret);
        EVP_MAC_CTX_free(ctx);
      }
    }
    EVP_MAC_free(mac);
  }
  return ret;
}

/***
free MAC context resources
@function close
@treturn number always returns 0
*/
static int
openssl_mac_ctx_free(lua_State *L)
{
  mac_ctx_ud *ud = mac_ctx_check(L, 1);
  if (ud->ctx) {
    EVP_MAC_CTX_free(ud->ctx);
    ud->ctx = NULL;
  }
  return 0;
}

/***
compute mac one step, in module openssl.mac

@function mac
@tparam evp_digest|string|nid digest digest alg identity
@tparam string message
@tparam string key
@tparam[opt=false] boolean raw binary or hex encoded result, default false for hex result
@treturn string result binary string when raw is true, hex string otherwise
*/
static int
openssl_mac(lua_State *L)
{
  int           ret = 0;
  const EVP_MD *type = get_digest(L, 1, NULL);
  size_t        len;
  const char   *dat = luaL_checklstring(L, 2, &len);
  size_t        l;
  const char   *k = luaL_checklstring(L, 3, &l);
  int           raw = (lua_isnone(L, 4)) ? 0 : lua_toboolean(L, 4);
  ENGINE       *e = lua_isnoneornil(L, 5) ? NULL : CHECK_OBJECT(5, ENGINE, "openssl.engine");
  (void)e;

  unsigned char digest[EVP_MAX_MD_SIZE];

  size_t       dlen = EVP_MAX_MD_SIZE;
  EVP_MAC     *mac;
  EVP_MAC_CTX *ctx = NULL;

  OSSL_PARAM params[2];
  size_t     params_n = 0;

  mac = EVP_MAC_fetch(NULL, "hmac", NULL);
  if (mac) {
    params[params_n++] = OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_name(type), 0);
    params[params_n] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx) {
      ret = EVP_MAC_init(ctx, (const unsigned char *)k, l, params);
      if (ret == 1) {
        ret = EVP_MAC_update(ctx, (const unsigned char *)dat, len);
        if (ret == 1) ret = EVP_MAC_final(ctx, digest, &dlen, dlen);
      }
      EVP_MAC_CTX_free(ctx);
    }
    EVP_MAC_free(mac);
  }

  if (ret == 0) return openssl_pushresult(L, ret);

  if (raw)
    lua_pushlstring(L, (char *)digest, dlen);
  else {
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    to_hex((const char *)digest, dlen, hex);
    lua_pushstring(L, hex);
  }

  return 1;
}

/***
feed data to do digest

note: update() is rejected once final() has been called; EVP_MAC_final()
  consumes the underlying context (a second tag would be meaningless).

@function update
@tparam string msg data
@treturn boolean result true for success
@treturn[2] nil on failure
@treturn[2] string error message
@treturn[2] number error code
@usage
local ctx = mac.ctx("aes-128-cbc", key)
assert(ctx:update("part1"))
assert(ctx:update("part2"))
local tag = assert(ctx:final())
 */
static int
openssl_mac_ctx_update(lua_State *L)
{
  int         ret;
  size_t      l;
  const char *s;
  mac_ctx_ud *ud = mac_ctx_check(L, 1);

  if (ud->finalized)
    return mac_ctx_finalized_error(L);

  s = luaL_checklstring(L, 2, &l);

  ret = EVP_MAC_update(ud->ctx, (unsigned char *)s, l);
  return openssl_pushresult(L, ret);
}

/***
get result of mac

note: final() consumes the context: the returned tag is the final MAC and
  any further update()/final() call on the same context is rejected with
  nil, err, code. Create a new mac.ctx to compute another tag.

@function final
@tparam[opt] string last last part of data
@tparam[opt=false] boolean raw binary or hex encoded result, default false for hex result
@treturn string val hash result
@treturn[2] nil on failure
@treturn[2] string error message
@treturn[2] number error code
@usage
local ctx = mac.ctx("aes-128-cbc", key)
ctx:update("data")
local tag_hex = ctx:final()          -- hex string
local tag_raw = ctx:final(true)      -- binary string
 */
static int
openssl_mac_ctx_final(lua_State *L)
{
  mac_ctx_ud   *ud = mac_ctx_check(L, 1);
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t        len = sizeof(digest);
  int           raw = 0;
  int           ret = 1;

  if (ud->finalized)
    return mac_ctx_finalized_error(L);

  if (lua_isstring(L, 2)) {
    size_t      l;
    const char *s = luaL_checklstring(L, 2, &l);
    ret = EVP_MAC_update(ud->ctx, (unsigned char *)s, l);
    raw = (lua_isnone(L, 3)) ? 0 : lua_toboolean(L, 3);
  } else
    raw = (lua_isnone(L, 2)) ? 0 : lua_toboolean(L, 2);

  if (ret == 1) {
    ret = EVP_MAC_final(ud->ctx, digest, &len, len);
  }

  if (ret == 0) return openssl_pushresult(L, ret);

  /* EVP_MAC_final() consumes the context (for CMAC it is destructive: a
   * second final() on the same context yields a different, meaningless
   * tag). Mark the context finalized so update()/final() are rejected. */
  ud->finalized = 1;

  if (raw) {
    lua_pushlstring(L, (char *)digest, len);
  } else {
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    to_hex((const char *)digest, len, hex);
    lua_pushstring(L, hex);
  }
  return 1;
}

/***
return size of mac value

@function size
@tparam string msg data
@treturn number size of MAC value in bytes
*/
static int
openssl_mac_ctx_size(lua_State *L)
{
  mac_ctx_ud *ud = mac_ctx_check(L, 1);
  size_t      sz = EVP_MAC_CTX_get_mac_size(ud->ctx);

  lua_pushinteger(L, sz);
  return 1;
}

static luaL_Reg mac_funs[] = {
  { "is_a",       openssl_mac_is_a       },
  { "names",      openssl_mac_names      },
  { "provider",   openssl_mac_provider   },
  { "get_params", openssl_mac_get_params },

  { "__tostring", auxiliar_tostring      },
  { "__gc",       openssl_mac_gc         },
  { NULL,         NULL                   }
};

static luaL_Reg mac_ctx_funs[] = {
  { "update",     openssl_mac_ctx_update },
  { "final",      openssl_mac_ctx_final  },
  { "close",      openssl_mac_ctx_free   },
  { "size",       openssl_mac_ctx_size   },

  { "dup",        openssl_mac_ctx_dup    },
  { "mac",        openssl_mac_ctx_mac    },
  { "params",     openssl_mac_ctx_params },

  { "__tostring", auxiliar_tostring      },
  { "__gc",       openssl_mac_ctx_free   },

  { NULL,         NULL                   }
};

static const luaL_Reg mac_R[] = {
  { "ctx", openssl_mac_ctx_new },
  { "new", openssl_mac_new     },
  { "mac", openssl_mac         },

  { NULL,  NULL                }
};

int
luaopen_mac(lua_State *L)
{
  auxiliar_newclass(L, "openssl.mac", mac_funs);
  auxiliar_newclass(L, "openssl.mac_ctx", mac_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, mac_R, 0);

  return 1;
}
#endif
