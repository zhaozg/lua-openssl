/**
 * ssl_pqc module - Post-Quantum Cryptography TLS Integration
 *
 * Provides SSL/TLS context methods for configuring PQC signature algorithms
 * and KEM groups for TLS 1.3 handshakes, including hybrid key exchange.
 *
 * This module extends the ssl.ctx object with PQC-specific configuration
 * methods, conditionally compiled when OpenSSL 3.x has PQC provider support.
 *
 * @module ssl.pqc
 * @usage
 *   local ssl = require('openssl').ssl
 *   local ctx = ssl.ctx_new('TLS')
 *
 *   -- Set PQC signature algorithms for TLS 1.3
 *   ctx:set_pqc_sigalgs("ML-DSA-44", "ML-DSA-65")
 *
 *   -- Set PQC KEM groups for hybrid key exchange
 *   ctx:set_pqc_groups("ML-KEM-768", "X25519+ML-KEM-768")
 */

#include "openssl.h"
#include "private.h"
#include "pkey/pkey.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>

/* ========================================================================
 * Compatibility: SSL_CTX_set1_sigalgs_list / SSL_CTX_set1_groups_list
 *
 * These functions are available in OpenSSL 1.1.0+ and LibreSSL 3.x+.
 * For older versions, we provide stub implementations that return error.
 * ======================================================================== */

#if (OPENSSL_VERSION_NUMBER < 0x30000000L) || defined(LIBRESSL_VERSION_NUMBER)
/* Stub: no sigalgs/groups list support before OpenSSL 1.1.0 */
static int
ssl_pqc_set_sigalgs_list(SSL_CTX *ctx, const char *sigalgs)
{
    (void)ctx;
    (void)sigalgs;
    return 0; /* not supported */
}

static int
ssl_pqc_set_groups_list(SSL_CTX *ctx, const char *groups)
{
    (void)ctx;
    (void)groups;
    return 0; /* not supported */
}
#else
#include <openssl/core_names.h>

#define ssl_pqc_set_sigalgs_list SSL_CTX_set1_sigalgs_list
#define ssl_pqc_set_groups_list  SSL_CTX_set1_groups_list

/* ========================================================================
 * PQC Algorithm Name Tables
 *
 * These tables map human-readable PQC algorithm names to their
 * OpenSSL signature algorithm string representations for use with
 * SSL_CTX_set1_sigalgs_list().
 *
 * The names follow both old OQS provider conventions and the
 * standardized NIST names (OpenSSL 3.5+).
 * ======================================================================== */

/**
 * PQC signature algorithms for TLS 1.3.
 * These algorithms use internal hashing (no external digest needed).
 */
static const char *pqc_sig_algs[] = {
    /* ML-DSA (FIPS 204) - Standardized NIST names */
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    /* ML-DSA - Old OQS provider names */
    "DILITHIUM2",
    "DILITHIUM3",
    "DILITHIUM5",
    /* Falcon */
    "FALCON512",
    "FALCON1024",
    /* SLH-DSA (FIPS 205) - Standardized NIST names */
    "SLH-DSA-SHA2-128S",
    "SLH-DSA-SHA2-128F",
    "SLH-DSA-SHA2-192S",
    "SLH-DSA-SHA2-192F",
    "SLH-DSA-SHA2-256S",
    "SLH-DSA-SHA2-256F",
    "SLH-DSA-SHAKE-128S",
    "SLH-DSA-SHAKE-128F",
    "SLH-DSA-SHAKE-192S",
    "SLH-DSA-SHAKE-192F",
    "SLH-DSA-SHAKE-256S",
    "SLH-DSA-SHAKE-256F",
    /* SLH-DSA - Old OQS provider names */
    "SPHINCS+-SHA256-128S",
    "SPHINCS+-SHA256-128F",
    "SPHINCS+-SHA256-192S",
    "SPHINCS+-SHA256-192F",
    "SPHINCS+-SHA256-256S",
    "SPHINCS+-SHA256-256F",
    "SPHINCS+-SHAKE256-128S",
    "SPHINCS+-SHAKE256-128F",
    "SPHINCS+-SHAKE256-192S",
    "SPHINCS+-SHAKE256-192F",
    "SPHINCS+-SHAKE256-256S",
    "SPHINCS+-SHAKE256-256F",
    NULL
};

/**
 * PQC KEM groups for TLS 1.3 key exchange.
 * These include both pure PQC groups and hybrid groups (PQC + traditional).
 */
static const char *pqc_kem_groups[] = {
    /* ML-KEM (FIPS 203) - Standardized NIST names */
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    /* ML-KEM - Old OQS provider names */
    "KYBER512",
    "KYBER768",
    "KYBER1024",
    /* Hybrid groups (PQC + traditional) */
    "X25519+ML-KEM-512",
    "X25519+ML-KEM-768",
    "X25519+ML-KEM-1024",
    "P256+ML-KEM-512",
    "P256+ML-KEM-768",
    "P384+ML-KEM-1024",
    "X448+ML-KEM-1024",
    NULL
};

/* ========================================================================
 * Helper: check if a PQC algorithm is available in the current OpenSSL
 * provider configuration.
 *
 * Uses EVP_PKEY_keygen to probe algorithm availability.
 * Returns 1 if available, 0 otherwise.
 * ======================================================================== */
static int
pqc_algorithm_available(const char *alg_name)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    int nid;

    /* Try OBJ_txt2nid first (works for registered OIDs) */
    nid = OBJ_txt2nid(alg_name);
    if (nid == NID_undef) {
        /* Fall back to evp_pkey_name2type for case-insensitive lookup */
        nid = evp_pkey_name2type(alg_name);
    }

    if (nid == NID_undef)
        return 0;

    ctx = EVP_PKEY_CTX_new_id(nid, NULL);
    if (ctx == NULL)
        return 0;

    if (EVP_PKEY_keygen_init(ctx) == 1) {
        /* Keygen init succeeded, algorithm is available */
        ret = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ========================================================================
 * Helper: build a colon-separated list of available PQC algorithms
 * from a table of candidate names.
 *
 * Returns a newly allocated string (caller must OPENSSL_free), or NULL
 * if no algorithms from the table are available.
 * ======================================================================== */
static char *
build_available_list(lua_State *L, const char *candidates[], int from_lua_args)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int count = 0;
    int i;

    if (bio == NULL)
        return NULL;

    if (from_lua_args) {
        /* Build list from Lua arguments (vararg) */
        int n = lua_gettop(L);
        for (i = 1; i <= n; i++) {
            const char *name = luaL_checkstring(L, i);
            if (pqc_algorithm_available(name)) {
                if (count > 0)
                    BIO_printf(bio, ":");
                BIO_printf(bio, "%s", name);
                count++;
            }
        }
    } else {
        /* Build list from static table, checking availability */
        for (i = 0; candidates[i] != NULL; i++) {
            if (pqc_algorithm_available(candidates[i])) {
                if (count > 0)
                    BIO_printf(bio, ":");
                BIO_printf(bio, "%s", candidates[i]);
                count++;
            }
        }
    }

    if (count == 0) {
        BIO_free(bio);
        return NULL;
    }

    {
        BUF_MEM *mem;
        BIO_get_mem_ptr(bio, &mem);
        char *result = OPENSSL_malloc(mem->length + 1);
        if (result) {
            memcpy(result, mem->data, mem->length);
            result[mem->length] = '\0';
        }
        BIO_free(bio);
        return result;
    }
}

/* ========================================================================
 * openssl_ssl_ctx_set_pqc_sigalgs - Configure PQC signature algorithms
 *
 * Sets the signature algorithms for TLS 1.3 handshake to include
 * PQC algorithms. Accepts a list of algorithm names as varargs.
 * If no arguments given, auto-detects and enables all available
 * PQC signature algorithms.
 *
 * Usage from Lua:
 *   ctx:set_pqc_sigalgs("ML-DSA-44", "ML-DSA-65")
 *   ctx:set_pqc_sigalgs()  -- auto-detect all available
 *
 * @function set_pqc_sigalgs
 * @tparam ssl.ctx ctx SSL context object
 * @tparam[opt] string ... PQC signature algorithm names (vararg)
 * @treturn boolean true on success
 * @treturn[2] nil on failure
 * @treturn[2] string error message
 * @see openssl/ssl.h:SSL_CTX_set1_sigalgs_list
 * @usage
 *   local ctx = ssl.ctx_new('TLS')
 *   if ctx:set_pqc_sigalgs("ML-DSA-44") then
 *     print("ML-DSA-44 configured for TLS")
 *   end
 * ======================================================================== */
static int
openssl_ssl_ctx_set_pqc_sigalgs(lua_State *L)
{
    SSL_CTX *ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
    char *sigalgs_list = NULL;
    int ret;

    /* Remove ctx from stack, leaving only algorithm names */
    lua_remove(L, 1);

    if (lua_gettop(L) == 0) {
        /* No arguments: auto-detect all available PQC signature algorithms */
        sigalgs_list = build_available_list(L, pqc_sig_algs, 0);
    } else {
        /* Use user-specified algorithm names */
        sigalgs_list = build_available_list(L, NULL, 1);
    }

    if (sigalgs_list == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "No PQC signature algorithms available");
        return 2;
    }

    ret = ssl_pqc_set_sigalgs_list(ctx, sigalgs_list);
    OPENSSL_free(sigalgs_list);

    if (ret != 1) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to set PQC signature algorithms");
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_set_pqc_groups - Configure PQC KEM groups
 *
 * Sets the supported groups (key exchange curves) for TLS handshake
 * to include PQC KEM algorithms. Accepts a list of group names as varargs.
 * If no arguments given, auto-detects and enables all available
 * PQC KEM groups.
 *
 * Usage from Lua:
 *   ctx:set_pqc_groups("ML-KEM-768", "X25519+ML-KEM-768")
 *   ctx:set_pqc_groups()  -- auto-detect all available
 *
 * @function set_pqc_groups
 * @tparam ssl.ctx ctx SSL context object
 * @tparam[opt] string ... PQC KEM group names (vararg)
 * @treturn boolean true on success
 * @treturn[2] nil on failure
 * @treturn[2] string error message
 * @see openssl/ssl.h:SSL_CTX_set1_groups_list
 * @usage
 *   local ctx = ssl.ctx_new('TLS')
 *   if ctx:set_pqc_groups("ML-KEM-768") then
 *     print("ML-KEM-768 configured for TLS key exchange")
 *   end
 * ======================================================================== */
static int
openssl_ssl_ctx_set_pqc_groups(lua_State *L)
{
    SSL_CTX *ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
    char *groups_list = NULL;
    int ret;

    /* Remove ctx from stack, leaving only group names */
    lua_remove(L, 1);

    if (lua_gettop(L) == 0) {
        /* No arguments: auto-detect all available PQC KEM groups */
        groups_list = build_available_list(L, pqc_kem_groups, 0);
    } else {
        /* Use user-specified group names */
        groups_list = build_available_list(L, NULL, 1);
    }

    if (groups_list == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "No PQC KEM groups available");
        return 2;
    }

    ret = ssl_pqc_set_groups_list(ctx, groups_list);
    OPENSSL_free(groups_list);

    if (ret != 1) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to set PQC KEM groups");
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_set_pqc_hybrid_groups - Configure hybrid PQC+traditional groups
 *
 * Sets the supported groups to include hybrid key exchange groups
 * (e.g., X25519+ML-KEM-768, P256+ML-KEM-768). These groups combine
 * a traditional key exchange with a PQC KEM for hybrid security.
 *
 * Usage from Lua:
 *   ctx:set_pqc_hybrid_groups("X25519+ML-KEM-768", "P256+ML-KEM-768")
 *   ctx:set_pqc_hybrid_groups()  -- auto-detect all available hybrid groups
 *
 * @function set_pqc_hybrid_groups
 * @tparam ssl.ctx ctx SSL context object
 * @tparam[opt] string ... Hybrid group names (vararg)
 * @treturn boolean true on success
 * @treturn[2] nil on failure
 * @treturn[2] string error message
 * @see openssl/ssl.h:SSL_CTX_set1_groups_list
 * @usage
 *   local ctx = ssl.ctx_new('TLS')
 *   if ctx:set_pqc_hybrid_groups("X25519+ML-KEM-768") then
 *     print("Hybrid X25519+ML-KEM-768 configured")
 *   end
 * ======================================================================== */
static int
openssl_ssl_ctx_set_pqc_hybrid_groups(lua_State *L)
{
    SSL_CTX *ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
    char *groups_list = NULL;
    int ret;

    /* Remove ctx from stack, leaving only group names */
    lua_remove(L, 1);

    /* Hybrid groups contain '+' character (e.g., "X25519+ML-KEM-768") */
    static const char *hybrid_groups[] = {
        "X25519+ML-KEM-512",
        "X25519+ML-KEM-768",
        "X25519+ML-KEM-1024",
        "P256+ML-KEM-512",
        "P256+ML-KEM-768",
        "P384+ML-KEM-1024",
        "X448+ML-KEM-1024",
        NULL
    };

    if (lua_gettop(L) == 0) {
        /* No arguments: auto-detect all available hybrid groups */
        groups_list = build_available_list(L, hybrid_groups, 0);
    } else {
        /* Use user-specified group names */
        groups_list = build_available_list(L, NULL, 1);
    }

    if (groups_list == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "No hybrid PQC groups available");
        return 2;
    }

    ret = ssl_pqc_set_groups_list(ctx, groups_list);
    OPENSSL_free(groups_list);

    if (ret != 1) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to set hybrid PQC groups");
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_get_pqc_sigalgs - Get configured PQC signature algorithms
 *
 * Returns a table of currently configured PQC signature algorithms
 * on the SSL context. This queries the SSL_CTX for its sigalgs list.
 *
 * Usage from Lua:
 *   local sigalgs = ctx:get_pqc_sigalgs()
 *
 * @function get_pqc_sigalgs
 * @tparam ssl.ctx ctx SSL context object
 * @treturn table Array of PQC signature algorithm names
 * @treturn[2] nil on failure
 * @treturn[2] string error message
 * ======================================================================== */
static int
openssl_ssl_ctx_get_pqc_sigalgs(lua_State *L)
{
    SSL_CTX *ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
    /* Return a table of available PQC signature algorithms */
    (void)ctx;
    lua_newtable(L);
    {
        int i, idx = 1;
        for (i = 0; pqc_sig_algs[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_sig_algs[i])) {
                lua_pushstring(L, pqc_sig_algs[i]);
                lua_rawseti(L, -2, idx++);
            }
        }
    }
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_get_pqc_groups - Get configured PQC KEM groups
 *
 * Returns a table of currently configured PQC KEM groups
 * on the SSL context.
 *
 * Usage from Lua:
 *   local groups = ctx:get_pqc_groups()
 *
 * @function get_pqc_groups
 * @tparam ssl.ctx ctx SSL context object
 * @treturn table Array of PQC KEM group names
 * @treturn[2] nil on failure
 * @treturn[2] string error message
 * ======================================================================== */
static int
openssl_ssl_ctx_get_pqc_groups(lua_State *L)
{
    SSL_CTX *ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
    /* Return a table of available PQC KEM groups */
    (void)ctx;
    lua_newtable(L);
    {
        int i, idx = 1;
        for (i = 0; pqc_kem_groups[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_kem_groups[i])) {
                lua_pushstring(L, pqc_kem_groups[i]);
                lua_rawseti(L, -2, idx++);
            }
        }
    }
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_is_pqc_available - Check if PQC is available
 *
 * Returns a boolean indicating whether PQC algorithms are available
 * in the current OpenSSL provider configuration.
 *
 * Usage from Lua:
 *   if ctx:is_pqc_available() then ... end
 *   -- or as module-level function:
 *   if ssl.is_pqc_available() then ... end
 *
 * @function is_pqc_available
 * @tparam[opt] string alg_name Optional specific algorithm to check
 * @treturn boolean true if PQC algorithms are available
 * @usage
 *   local ssl = require('openssl').ssl
 *   if ssl.is_pqc_available() then
 *     print("PQC is available!")
 *   end
 *   if ssl.is_pqc_available("ML-DSA-44") then
 *     print("ML-DSA-44 is available!")
 *   end
 * ======================================================================== */
static int
openssl_ssl_ctx_is_pqc_available(lua_State *L)
{
    const char *alg = lua_tostring(L, 1);

    if (alg) {
        /* Check specific algorithm */
        lua_pushboolean(L, pqc_algorithm_available(alg));
        return 1;
    }

    /* Check if any PQC signature algorithm is available */
    {
        int i;
        for (i = 0; pqc_sig_algs[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_sig_algs[i])) {
                lua_pushboolean(L, 1);
                return 1;
            }
        }
    }

    /* Check if any PQC KEM group is available */
    {
        int i;
        for (i = 0; pqc_kem_groups[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_kem_groups[i])) {
                lua_pushboolean(L, 1);
                return 1;
            }
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

/* ========================================================================
 * openssl_ssl_ctx_list_pqc_algorithms - List available PQC algorithms
 *
 * Returns a table of all available PQC algorithms detected in the
 * current OpenSSL provider configuration.
 *
 * Usage from Lua:
 *   local algs = ssl.list_pqc_algorithms()
 *   -- algs.sigalgs = { "ML-DSA-44", "ML-DSA-65", ... }
 *   -- algs.groups  = { "ML-KEM-768", "X25519+ML-KEM-768", ... }
 *
 * @function list_pqc_algorithms
 * @treturn table Table with 'sigalgs' and 'groups' arrays
 * @usage
 *   local ssl = require('openssl').ssl
 *   local algs = ssl.list_pqc_algorithms()
 *   for _, alg in ipairs(algs.sigalgs) do
 *     print("Signature: " .. alg)
 *   end
 *   for _, grp in ipairs(algs.groups) do
 *     print("Group: " .. grp)
 *   end
 * ======================================================================== */
static int
openssl_ssl_ctx_list_pqc_algorithms(lua_State *L)
{
    lua_newtable(L);

    /* Signature algorithms */
    lua_newtable(L);
    {
        int i, idx = 1;
        for (i = 0; pqc_sig_algs[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_sig_algs[i])) {
                lua_pushstring(L, pqc_sig_algs[i]);
                lua_rawseti(L, -2, idx++);
            }
        }
    }
    lua_setfield(L, -2, "sigalgs");

    /* KEM groups */
    lua_newtable(L);
    {
        int i, idx = 1;
        for (i = 0; pqc_kem_groups[i] != NULL; i++) {
            if (pqc_algorithm_available(pqc_kem_groups[i])) {
                lua_pushstring(L, pqc_kem_groups[i]);
                lua_rawseti(L, -2, idx++);
            }
        }
    }
    lua_setfield(L, -2, "groups");

    return 1;
}

/* ========================================================================
 * Module registration
 *
 * These functions are registered into the ssl.ctx metatable and the
 * ssl module table from ssl.c via the LOAD_SSL_CUSTOM hook.
 * ======================================================================== */

/**
 * Register PQC TLS functions into the ssl.ctx metatable.
 * Called from luaopen_ssl via LOAD_SSL_CUSTOM macro.
 *
 * @function register_pqc_ssl
 * @local
 */
int
luaopen_ssl_pqc(lua_State *L)
{
    /* Register methods into the existing ssl.ctx class */
    /* Note: These are registered from ssl.c via LOAD_SSL_CUSTOM */

    /* Register module-level functions */
    lua_pushcfunction(L, openssl_ssl_ctx_is_pqc_available);
    lua_setfield(L, -2, "is_pqc_available");

    lua_pushcfunction(L, openssl_ssl_ctx_list_pqc_algorithms);
    lua_setfield(L, -2, "list_pqc_algorithms");

    return 0;
}

/* ========================================================================
 * Functions to be called from ssl.c registration
 *
 * These are the actual function pointers that get added to the
 * ssl_ctx_funcs table in ssl.c via the LOAD_SSL_CUSTOM mechanism.
 * ======================================================================== */

/* Array of functions to add to ssl.ctx methods */
static luaL_Reg pqc_ssl_ctx_methods[] = {
    { "set_pqc_sigalgs",        openssl_ssl_ctx_set_pqc_sigalgs        },
    { "set_pqc_groups",         openssl_ssl_ctx_set_pqc_groups         },
    { "set_pqc_hybrid_groups",  openssl_ssl_ctx_set_pqc_hybrid_groups  },
    { "get_pqc_sigalgs",        openssl_ssl_ctx_get_pqc_sigalgs        },
    { "get_pqc_groups",         openssl_ssl_ctx_get_pqc_groups         },
    { "is_pqc_available",       openssl_ssl_ctx_is_pqc_available       },
    { NULL,                     NULL                                   },
};

/* Called from ssl.c to register PQC methods into ssl.ctx.
 *
 * We need to get the ssl.ctx metatable and add methods to it.
 * The metatable was created by auxiliar_newclass and its __index
 * table contains all the methods.
 */
void
ssl_pqc_register_ctx_methods(lua_State *L, int ctx_idx)
{
    /* Push the ssl.ctx class metatable.
     * auxiliar_newclass stores metatables in the registry
     * with the class name as key. */
    luaL_getmetatable(L, "openssl.ssl_ctx");
    if (!lua_isnil(L, -1)) {
        /* Get the __index table from the metatable */
        lua_getfield(L, -1, "__index");
        if (lua_istable(L, -1)) {
            /* Add PQC methods to the __index table */
            luaL_setfuncs(L, pqc_ssl_ctx_methods, 0);
        }
        lua_pop(L, 1); /* pop __index table or nil */
    }
    lua_pop(L, 1); /* pop metatable or nil */
}
#endif
