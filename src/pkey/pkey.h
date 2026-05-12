/***
 * pkey module internal header
 * Shared declarations for pkey sub-modules
 */
#ifndef LUA_OPENSSL_PKEY_H
#define LUA_OPENSSL_PKEY_H

#include "../openssl.h"
#include "../private.h"

/* OSSL_ITEM is OpenSSL 3.0+ (defined in <openssl/core.h>);
 * provide our own for older versions.  The struct has
 *   unsigned int id;
 *   void *ptr;
 * but we only ever store const char * in ptr. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
# ifndef OSSL_ITEM
struct luaopenssl_ossl_item {
  unsigned int  id;
  const char   *ptr;
};
#  define OSSL_ITEM struct luaopenssl_ossl_item
# endif
#endif

/* Forward declarations for functions used across pkey sub-modules */

/* Type mapping - used by read.c and core.c */
int evp_pkey_name2type(const char *name);
const char *evp_pkey_type2name(int type);

/* PQC helper: check if a key is a PQC signature algorithm (ML-DSA, Falcon, SLH-DSA).
 * Returns 1 if the key is a PQC signature algorithm that uses internal hashing.
 * Returns 0 otherwise.
 * Uses the pqc_sig_nids[] table for O(1) lookup by NID.
 * For OpenSSL 3.0+, also tries EVP_PKEY_is_a() for keymgmt-based keys. */
int evp_pkey_is_pqc_sig(EVP_PKEY *pkey);

/* PQC helper: check if a key type uses internal hashing (no external digest needed).
 * Returns 1 if the key is EdDSA, ML-DSA, Falcon, SLH-DSA, or a keymgmt-based key.
 * Returns 0 otherwise (traditional algorithms like RSA, ECDSA).
 * This is a superset of evp_pkey_is_pqc_sig() that also includes EdDSA. */
int evp_pkey_needs_null_digest(EVP_PKEY *pkey);

/* Key operations exposed to other modules */
int openssl_pkey_is_private1(lua_State *L);
int openssl_pkey_read(lua_State *L);
int openssl_pkey_new(lua_State *L);
int openssl_pkey_export(lua_State *L);
int openssl_pkey_free(lua_State *L);
int openssl_pkey_parse(lua_State *L);
int openssl_pkey_encrypt(lua_State *L);
int openssl_pkey_decrypt(lua_State *L);
int openssl_pkey_get_public(lua_State *L);
int openssl_pkey_ctx(lua_State *L);
int openssl_pkey_bits(lua_State *L);
int openssl_pkey_mssing_parameters(lua_State *L);

/* EVP_PKEY_CTX operations */
int openssl_pkey_ctx_new(lua_State *L);
int openssl_pkey_ctx_free(lua_State *L);
int openssl_pkey_ctx_keygen(lua_State *L);
int openssl_pkey_ctx_ctrl(lua_State *L);
int openssl_pkey_ctx_decrypt_init(lua_State *L);
int openssl_pkey_ctx_encrypt_init(lua_State *L);
int openssl_pkey_ctx_verify_init(lua_State *L);
int openssl_pkey_ctx_sign_init(lua_State *L);
int openssl_pkey_ctx_decrypt(lua_State *L);
int openssl_pkey_ctx_encrypt(lua_State *L);
int openssl_pkey_ctx_verify(lua_State *L);
int openssl_pkey_ctx_sign(lua_State *L);

/* Sign/verify/derive/seal/open */
int openssl_sign(lua_State *L);
int openssl_verify(lua_State *L);
int openssl_derive(lua_State *L);

/* KEM (Key Encapsulation Mechanism) operations */
int openssl_encapsulate(lua_State *L);
int openssl_decapsulate(lua_State *L);
int openssl_seal(lua_State *L);
int openssl_open(lua_State *L);
int openssl_seal_init(lua_State *L);
int openssl_seal_update(lua_State *L);
int openssl_seal_final(lua_State *L);
int openssl_open_init(lua_State *L);
int openssl_open_update(lua_State *L);
int openssl_open_final(lua_State *L);

/* Engine support */
#ifndef OPENSSL_NO_ENGINE
int openssl_pkey_set_engine(lua_State *L);
#endif

/* SM2 support */
#if defined(OPENSSL_SUPPORT_SM2)
int openssl_pkey_as_sm2(lua_State *L);
#endif

/* luaL_Reg arrays defined in core.c */
extern luaL_Reg pkey_funcs[];
extern luaL_Reg pkey_ctx_funcs[];

#endif /* LUA_OPENSSL_PKEY_H */
