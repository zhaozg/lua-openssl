# Post-Quantum Cryptography (PQC) Support in lua-openssl

## Executive Summary

lua-openssl now provides **initial support for Post-Quantum Cryptography (PQC) algorithms** through OpenSSL's EVP_PKEY abstraction layer. This support was introduced in commit `423e3c7` ("feat: introduce PQC for openssl v3.x").

The implementation enables:
- **Key generation** for PQC algorithms (ML-DSA/Dilithium, ML-KEM/Kyber, Falcon, SLH-DSA/SPHINCS+) when the underlying OpenSSL 3.x has PQC provider support (e.g., OQS provider, or OpenSSL 3.5+ built-in)
- **Sign/verify** operations with PQC signature algorithms
- **Key export/import** (PEM/DER) round-trip
- **Key parsing** with generic parameter extraction
- **Public key extraction** via `EVP_PKEY_dup` fallback

## Current State Analysis

### 1. What Has Been Implemented

#### 1.1 Algorithm Name Registration (`src/pkey/core.c`)

The `standard_name2type[]` table now includes comprehensive PQC algorithm type mappings, conditionally compiled based on OpenSSL provider support:

| Category | Old OQS Names | Standardized NIST Names |
|----------|---------------|------------------------|
| **ML-DSA (FIPS 204)** | `DILITHIUM`, `DILITHIUM2`, `DILITHIUM3`, `DILITHIUM5` | `ML-DSA`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |
| **ML-KEM (FIPS 203)** | `KYBER`, `KYBER512`, `KYBER768`, `KYBER1024` | `ML-KEM`, `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` |
| **Falcon** | `FALCON`, `FALCON512`, `FALCON1024` | — |
| **SLH-DSA (FIPS 205)** | `SPHINCS`, `SPHINCS-SHA256`, `SPHINCS-SHAKE256` | `SLH-DSA`, `SLH-DSA-SHA2-*`, `SLH-DSA-SHAKE-*` |

Both old OQS provider names and standardized NIST names (OpenSSL 3.5+ built-in) are supported.

#### 1.2 Key Generation (`src/pkey/new.c`)

The `openssl_pkey_new()` function now has a fallback path for unknown algorithms:
1. Try `OBJ_txt2nid(alg)` to convert algorithm name to NID
2. Fall back to `evp_pkey_name2type(alg)` for case-insensitive lookup
3. Create `EVP_PKEY_CTX` via `EVP_PKEY_CTX_new_id(nid, NULL)`
4. Call `EVP_PKEY_keygen_init()` + `EVP_PKEY_keygen()` to generate key pair

This enables `pkey.new("ML-DSA-44")` or `pkey.new("DILITHIUM2")` syntax.

#### 1.3 Sign/Verify (`src/pkey/sign.c`)

Both `openssl_sign()` and `openssl_verify()` now detect PQC signature algorithms and use `NULL` digest (internal hashing) for:
- All Dilithium/ML-DSA variants
- All Falcon variants
- All SPHINCS+/SLH-DSA variants
- Keymgmt-based keys (`EVP_PKEY_id == -1`) as fallback

The one-shot API (`EVP_DigestSign`/`EVP_DigestVerify`) is used for these algorithms when available (OpenSSL >= 1.1.1).

#### 1.4 Public Key Extraction (`src/pkey/core.c`)

`openssl_pkey_get_public()` now has a fallback path:
1. Try standard `i2d_PUBKEY`/`d2i_PUBKEY` round-trip (works for traditional algorithms)
2. If the reconstructed key has `id == NID_undef` (PQC keys on OpenSSL 3.5+), fall through
3. Use `EVP_PKEY_dup()` as final fallback (PQC private keys contain full public key data)

#### 1.5 Key Parsing (`src/pkey/core.c`)

`openssl_pkey_parse()` now handles unknown key types (including PQC) with:
- Fallback to `OBJ_nid2sn()`/`OBJ_nid2ln()` for type name
- OpenSSL 3.x PARAM API extraction: `OSSL_PKEY_PARAM_ALGORITHM_ID`, `OSSL_PKEY_PARAM_PUB_KEY`, `OSSL_PKEY_PARAM_SECURITY_BITS`

#### 1.6 Key Reading (`src/pkey/read.c`)

`openssl_pkey_read()` now uses generic `PEM_read_bio_PUBKEY()`/`d2i_PUBKEY_bio()` for unknown types (including PQC), and `d2i_PKCS8PrivateKey_bio()` for private keys.

#### 1.7 EVP_PKEY_dup Fallback (`src/compat.c`)

For OpenSSL < 3.0 and LibreSSL, an `EVP_PKEY_dup()` fallback is implemented using BIO-based serialization round-trip:
1. Try PKCS#8 PrivateKeyInfo (for private keys)
2. Fall back to SubjectPublicKeyInfo (for public keys)

#### 1.8 Test Suite (`test/9.pqc.lua`)

A comprehensive test suite with 307 lines covering:
- **TestPQCDetection**: Version check, provider module detection, algorithm probing
- **TestPQCOperations**: Key generation, sign/verify, export/import (PEM/DER), key parsing
- **TestPQCProvider**: OQS provider loading (if available)
- **TestPQCEdgeCases**: Unknown algorithm error handling, invalid PEM handling

Tests gracefully skip when PQC is not available (no OQS provider installed).

### 2. Architecture Decisions

#### 2.1 Conditional Compilation via `#ifdef EVP_PKEY_*`

All PQC-specific code uses `#ifdef EVP_PKEY_DILITHIUM`, `#ifdef EVP_PKEY_ML_DSA_44`, etc. This ensures:
- Zero impact on systems without PQC support
- Automatic support when OpenSSL is compiled with OQS provider or OpenSSL 3.5+ built-in PQC
- No new compile-time dependencies

#### 2.2 Null Digest for PQC Signature Algorithms

PQC signature algorithms (ML-DSA, Falcon, SLH-DSA) use internal hashing and don't need an external digest. The implementation detects these by comparing `EVP_PKEY_id(pkey)` directly, since `EVP_PKEY_type()` returns 0 for these NIDs (they're not registered in the legacy type table).

#### 2.3 EVP_PKEY_dup for Public Key Extraction

PQC keys on OpenSSL 3.5+ use keymgmt-based `EVP_PKEY` with `id == -1`. The standard `i2d_PUBKEY`/`d2i_PUBKEY` round-trip fails for these. `EVP_PKEY_dup()` works because PQC private keys contain the full public key data internally.

### 3. Known Limitations

#### 3.1 No Hybrid Key Support

There's no support for hybrid keys (e.g., X25519+ML-KEM-768) or composite signatures (e.g., ECDSA+ML-DSA-44).

#### 3.2 Provider Loading Now Automated ✅

The library now auto-loads common PQC providers (oqsprovider, liboqs, oqs) on module initialization.
Users can also call `provider.load_pqc_providers()` to retry or discover additional providers,
and `provider.query_pqc_algorithms()` to list available PQC algorithms.

#### 3.3 Large Code Duplication in sign.c

The PQC algorithm detection in `openssl_sign()` and `openssl_verify()` uses a long chain of `#ifdef`/`if` comparisons. This is repetitive and could be refactored into a helper function.

#### 3.4 No LDoc Documentation for PQC Functions

The new PQC-related code paths lack proper LDoc documentation (`@tparam`/`@treturn` annotations).

## Implementation Roadmap

### Phase 1 ✅ (Completed)
- [x] Research and document OpenSSL's PQC support mechanisms
- [x] Register PQC algorithm names in type mapping table
- [x] Implement generic key generation via EVP_PKEY_CTX
- [x] Add null digest detection for PQC signature algorithms
- [x] Implement EVP_PKEY_dup fallback for older OpenSSL
- [x] Add public key extraction fallback for PQC keys
- [x] Add generic key parsing for unknown types
- [x] Create comprehensive test suite (test/9.pqc.lua)

### Phase 2 ✅ (Completed)

#### 2.1 Refactor PQC Detection in sign.c ✅ (Completed)
- [x] Extract PQC algorithm detection into a shared helper function `evp_pkey_is_pqc_sig()`
- [x] Reduce code duplication between `openssl_sign()` and `openssl_verify()` via shared `sign_verify_init_ctx()` helper
- [x] Use `EVP_PKEY_is_a()` for OpenSSL 3.x native detection of keymgmt-based keys
- [x] Replace 30+ individual `#ifdef`/`if` comparisons with a data-driven `pqc_sig_nids[]` table
- [x] Add `evp_pkey_is_pqc_sig()` declaration to `pkey.h` for reuse by other modules

#### 2.2 Add LDoc Documentation
- [ ] Document PQC-related code paths in `src/pkey/core.c`, `new.c`, `sign.c`, `read.c`
- [ ] Add `@tparam`/`@treturn` annotations for new function behaviors
- [ ] Document algorithm name mappings (old OQS vs standardized NIST names)

#### 2.3 KEM API (Encapsulate/Decapsulate) ✅ (Completed)
- [x] Add `pkey.encapsulate(key)` → `ciphertext, shared_secret`
- [x] Add `pkey.decapsulate(key, ciphertext)` → `shared_secret`
- [x] Support ML-KEM (Kyber) key encapsulation mechanism
- [x] Add tests for KEM operations

#### 2.4 Provider Management ✅ (Completed)
- [x] Add `openssl.provider` module documentation with complete LDoc annotations
- [x] Auto-load common PQC providers (oqsprovider, liboqs, oqs) on module initialization
- [x] Add `provider.query_pqc_algorithms()` to list available PQC algorithms
- [x] Add `provider.load_pqc_providers()` to auto-detect and load PQC providers
- [x] Add comprehensive tests for PQC provider management APIs

### Phase 3 🎯 (Medium-term)

#### 3.1 TLS Integration ✅ (Completed)
- [x] Create `src/ssl_pqc.c` module for PQC TLS integration
- [x] Add `ssl.ctx:set_pqc_sigalgs()` for PQC signature algorithm configuration
- [x] Add `ssl.ctx:set_pqc_groups()` for PQC KEM groups (hybrid key exchange)
- [x] Add `ssl.ctx:set_pqc_hybrid_groups()` for hybrid PQC+traditional groups
- [x] Add `ssl.ctx:get_pqc_sigalgs()` to query available PQC signature algorithms
- [x] Add `ssl.ctx:get_pqc_groups()` to query available PQC KEM groups
- [x] Add `ssl.ctx:is_pqc_available()` to check PQC algorithm availability
- [x] Add `ssl.list_pqc_algorithms()` module-level function to list all PQC algorithms
- [x] Add `ssl.is_pqc_available()` module-level function for PQC availability check
- [x] Auto-detection of available PQC algorithms via `EVP_PKEY_keygen_init` probing
- [x] Support both old OQS provider names and standardized NIST names
- [x] Conditional compilation for OpenSSL >= 3.0 (no impact on older versions)
- [x] Integration into build system (Makefile, CMakeLists.txt)

#### 3.2 Hybrid Key Support
- [ ] Research OpenSSL's composite/hybrid key API
- [ ] Add support for X.509 certificates with composite keys
- [ ] Add hybrid signature operations (e.g., ECDSA + ML-DSA)

#### 3.3 Performance Optimization
- [ ] Benchmark PQC key generation, signing, and verification
- [ ] Consider batch key generation for testing
- [ ] Document expected key sizes and performance characteristics

### Phase 4 📚 (Long-term)

#### 4.1 Documentation and Examples
- [ ] Create PQC usage guide with examples
- [ ] Document how to compile OpenSSL with OQS provider
- [ ] Add security considerations specific to PQC algorithms
- [ ] Create migration guide for hybrid deployments

#### 4.2 CI Integration
- [ ] Add OQS provider installation to CI pipeline
- [ ] Run PQC tests in CI when provider is available
- [ ] Test across OpenSSL 3.0/3.2/3.5+ with different provider configurations

#### 4.3 FIPS Considerations
- [ ] Document FIPS 140-3 validation status of PQC algorithms
- [ ] Ensure ML-DSA (FIPS 204), ML-KEM (FIPS 203), SLH-DSA (FIPS 205) paths work in FIPS mode
- [ ] Add FIPS indicator checks for PQC operations

## Technical Details

### Algorithm NID Compatibility

| OpenSSL Version | PQC Support | NID Source |
|----------------|-------------|------------|
| < 3.0 | None | N/A |
| 3.0 - 3.4 | Via OQS provider only | `EVP_PKEY_DILITHIUM2`, etc. (provider-defined) |
| 3.5+ | Built-in + OQS provider | `EVP_PKEY_ML_DSA_44`, `EVP_PKEY_SLH_DSA_SHA2_128S`, etc. |

### Key Sizes (Approximate)

| Algorithm | Private Key | Public Key | Signature |
|-----------|-------------|------------|-----------|
| ML-DSA-44 (Dilithium2) | ~2.5 KB | ~1.3 KB | ~2.4 KB |
| ML-DSA-65 (Dilithium3) | ~4.0 KB | ~2.0 KB | ~3.3 KB |
| ML-DSA-87 (Dilithium5) | ~5.0 KB | ~2.6 KB | ~4.6 KB |
| ML-KEM-512 (Kyber512) | ~1.6 KB | ~0.8 KB | N/A (KEM) |
| ML-KEM-768 (Kyber768) | ~2.4 KB | ~1.2 KB | N/A (KEM) |
| ML-KEM-1024 (Kyber1024) | ~3.2 KB | ~1.6 KB | N/A (KEM) |
| Falcon-512 | ~1.3 KB | ~0.9 KB | ~0.7 KB |
| Falcon-1024 | ~2.3 KB | ~1.8 KB | ~1.3 KB |
| SLH-DSA-SHA2-128S | ~0.1 KB | ~0.1 KB | ~8.0 KB |
| SLH-DSA-SHAKE-128S | ~0.1 KB | ~0.1 KB | ~8.0 KB |

### Usage Examples

```lua
local openssl = require('openssl')
local pkey = openssl.pkey

-- Check if PQC is available
local function is_pqc_available(alg)
  local ok, key = pcall(pkey.new, alg)
  return ok and key ~= nil
end

-- Generate ML-DSA-44 (Dilithium2) key pair
if is_pqc_available("ML-DSA-44") then
  local key = pkey.new("ML-DSA-44")
  local pub = pkey.get_public(key)

  -- Sign and verify
  local msg = "Post-Quantum message"
  local sig = pkey.sign(key, msg)
  local ok = pkey.verify(pub, msg, sig)
  assert(ok, "PQC signature verification failed")

  -- Export and re-import
  local pem = key:export("pem", false)
  local key2 = pkey.read(pem, true)
  assert(key2:is_private())
end
```

## Conclusion

lua-openssl now has a solid foundation for PQC support. The implementation leverages OpenSSL's EVP_PKEY abstraction to transparently support PQC algorithms when the underlying provider is available. Key generation, signing, verification, and key serialization all work with PQC algorithms.

The next priorities are:
1. **Refactor** the repetitive PQC detection code in `sign.c` ✅ (Completed)
2. **Add KEM API** for ML-KEM encapsulate/decapsulate operations ✅ (Completed)
3. **Integrate with TLS** for PQC signature algorithms and hybrid key exchange ✅ (Completed)
4. **Provider Management** - auto-load PQC providers, query API ✅ (Completed)
5. **Document** the PQC capabilities with proper LDoc and usage guides

This positions lua-openssl as a practical tool for experimenting with and deploying post-quantum cryptography in Lua-based applications, while maintaining full backward compatibility with existing systems.
