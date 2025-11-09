# OpenSSL 3.0 Deprecation Warnings - Current Status

**Last Updated:** 2025-11-09  
**OpenSSL Version Tested:** 3.0.13  
**Test Results:** 177/177 passing ✅

## Executive Summary

This document tracks the status of OpenSSL 3.0 deprecation warning handling in lua-openssl. 
The project has successfully addressed deprecation warnings in critical modules while maintaining 
backward compatibility with OpenSSL 1.1.x and LibreSSL.

## Completed Modules ✅

### DH Module (src/dh.c) - Issue #344
**Status:** ✅ **COMPLETED**  
**Warnings:** 0  
**Strategy:**
- Uses `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` to suppress warnings
- Implements OSSL_PARAM API for OpenSSL 3.0+ (e.g., EVP_PKEY_CTX_new_from_name)
- Maintains backward compatibility with OpenSSL 1.1.x through conditional compilation
- Full test coverage with existing test suite

**Code Example:**
```c
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
// DH operations...
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
```

### DSA Module (src/dsa.c) - Issue #346
**Status:** ✅ **COMPLETED**  
**Warnings:** 0  
**Strategy:**
- Uses `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` to suppress warnings
- DSA API is marked deprecated in OpenSSL 3.0 but remains fully functional
- Retained for backward compatibility and existing application support
- Full test coverage

**Rationale:**  
DSA is deprecated in OpenSSL 3.0 due to security concerns and recommendations to use ECDSA or EdDSA instead.
However, many existing applications still rely on DSA, so the module is maintained with suppressed warnings.

### EC Module (src/ec.c)
**Status:** ✅ **COMPLETED**  
**Warnings:** 0 (suppressed by pragma)  
**Strategy:**
- Uses `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` for the entire module
- Core cryptographic operations (ECDSA sign/verify, ECDH) migrated to EVP APIs
- EC_KEY accessor functions retained for Lua API and object lifecycle management
- Full test coverage including EC key generation, signing, and verification

**Code Comment from Source:**
```c
/* Suppress deprecation warnings for EC_KEY accessor functions that are part of the module's API.
 * The core cryptographic operations (ECDSA sign/verify, ECDH) have been migrated to EVP APIs.
 * These accessors are needed for the Lua API and object lifecycle management. */
```

### Digest Module (src/digest.c) - PR #353
**Status:** ✅ **COMPLETED**  
**Warnings:** 0  
**Strategy:**
- Conditional compilation to disable `EVP_MD_meth_get_app_datasize()` for OpenSSL 3.0+ and LibreSSL
- Function is not supported in modern OpenSSL/LibreSSL, so the feature is gracefully disabled
- No breaking changes to API - function returns 0 when unsupported
- Full test coverage

**Code Example:**
```c
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* EVP_MD_meth_get_app_datasize is deprecated in OpenSSL 3.0+ */
  (void)ctx;
  return 0;
#else
  const EVP_MD *md = EVP_MD_CTX_md(ctx);
  size_t ctx_size = (size_t)EVP_MD_meth_get_app_datasize(md);
  // ... implementation for older OpenSSL
#endif
```

### SRP Module (src/srp.c) - Issue #351
**Status:** ✅ **COMPLETED**  
**Warnings:** 0  
**Strategy:**
- Uses `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` to suppress warnings
- SRP is deprecated in OpenSSL 3.0 but remains functional
- Retained for backward compatibility
- Full test coverage

**Code Comment from Source:**
```c
/* Suppress deprecation warnings for SRP functions in OpenSSL 3.0+
 * The SRP module is marked deprecated but remains functional.
 * We continue to use it to maintain backward compatibility. */
```

### RSA Module (src/rsa.c)
**Status:** ✅ **COMPLETED**  
**Warnings:** 0  
**Strategy:**
- Uses `#pragma GCC diagnostic ignored "-Wdeprecated-declarations"` to suppress warnings
- RSA low-level API is deprecated in OpenSSL 3.0 but remains fully functional
- Provides direct Lua bindings to complete RSA functionality
- Retained for backward compatibility and complete control over RSA operations
- Full test coverage

**Code Comment from Source:**
```c
/* Suppress deprecation warnings for RSA functions in OpenSSL 3.0+
 * RSA low-level API functions are deprecated in OpenSSL 3.0 in favor of EVP_PKEY APIs.
 * However, this module provides direct Lua bindings to OpenSSL RSA API for:
 * 1. Complete RSA functionality including low-level operations
 * 2. Backward compatibility with existing Lua code
 * 3. Direct control over RSA operations (padding, encryption modes, etc.)
 * 
 * The RSA API remains functional in OpenSSL 3.0+ and is widely used.
 * Future versions may migrate to EVP_PKEY operations while maintaining API compatibility.
 * 
 * Compatibility: OpenSSL 1.1.x, 3.0.x, 3.x.x and LibreSSL 3.3.6+
 */
```

## Remaining Deprecation Warnings

The following modules still have deprecation warnings. These are **expected and acceptable** as they 
provide direct Lua bindings to low-level OpenSSL APIs. Migration would require significant refactoring 
and could break backward compatibility.

### ENGINE Module (src/engine.c)
**Warnings:** 53  
**Reason:** ENGINE API is deprecated in OpenSSL 3.0 in favor of the Provider API  
**Status:** Retained for backward compatibility  
**Future:** May be migrated to Provider API in a future major version

### PKEY Module (src/pkey.c)
**Warnings:** 127  
**Reason:** Low-level key operations required for complete OpenSSL key management  
**Status:** Many functions needed for legacy key support and backward compatibility  
**Future:** Gradual migration as Provider API matures

### HMAC Module (src/hmac.c)
**Warnings:** 7  
**Reason:** HMAC API replaced by EVP_MAC in OpenSSL 3.0  
**Status:** Functional with current API  
**Future:** Evaluate migration to EVP_MAC with backward compatibility layer

## Implementation Strategy

The project uses a pragmatic approach to deprecation warnings:

1. **Migration First:** When possible, migrate to modern APIs (e.g., DH module uses OSSL_PARAM in OpenSSL 3.0+)
2. **Suppression with Documentation:** For APIs that must be retained, use pragma directives with clear explanations
3. **Conditional Compilation:** Support multiple OpenSSL versions through preprocessor directives
4. **Testing:** All changes verified with comprehensive test suite (177 tests)

## Version Compatibility

| OpenSSL Version | Status | Notes |
|----------------|--------|-------|
| 1.1.0 - 1.1.1w | ✅ Fully Supported | Primary backward compatibility target |
| 3.0.0 - 3.0.x | ✅ Fully Supported | Modern API usage where appropriate |
| 3.5.x - 3.6.0 | ✅ Supported | Latest features not yet utilized |
| LibreSSL 3.3.6+ | ✅ Supported | Some features unavailable |

## Testing

All deprecation warning handling has been validated with:
- **Test Suite:** 177/177 tests passing
- **Build:** Successful compilation with OpenSSL 3.0.13
- **Runtime:** No functional regressions
- **Compatibility:** Tested across OpenSSL 1.1.x and 3.0.x

## Recommendations

### For Users
- Use the latest OpenSSL version available (3.0.x recommended)
- Deprecation warnings are expected and do not affect functionality
- All critical modules have been reviewed and are safe to use

### For Contributors
- New code should use EVP APIs when possible
- Use pragma directives for unavoidable deprecation warnings
- Add clear documentation explaining why deprecated APIs are retained
- Ensure backward compatibility with OpenSSL 1.1.x
- Run full test suite before submitting PRs

## References

- [OpenSSL 3.0 Migration Guide](https://www.openssl.org/docs/man3.0/man7/migration_guide.html)
- [OpenSSL 3.0 Provider Documentation](https://www.openssl.org/docs/man3.0/man7/provider.html)
- Issue #344: DH module deprecation warnings
- Issue #346: DSA module deprecation warnings  
- Issue #351: SRP module deprecation warnings
- PR #353: Digest module deprecation fixes

## Conclusion

The lua-openssl project has successfully addressed critical deprecation warnings for OpenSSL 3.0 
compatibility while maintaining full backward compatibility with OpenSSL 1.1.x. Remaining warnings 
are in low-level API modules and are expected/acceptable. The project is well-positioned for 
long-term OpenSSL 3.0+ support.
