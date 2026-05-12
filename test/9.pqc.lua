--[[
PQC (Post-Quantum Cryptography) Test Suite

Tests for Post-Quantum Cryptography algorithm support in lua-openssl.
These tests verify that PQC algorithms can be discovered, generated,
loaded, and used when the underlying OpenSSL 3.x has PQC provider support
(e.g., OQS provider).

Note: Most systems will not have PQC providers installed, so these tests
are designed to gracefully skip when PQC is not available.
]]

local lu = require('luaunit')
local openssl = require('openssl')
local pkey = openssl.pkey

-- Helper: check if we're on OpenSSL 3.x (not LibreSSL)
local function is_openssl35()
  local _, _, ssl_ver = openssl.version()
  local _, _, ssl_num = openssl.version(true)
  return ssl_num >= 0x30500000 and not ssl_ver:match("LibreSSL")
end

-- Helper: check if a specific algorithm is available for key generation
local function is_alg_available(alg_name)
  -- Try to create a key via EVP_PKEY_CTX
  local ok, key = pcall(pkey.new, alg_name)
  return ok and key ~= nil
end

if not is_openssl35() then
  print("  Skipping: Not OpenSSL 3.x")
  return
end

-- Known PQC algorithm names to probe
local PQC_ALGORITHMS = {
  -- Dilithium / ML-DSA (FIPS 204)
  "DILITHIUM2", "ML-DSA-44",
  "DILITHIUM3", "ML-DSA-65",
  "DILITHIUM5", "ML-DSA-87",
  -- Kyber / ML-KEM (FIPS 203)
  "KYBER512", "ML-KEM-512",
  "KYBER768", "ML-KEM-768",
  "KYBER1024", "ML-KEM-1024",
  -- Falcon
  "FALCON512",
  "FALCON1024",
  -- SPHINCS+ / SLH-DSA (FIPS 205)
  "SPHINCS-SHA256",
  "SPHINCS-SHAKE256",
}

-- Test suite for PQC algorithm detection
TestPQCDetection = {}

function TestPQCDetection:test_openssl_version_check()
  -- Verify we can detect OpenSSL 3.x
  local _, lua_ver, ssl_ver = openssl.version()
  local _, lua_num, ssl_num = openssl.version(true)

  lu.assertNotNil(ssl_ver, "Should have SSL version string")
  lu.assertNotNil(ssl_num, "Should have SSL version number")
end

function TestPQCDetection:test_provider_module_available()
  -- Provider module should be available on OpenSSL 3.x
  if is_openssl35() then
    lu.assertNotNil(openssl.provider, "Provider module should exist on OpenSSL 3.x")
    if openssl.provider and not openssl.provider._error then
      print("  Provider module is functional")
    end
  else
    print("  Skipping: Not OpenSSL 3.x")
  end
end

function TestPQCDetection:test_probe_pqc_algorithms()
  -- Probe for available PQC algorithms and report
  local available = {}

  for _, alg in ipairs(PQC_ALGORITHMS) do
    if is_alg_available(alg) then
      available[#available + 1] = alg
    end
  end

  if #available > 0 then
    print(string.format("  Found %d PQC algorithm(s):", #available))
    for _, name in ipairs(available) do
      print("    - " .. name)
    end
  else
    print("  No PQC algorithms detected (OQS provider may not be loaded)")
    print("  To test PQC, install liboqs and OQS provider, then load it:")
    print("    local prov = openssl.provider.load('oqsprovider')")
  end

  -- This test doesn't assert - it's informational
  lu.assertTrue(true, "Probe completed")
end

-- Test suite for PQC key operations (only runs if PQC algorithms available)
TestPQCOperations = {}

function TestPQCOperations:setUp()
  -- Find first available PQC signature algorithm
  self.sig_alg = nil
  self.kem_alg = nil

  for _, alg in ipairs(PQC_ALGORITHMS) do
    if is_alg_available(alg) then
      local name_upper = alg:upper()
      -- Signature algorithms: DILITHIUM/ML-DSA, FALCON, SPHINCS/SLH-DSA
      if name_upper:match("DILITHIUM") or name_upper:match("ML%-DSA") or name_upper:match("FALCON") or name_upper:match("SPHINCS") or name_upper:match("SLH%-DSA") then
        if not self.sig_alg then
          self.sig_alg = alg
        end
      end
      -- KEM algorithms: KYBER, ML-KEM
      if name_upper:match("KYBER") or name_upper:match("ML%-KEM") then
        if not self.kem_alg then
          self.kem_alg = alg
        end
      end
    end
  end
end

function TestPQCOperations:test_generate_pqc_key()
  lu.assertNotNil(self.sig_alg, "Need at least one PQC signature algorithm available")
  if not self.sig_alg then return end

  -- Generate a PQC key pair
  local key = pkey.new(self.sig_alg)
  lu.assertNotNil(key, "Should generate " .. self.sig_alg .. " key")
  lu.assertTrue(key:is_private(), "Generated key should be private")

  -- Get public key
  local pub = pkey.get_public(key)
  lu.assertNotNil(pub, "Should get public key")
  lu.assertFalse(pub:is_private(), "Public key should not be private")

  print(string.format("  Generated %s key pair successfully", self.sig_alg))
end

function TestPQCOperations:test_pqc_sign_and_verify()
  lu.assertNotNil(self.sig_alg, "Need at least one PQC signature algorithm available")
  if not self.sig_alg then return end

  local key = pkey.new(self.sig_alg)
  lu.assertNotNil(key, "Should generate key")

  local pub = pkey.get_public(key)
  lu.assertNotNil(pub, "Should get public key")

  -- Sign a message
  local msg = "Hello, Post-Quantum World!"
  local sig = pkey.sign(key, msg)
  lu.assertNotNil(sig, "Should sign message")
  lu.assertTrue(#sig > 0, "Signature should not be empty")

  -- Verify signature
  local ok = pkey.verify(pub, msg, sig)
  lu.assertTrue(ok, "Should verify signature")

  -- Verify with wrong message should fail
  local wrong_ok = pkey.verify(pub, "Wrong message", sig)
  lu.assertFalse(wrong_ok, "Should reject wrong message")

  print(string.format("  %s sign/verify test passed (sig len: %d bytes)", self.sig_alg, #sig))
end

function TestPQCOperations:test_pqc_key_export_import()
  lu.assertNotNil(self.sig_alg, "Need at least one PQC signature algorithm available")
  if not self.sig_alg then return end

  local key = pkey.new(self.sig_alg)
  lu.assertNotNil(key, "Should generate key")

  -- Export private key as PEM
  local pem_priv = key:export("pem", false)
  lu.assertNotNil(pem_priv, "Should export private key as PEM")
  lu.assertTrue(#pem_priv > 0, "PEM export should not be empty")

  -- Export public key as PEM
  local pub = pkey.get_public(key)
  local pem_pub = pub:export("pem", false)
  lu.assertNotNil(pem_pub, "Should export public key as PEM")

  -- Re-import private key
  local key2 = pkey.read(pem_priv, true)
  lu.assertNotNil(key2, "Should re-import private key from PEM")
  lu.assertTrue(key2:is_private(), "Re-imported key should be private")

  -- Re-import public key
  local pub2 = pkey.read(pem_pub, false)
  lu.assertNotNil(pub2, "Should re-import public key from PEM")
  lu.assertFalse(pub2:is_private(), "Re-imported public key should not be private")

  -- Test sign/verify with re-imported keys
  local msg = "Export-Import test message"
  local sig = pkey.sign(key2, msg)
  lu.assertNotNil(sig, "Should sign with re-imported key")
  local ok = pkey.verify(pub2, msg, sig)
  lu.assertTrue(ok, "Should verify with re-imported public key")

  -- Export as DER
  local der_pub = pub:export("der", false)
  lu.assertNotNil(der_pub, "Should export public key as DER")
  lu.assertTrue(#der_pub > 0, "DER export should not be empty")

  -- Re-import from DER
  local pub3 = pkey.read(der_pub, false, "der")
  lu.assertNotNil(pub3, "Should re-import public key from DER")

  print(string.format("  %s export/import test passed", self.sig_alg))
end

function TestPQCOperations:test_pqc_key_parse()
  lu.assertNotNil(self.sig_alg, "Need at least one PQC signature algorithm available")
  if not self.sig_alg then return end

  local key = pkey.new(self.sig_alg)
  lu.assertNotNil(key, "Should generate key")

  -- Parse key info
  local info = key:parse()
  lu.assertNotNil(info, "Should parse key info")
  lu.assertEquals(type(info), 'table', "Parse result should be a table")

  -- Should have basic fields
  lu.assertTrue(info.bits ~= nil, "Should have bits field")
  lu.assertTrue(info.size ~= nil, "Should have size field")
  lu.assertTrue(info.type ~= nil, "Should have type field")

  print(string.format("  %s parse: type=%s, bits=%d, size=%d",
    self.sig_alg, tostring(info.type), info.bits or 0, info.size or 0))

  -- Parse public key too
  local pub = pkey.get_public(key)
  local pub_info = pub:parse()
  lu.assertNotNil(pub_info, "Should parse public key info")
  lu.assertEquals(pub_info.bits, info.bits, "Public key bits should match")
end

-- Test suite for provider-based PQC loading
TestPQCProvider = {}

function TestPQCProvider:test_load_oqs_provider()
  -- Try to load OQS provider if available
  if not is_openssl35() then
    print("  Skipping: Requires OpenSSL 3.x")
    return
  end

  if not openssl.provider or openssl.provider._error then
    print("  Skipping: Provider module not available")
    return
  end

  -- Try to load OQS provider (may not be installed)
  local prov, err = openssl.provider.load('oqsprovider')
  if prov then
    print("  OQS provider loaded successfully")
    lu.assertEquals(prov:name(), 'oqsprovider', "Provider name should be 'oqsprovider'")

    -- Now probe for PQC algorithms
    local count = 0
    for _, alg in ipairs(PQC_ALGORITHMS) do
      if is_alg_available(alg) then
        count = count + 1
      end
    end
    print(string.format("  Found %d PQC algorithms after loading OQS provider", count))

    -- Clean up
    prov:unload()
  else
    print("  OQS provider not available (install liboqs and OQS provider to test)")
  end
end

-- Test suite for edge cases
TestPQCEdgeCases = {}

function TestPQCEdgeCases:test_unknown_algorithm_error()
  -- Should get a proper error for unknown algorithm
  local ok, err = pcall(pkey.new, "NONEXISTENT_PQC_ALG_12345")
  lu.assertFalse(ok, "Should fail for unknown algorithm")
  if not ok then
    lu.assertTrue(type(err) == 'string', "Error should be a string")
    print("  Error for unknown algorithm: " .. tostring(err))
  end
end

function TestPQCEdgeCases:test_read_invalid_pqc_pem()
  -- Reading invalid PEM should fail gracefully
  local invalid_pem = "-----BEGIN PUBLIC KEY-----\nINVALIDDATA\n-----END PUBLIC KEY-----"
  local ok, err = pcall(pkey.read, invalid_pem, false)
  -- Should either return nil or throw an error
  if not ok then
    lu.assertTrue(type(err) == 'string', "Error should be a string")
  end
  print("  Invalid PEM handling: OK")
end

-- Test suite for KEM (Key Encapsulation Mechanism) operations
TestPQCKEM = {}

function TestPQCKEM:setUp()
  -- Find first available KEM algorithm
  self.kem_alg = nil

  for _, alg in ipairs(PQC_ALGORITHMS) do
    if is_alg_available(alg) then
      local name_upper = alg:upper()
      if name_upper:match("KYBER") or name_upper:match("ML%-KEM") then
        if not self.kem_alg then
          self.kem_alg = alg
        end
      end
    end
  end
end

function TestPQCKEM:test_kem_key_generation()
  lu.assertNotNil(self.kem_alg, "Need at least one KEM algorithm available")
  if not self.kem_alg then return end

  local key = pkey.new(self.kem_alg)
  lu.assertNotNil(key, "Should generate " .. self.kem_alg .. " key")
  lu.assertTrue(key:is_private(), "Generated KEM key should be private")

  local pub = pkey.get_public(key)
  lu.assertNotNil(pub, "Should get public KEM key")
  lu.assertFalse(pub:is_private(), "Public KEM key should not be private")

  print(string.format("  Generated %s KEM key pair successfully", self.kem_alg))
end

function TestPQCKEM:test_kem_encapsulate_decapsulate()
  lu.assertNotNil(self.kem_alg, "Need at least one KEM algorithm available")
  if not self.kem_alg then return end

  -- Generate KEM key pair
  local key = pkey.new(self.kem_alg)
  lu.assertNotNil(key, "Should generate key")

  local pub = pkey.get_public(key)
  lu.assertNotNil(pub, "Should get public key")

  -- Encapsulate: create a shared secret with the public key
  local ct, ss1 = pkey.encapsulate(pub)
  if ct then
    lu.assertTrue(#ct > 0, "Ciphertext should not be empty")
    print(string.format("  %s encapsulate: ct=%d bytes, ss=%d bytes",
      self.kem_alg, #ct, #ss1 or 0))

    -- Decapsulate: recover the shared secret with the private key
    if ss1 and #ss1 > 0 then
      local ss2 = pkey.decapsulate(key, ct)
      lu.assertNotNil(ss2, "Should decapsulate shared secret")
      lu.assertEquals(ss1, ss2, "Shared secrets should match")
      print(string.format("  %s encapsulate/decapsulate round-trip passed", self.kem_alg))
    end
  else
    print(string.format("  %s encapsulate not yet supported (KEM API may need provider update)", self.kem_alg))
  end
end

function TestPQCKEM:test_kem_key_export_import()
  lu.assertNotNil(self.kem_alg, "Need at least one KEM algorithm available")
  if not self.kem_alg then return end

  local key = pkey.new(self.kem_alg)
  lu.assertNotNil(key, "Should generate key")

  -- Export private key as PEM
  local pem_priv = key:export("pem", false)
  lu.assertNotNil(pem_priv, "Should export private key as PEM")

  -- Export public key as PEM
  local pub = pkey.get_public(key)
  local pem_pub = pub:export("pem", false)
  lu.assertNotNil(pem_pub, "Should export public key as PEM")

  -- Re-import and test encapsulate/decapsulate
  local key2 = pkey.read(pem_priv, true)
  lu.assertNotNil(key2, "Should re-import private key")

  local pub2 = pkey.read(pem_pub, false)
  lu.assertNotNil(pub2, "Should re-import public key")

  -- Test with re-imported keys
  local ct, ss1 = pkey.encapsulate(pub2)
  if ct and ss1 and #ss1 > 0 then
    local ss2 = pkey.decapsulate(key2, ct)
    lu.assertNotNil(ss2, "Should decapsulate with re-imported key")
    lu.assertEquals(ss1, ss2, "Shared secrets should match after re-import")
    print(string.format("  %s KEM export/import round-trip passed", self.kem_alg))
  end
end

