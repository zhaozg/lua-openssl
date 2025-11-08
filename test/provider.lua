local lu = require('luaunit')
local openssl = require('openssl')

-- Check if provider module is available (OpenSSL 3.0+ and not LibreSSL)
if not openssl.provider then
  print("\n" .. string.rep("=", 60))
  print("Provider API Test Skipped")
  print(string.rep("=", 60))
  print("Reason: Provider API requires OpenSSL 3.0 or later")
  print("        (not available in LibreSSL)")
  print("\nCurrent OpenSSL version:")
  local version_str, lua_ver, ssl_ver = openssl.version()
  print("  " .. ssl_ver)
  print("\nProvider tests will be skipped.")
  print(string.rep("=", 60) .. "\n")
  os.exit(0)
end

-- Additional check: verify provider module is actually functional
if openssl.provider._error then
  print("\n" .. string.rep("=", 60))
  print("Provider API Test Skipped")
  print(string.rep("=", 60))
  print("Reason: " .. openssl.provider._error)
  print("\nCurrent OpenSSL version:")
  local version_str, lua_ver, ssl_ver = openssl.version()
  print("  " .. ssl_ver)
  print("\nProvider tests will be skipped.")
  print(string.rep("=", 60) .. "\n")
  os.exit(0)
end

local provider = openssl.provider

TestProvider = {}

function TestProvider:setUp()
  -- Clean up any previously loaded test providers
  collectgarbage('collect')
end

function TestProvider:tearDown()
  collectgarbage('collect')
end

function TestProvider:test_load_default_provider()
  print("\n=== Testing load default provider ===")
  local prov = provider.load('default')
  
  lu.assertNotNil(prov, "Should load default provider")
  lu.assertEquals(type(prov), 'userdata', "Provider should be userdata")
  
  print("✓ Default provider loaded successfully")
end

function TestProvider:test_provider_name()
  print("\n=== Testing provider name ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  local name = prov:name()
  lu.assertNotNil(name, "Provider should have a name")
  lu.assertEquals(name, 'default', "Name should be 'default'")
  
  print("✓ Provider name:", name)
end

function TestProvider:test_provider_available()
  print("\n=== Testing provider availability ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  local available = prov:available()
  lu.assertTrue(available, "Default provider should be available")
  
  print("✓ Default provider is available:", available)
end

function TestProvider:test_provider_get_params()
  print("\n=== Testing provider parameters ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  -- Try to get some common parameters
  local params = prov:get_params({'name', 'version', 'buildinfo'})
  lu.assertNotNil(params, "Should return params table")
  lu.assertEquals(type(params), 'table', "Params should be a table")
  
  print("✓ Provider parameters retrieved:")
  for k, v in pairs(params) do
    print("  ", k, "=", v)
  end
end

function TestProvider:test_provider_self_test()
  print("\n=== Testing provider self-test ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  local result = prov:self_test()
  lu.assertNotNil(result, "Self-test should return a result")
  lu.assertEquals(type(result), 'boolean', "Self-test result should be boolean")
  
  print("✓ Provider self-test result:", result)
end

function TestProvider:test_load_legacy_provider()
  print("\n=== Testing load legacy provider ===")
  -- Legacy provider might not be available on all systems
  local prov, err = provider.load('legacy')
  
  if prov then
    lu.assertNotNil(prov, "Legacy provider loaded")
    local name = prov:name()
    lu.assertEquals(name, 'legacy', "Name should be 'legacy'")
    print("✓ Legacy provider loaded successfully")
    
    -- Test unload
    local unload_result = prov:unload()
    lu.assertNotNil(unload_result, "Unload should return a result")
    print("✓ Legacy provider unloaded:", unload_result)
  else
    print("⚠ Legacy provider not available on this system")
    print("  Error:", err or "unknown")
  end
end

function TestProvider:test_load_fips_provider()
  print("\n=== Testing load FIPS provider ===")
  -- FIPS provider might not be available on all systems
  local prov, err = provider.load('fips')
  
  if prov then
    lu.assertNotNil(prov, "FIPS provider loaded")
    local name = prov:name()
    lu.assertEquals(name, 'fips', "Name should be 'fips'")
    print("✓ FIPS provider loaded successfully")
    
    -- Test FIPS self-test
    local self_test = prov:self_test()
    print("✓ FIPS provider self-test:", self_test)
  else
    print("⚠ FIPS provider not available on this system")
    print("  Error:", err or "unknown")
  end
end

function TestProvider:test_provider_get()
  print("\n=== Testing provider get (without loading) ===")
  -- Default provider should already be loaded
  local prov = provider.get('default')
  
  if prov then
    lu.assertNotNil(prov, "Should get default provider")
    local name = prov:name()
    lu.assertEquals(name, 'default', "Name should be 'default'")
    print("✓ Got default provider without explicit load")
  else
    print("⚠ Default provider not pre-loaded")
  end
end

function TestProvider:test_provider_list()
  print("\n=== Testing provider list ===")
  local providers = provider.list()
  
  lu.assertNotNil(providers, "Should return providers list")
  lu.assertEquals(type(providers), 'table', "Providers should be a table")
  lu.assertTrue(#providers > 0, "Should have at least one provider")
  
  print("✓ Available providers:")
  for i, name in ipairs(providers) do
    print("  ", i, name)
  end
end

function TestProvider:test_provider_tostring()
  print("\n=== Testing provider tostring ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  local str = tostring(prov)
  lu.assertNotNil(str, "tostring should return a value")
  lu.assertTrue(string.find(str, 'openssl.provider') ~= nil, 
                "String should contain 'openssl.provider'")
  lu.assertTrue(string.find(str, 'default') ~= nil, 
                "String should contain provider name")
  
  print("✓ Provider string representation:", str)
end

function TestProvider:test_load_with_retain()
  print("\n=== Testing load provider with retain flag ===")
  local prov = provider.load('default', true)
  
  lu.assertNotNil(prov, "Should load default provider with retain")
  local name = prov:name()
  lu.assertEquals(name, 'default', "Name should be 'default'")
  
  print("✓ Provider loaded with retain flag")
end

function TestProvider:test_load_invalid_provider()
  print("\n=== Testing load invalid provider ===")
  local prov, err = provider.load('nonexistent_provider_xyz')
  
  lu.assertNil(prov, "Should not load non-existent provider")
  if err then
    print("✓ Properly failed to load invalid provider")
    print("  Error:", err)
  else
    print("✓ Properly failed to load invalid provider (no error message)")
  end
end

function TestProvider:test_multiple_providers()
  print("\n=== Testing multiple providers ===")
  local prov1 = provider.load('default')
  local prov2 = provider.load('default')
  
  lu.assertNotNil(prov1, "First load should succeed")
  lu.assertNotNil(prov2, "Second load should succeed")
  
  -- Both should be usable
  lu.assertEquals(prov1:name(), 'default', "First provider name")
  lu.assertEquals(prov2:name(), 'default', "Second provider name")
  
  print("✓ Multiple provider instances work correctly")
end

function TestProvider:test_provider_with_digest()
  print("\n=== Testing provider with digest operations ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  -- Test that digest operations work with loaded provider
  local digest = openssl.digest.get('sha256')
  lu.assertNotNil(digest, "Should get sha256 digest")
  
  local data = "Hello, OpenSSL Provider!"
  local hash = digest:digest(data)
  lu.assertNotNil(hash, "Should compute hash")
  lu.assertEquals(#hash, 32, "SHA256 should produce 32 bytes")
  
  print("✓ Digest operations work with provider loaded")
  print("  Hash:", openssl.hex(hash))
end

function TestProvider:test_provider_with_cipher()
  print("\n=== Testing provider with cipher operations ===")
  local prov = provider.load('default')
  lu.assertNotNil(prov, "Should load default provider")
  
  -- Test that cipher operations work with loaded provider
  local cipher = openssl.cipher.get('aes-256-cbc')
  lu.assertNotNil(cipher, "Should get aes-256-cbc cipher")
  
  local key = string.rep('k', 32)  -- 256-bit key
  local iv = string.rep('i', 16)   -- 128-bit IV
  local plaintext = "Secret message with provider"
  
  local ciphertext = cipher:encrypt(plaintext, key, iv)
  lu.assertNotNil(ciphertext, "Should encrypt")
  
  local decrypted = cipher:decrypt(ciphertext, key, iv)
  lu.assertEquals(decrypted, plaintext, "Decrypted should match plaintext")
  
  print("✓ Cipher operations work with provider loaded")
end

-- Test suite for OpenSSL 3.0+ specific features
TestProviderAdvanced = {}

function TestProviderAdvanced:test_base_provider()
  print("\n=== Testing base provider (OpenSSL 3.0+) ===")
  local prov, err = provider.load('base')
  
  if prov then
    lu.assertNotNil(prov, "Base provider loaded")
    print("✓ Base provider available:", prov:name())
  else
    print("⚠ Base provider not available")
    print("  Error:", err or "unknown")
  end
end

function TestProviderAdvanced:test_null_provider()
  print("\n=== Testing null provider (OpenSSL 3.0+) ===")
  local prov, err = provider.load('null')
  
  if prov then
    lu.assertNotNil(prov, "Null provider loaded")
    print("✓ Null provider available:", prov:name())
  else
    print("⚠ Null provider not available")
    print("  Error:", err or "unknown")
  end
end

-- Performance test
TestProviderPerformance = {}

function TestProviderPerformance:test_provider_load_performance()
  print("\n=== Testing provider load performance ===")
  local iterations = 100
  local start_time = os.clock()
  
  for i = 1, iterations do
    local prov = provider.load('default')
    if prov then
      prov:unload()
    end
  end
  
  local end_time = os.clock()
  local elapsed = end_time - start_time
  local avg_time = elapsed / iterations * 1000  -- Convert to milliseconds
  
  print(string.format("✓ Loaded/unloaded provider %d times in %.3f seconds", 
                      iterations, elapsed))
  print(string.format("  Average time per operation: %.3f ms", avg_time))
  
  lu.assertTrue(avg_time < 100, "Average load time should be reasonable")
end

-- Run tests
print("\n" .. string.rep("=", 60))
print("OpenSSL Provider API Test Suite")
print(string.rep("=", 60))

local runner = lu.LuaUnit.new()
runner:setOutputType("text")
os.exit(runner:runSuite())
