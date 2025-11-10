local lu = require("luaunit")

local openssl = require("openssl")
local kdf = require("openssl").kdf

TestKDF = {}

function TestKDF:testDerive()
  if kdf.iterator then
    return
  end
  local pwd = "1234567890"
  local salt = "0987654321"
  local md = "sha256"
  local iter = 4096
  local keylen = 32

  local key = assert(kdf.derive(pwd, salt, md, iter, keylen))
  assert(key)
  assert(#key == 32)
end

function TestKDF:testBasic()
  if not kdf.iterator then
    return
  end
  kdf.iterator(function(k)
    assert(k:name())
    assert(k)
    assert(k:provider())
    assert(k:is_a(k:name()))
    --print(k:description())

    local t = k:settable_ctx_params()
    assert(#t > 0)
    t = k:gettable_ctx_params()
    assert(#t > 0)
    assert(k:get_params(t))
  end)
end

function TestKDF:testPBKDF2()
  if not kdf.fetch then
    return
  end

  local pwd = "1234567890"
  local salt = "0987654321" -- getSalt(pwd)
  local pbkdf2 = kdf.fetch("PBKDF2")
  local t = assert(pbkdf2:settable_ctx_params())
  local key = assert(pbkdf2:derive({
    {
      name = "pass",
      data = pwd,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "mac",
      data = "HMAC",
    },
    {
      name = "pkcs5",
      data = 1, -- 0 to enable
    },
    {
      name = "iter",
      data = 128,
    },
  }))
  assert(openssl.hex(key) == "4f3d3828fff90151dd81cef869a0175b")
end

function TestKDF:testPBKDF2CTX()
  if not kdf.fetch then
    return
  end

  local pwd = "1234567890"
  local salt = "0987654321" -- getSalt(pwd)
  local pbkdf2 = kdf.fetch("PBKDF2")
  local ctx = assert(pbkdf2:new())

  local t = ctx:settable_params()
  assert(#t > 0)
  local key = assert(ctx:derive({
    {
      name = "pass",
      data = pwd,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "mac",
      data = "HMAC",
    },
    {
      name = "pkcs5",
      data = 1, -- 0 to enable
    },
    {
      name = "iter",
      data = 128,
    },
  }))
  assert(openssl.hex(key) == "4f3d3828fff90151dd81cef869a0175b")
end

function TestKDF:testHKDF()
  if not kdf.fetch then
    return
  end

  -- Test HKDF key derivation
  local hkdf = kdf.fetch("HKDF")
  assert(hkdf)
  
  -- Test HKDF with SHA256
  local ikm = "input key material"
  local salt = "optional salt"
  local info = "context info"
  
  local key = assert(hkdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = ikm,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "info",
      data = info,
    },
  }, 32))
  
  assert(#key == 32)
  -- Verify it produces consistent output
  local key2 = assert(hkdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = ikm,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "info",
      data = info,
    },
  }, 32))
  assert(key == key2, "HKDF should produce consistent output")
end

function TestKDF:testHKDFWithoutSalt()
  if not kdf.fetch then
    return
  end

  -- Test HKDF without salt (should use zero-filled salt)
  local hkdf = kdf.fetch("HKDF")
  local ikm = "test key material"
  local info = "application context"
  
  local key = assert(hkdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = ikm,
    },
    {
      name = "info",
      data = info,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testSCRYPT()
  if not kdf.fetch then
    return
  end

  -- Test scrypt key derivation
  local scrypt = kdf.fetch("SCRYPT")
  assert(scrypt)
  
  local password = "test password"
  local salt = "random salt"
  
  -- Use lower parameters for faster testing
  local key = assert(scrypt:derive({
    {
      name = "pass",
      data = password,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "n",
      data = 1024, -- N parameter (CPU/memory cost)
    },
    {
      name = "r",
      data = 8, -- block size
    },
    {
      name = "p",
      data = 1, -- parallelization parameter
    },
  }, 32))
  
  assert(#key == 32)
  
  -- Verify consistency
  local key2 = assert(scrypt:derive({
    {
      name = "pass",
      data = password,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "n",
      data = 1024,
    },
    {
      name = "r",
      data = 8,
    },
    {
      name = "p",
      data = 1,
    },
  }, 32))
  assert(key == key2, "SCRYPT should produce consistent output")
end

function TestKDF:testSCRYPTHigherCost()
  if not kdf.fetch then
    return
  end

  -- Test scrypt with higher cost parameters
  local scrypt = kdf.fetch("SCRYPT")
  local password = "secure password"
  local salt = "unique salt value"
  
  local key = assert(scrypt:derive({
    {
      name = "pass",
      data = password,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "n",
      data = 16384, -- Higher N for production use
    },
    {
      name = "r",
      data = 8,
    },
    {
      name = "p",
      data = 1,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testTLS1PRF()
  if not kdf.fetch then
    return
  end

  -- Test TLS1-PRF (TLS 1.0/1.1/1.2 PRF)
  local tls1prf = kdf.fetch("TLS1-PRF")
  assert(tls1prf)
  
  local master_secret = "master secret value"
  local label_and_seed = "key expansion" .. "random data"
  
  local key = assert(tls1prf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "secret",
      data = master_secret,
    },
    {
      name = "seed",
      data = label_and_seed,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testKBKDF()
  if not kdf.fetch then
    return
  end

  -- Test KBKDF (Key-Based Key Derivation Function)
  local kbkdf = kdf.fetch("KBKDF")
  assert(kbkdf)
  
  local key_material = "base key material"
  local context = "derivation context"
  
  local key = assert(kbkdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = key_material,
    },
    {
      name = "salt",
      data = context,
    },
    {
      name = "mode",
      data = "COUNTER",
    },
    {
      name = "mac",
      data = "HMAC",
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testPKCS12KDF()
  if not kdf.fetch then
    return
  end

  -- Test PKCS12KDF (used in PKCS#12 files)
  local pkcs12kdf = kdf.fetch("PKCS12KDF")
  assert(pkcs12kdf)
  
  local password = "test password"
  local salt = "random salt"
  
  local key = assert(pkcs12kdf:derive({
    {
      name = "pass",
      data = password,
    },
    {
      name = "salt",
      data = salt,
    },
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "id",
      data = 1, -- ID for key generation
    },
    {
      name = "iter",
      data = 1000,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testSSKDF()
  if not kdf.fetch then
    return
  end

  -- Test SSKDF (Single Step Key Derivation Function)
  local sskdf = kdf.fetch("SSKDF")
  assert(sskdf)
  
  local shared_secret = "shared secret from key exchange"
  local info = "context information"
  
  local key = assert(sskdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = shared_secret,
    },
    {
      name = "info",
      data = info,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testX963KDF()
  if not kdf.fetch then
    return
  end

  -- Test X963KDF (ANSI X9.63 KDF)
  local x963kdf = kdf.fetch("X963KDF")
  assert(x963kdf)
  
  local shared_secret = "ECDH shared secret value"
  local shared_info = "protocol context info"
  
  local key = assert(x963kdf:derive({
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "secret",
      data = shared_secret,
    },
    {
      name = "info",
      data = shared_info,
    },
  }, 32))
  
  assert(#key == 32)
end

function TestKDF:testKDFErrorHandling()
  if not kdf.fetch then
    return
  end

  -- Test error handling with invalid parameters
  local pbkdf2 = kdf.fetch("PBKDF2")
  
  -- Test with missing required parameter (password)
  -- Note: OpenSSL may return nil instead of throwing an error
  local key = pbkdf2:derive({
    {
      name = "salt",
      data = "salt",
    },
    {
      name = "iter",
      data = 100,
    },
  }, 32)
  -- If it doesn't error, it should at least return nil
  assert(not key or #key == 0, "Should fail or return empty without password")
end

function TestKDF:testKDFContextReuse()
  if not kdf.fetch then
    return
  end

  -- Test KDF context reuse with reset
  local pbkdf2 = kdf.fetch("PBKDF2")
  local ctx = assert(pbkdf2:new())
  
  local params = {
    {
      name = "pass",
      data = "password1",
    },
    {
      name = "salt",
      data = "salt1",
    },
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "iter",
      data = 1000,
    },
  }
  
  local key1 = assert(ctx:derive(params, 32))
  
  -- Reset and derive with different parameters
  ctx:reset()
  params[1].data = "password2"
  params[2].data = "salt2"
  
  local key2 = assert(ctx:derive(params, 32))
  
  assert(key1 ~= key2, "Different inputs should produce different keys")
end

function TestKDF:testKDFDifferentSizes()
  if not kdf.fetch then
    return
  end

  -- Test deriving keys of different sizes
  local hkdf = kdf.fetch("HKDF")
  
  local params = {
    {
      name = "digest",
      data = "SHA2-256",
    },
    {
      name = "key",
      data = "input key",
    },
    {
      name = "salt",
      data = "salt",
    },
    {
      name = "info",
      data = "info",
    },
  }
  
  -- Test various key sizes
  for _, size in ipairs({16, 32, 48, 64}) do
    local key = assert(hkdf:derive(params, size))
    assert(#key == size, "Key size should match requested size")
  end
end
