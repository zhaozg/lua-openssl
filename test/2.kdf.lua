local lu = require 'luaunit'

local openssl = require 'openssl'
local kdf = require'openssl'.kdf
if not kdf then
  return
end

TestKDF = {}

function TestKDF:testBasic()
  kdf.iterator(function(k)
    assert(k:name())
    assert(k)
    assert(k:provider())
    assert(k:is_a(k:name()))
    --print(k:description())

    local t = k:settable_ctx_params()
    assert(#t>0)
    t = k:gettable_ctx_params()
    assert(#t>0)
    assert(k:get_params(t))
  end)
end

function TestKDF:testPBKDF2()
  local pwd = "1234567890";
  local salt = "0987654321" -- <D-s>getSalt(pwd)
  local pbkdf2 = kdf.fetch('PBKDF2')
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
  assert(openssl.hex(key)=='4f3d3828fff90151dd81cef869a0175b')
end

function TestKDF:testPBKDF2CTX()
  local pwd = "1234567890";
  local salt = "0987654321" -- <D-s>getSalt(pwd)
  local pbkdf2 = kdf.fetch('PBKDF2')
  local ctx = assert(pbkdf2:new())

  local t = ctx:settable_params()
  assert(#t>0)
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
  assert(openssl.hex(key)=='4f3d3828fff90151dd81cef869a0175b')
end
