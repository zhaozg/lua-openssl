local lu = require("luaunit")

local openssl = require("openssl")
local mac = require("openssl").mac
if not mac then
  return
end

TestMAC = {}
function TestMAC:setUp()
  self.msg = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
  self.alg = "aes-128-cbc"
  self.key = "\x0F\x0E\x0D\x0C\x0B\x0A\x00\x08\x07\x06\x05\x04\x03\x02\x01\x00"
end

function TestMAC:tearDown() end

function TestMAC:testCMAC()
  local a, b, c, err

  openssl.clear_error()
  a, err = mac.ctx(self.alg, self.key)
  if a then
    b = a:final(self.msg)
    lu.assertEquals(b, "21a805600f5a650854142d7ec00a4224")

    -- get the raw binary form from a duplicated context: a finalized
    -- context cannot be fed again (see testFinalized)
    c = assert(a:dup():final(self.msg, true))
    lu.assertEquals(openssl.hex(c), b)
  else
    print("Bugs, " .. err)
  end
end

-- final() consumes the underlying EVP_MAC_CTX: any further update()/final()
-- on the same context must be rejected instead of silently producing a
-- second, meaningless tag. See issue #410.
function TestMAC:testFinalized()
  local a = assert(mac.ctx(self.alg, self.key))
  assert(a:update(self.msg))
  local tag = assert(a:final())
  lu.assertEquals(tag, "21a805600f5a650854142d7ec00a4224")

  -- update() after final() is rejected
  local ok, err = a:update("post-final-data")
  lu.assertNil(ok)
  lu.assertNotNil(err)

  -- final(last_data) after final() is rejected (it would implicitly update)
  ok, err = a:final("post-final-data", true)
  lu.assertNil(ok)
  lu.assertNotNil(err)

  -- even a bare final() is rejected: for CMAC EVP_MAC_final() is destructive
  -- and a second call returns a different, meaningless tag
  ok, err = a:final()
  lu.assertNil(ok)
  lu.assertNotNil(err)

  -- a duplicated finalized context inherits the finalized state
  local d = a:dup()
  ok, err = d:update("x")
  lu.assertNil(ok)
  lu.assertNotNil(err)

  -- a fresh context still works, and a dup of an unfinalized context can
  -- be fed independently
  local fresh = assert(mac.ctx(self.alg, self.key))
  local d2 = fresh:dup()
  assert(d2:update("hello"))
  local t2 = assert(d2:final(true))
  lu.assertEquals(#t2, 16)
  ok, err = d2:update("after")
  lu.assertNil(ok)
  lu.assertNotNil(err)
end

function TestMAC:testHMAC()
  local a = assert(mac.ctx("sha256", self.key))
  assert(a:update("hello "))
  local tag = assert(a:final("world"))
  -- sanity: 64 hex chars = 32-byte SHA-256 HMAC
  lu.assertEquals(#tag, 64)
  local ok, err = a:update("more")
  lu.assertNil(ok)
  lu.assertNotNil(err)
end
