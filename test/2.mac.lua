local lu = require("luaunit")

local openssl = require("openssl")
local mac = require("openssl").mac
if not mac then
  return
end

TestMAC = {}
function TestMAC:setUp()
  -- NB: use string.char()/numeric literals, not \xNN escapes: PUC Lua 5.1
  -- does not support \x hex escapes in string literals (added in 5.2), so
  -- "\x0F" would silently become the 3-char text "x0F" and the CMAC key
  -- would be 48 bytes instead of 16, failing with "invalid key length".
  self.msg = string.char(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
  self.alg = "aes-128-cbc"
  self.key = string.char(0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x00, 0x08,
                         0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00)
end

function TestMAC:tearDown() end

function TestMAC:testCMAC()
  local a, b, c, err

  openssl.clear_error()
  a, err = mac.ctx(self.alg, self.key)
  if a then
    b = a:final(self.msg)
    lu.assertEquals(b, "21a805600f5a650854142d7ec00a4224")

    -- get the raw binary form from a duplicated *fresh* context: the
    -- finalized context itself cannot be fed again (see testFinalized),
    -- and dup() inherits the finalized state of the original
    local fresh = assert(mac.ctx(self.alg, self.key))
    c = assert(fresh:dup():final(self.msg, true))
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
