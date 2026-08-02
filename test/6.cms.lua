local lu = require("luaunit")

local openssl = require("openssl")
local cms, csr = openssl.cms, openssl.x509.req
local helper = require("helper")
if not cms then
  print("Skip cms test")
  return
end

TestCMS = {}

-- need OpenSSL build with zlib support

function TestCMS:testCompress()
  local msg = openssl.random(1000)

  if cms.compression then
    for i = 1, #cms.compression do
      local comp_alg = cms.compression[i]
      local cs, err, code = cms.compress(msg, comp_alg, cms.flags.binary)
      if cs then
        local ret = assert(cms.uncompress(cs))
        lu.assertEquals(msg, ret)
      else
        local tips = "WARNING: %d:%s, maybe openssl without compress support"
        print(string.format(tips, code, err))
      end
    end
  end

  msg = "hello world"
  local cs, err, code = cms.compress(msg)
  if cs then
    local ret = assert(cms.uncompress(cs))
    lu.assertEquals(msg, ret)
  else
    local tips = "WARNING: %d:%s, maybe openssl without compress support"
    print(string.format(tips, code, err))
  end
end

function TestCMS:setUp()
  self.alg = "sha1"
  self.cadn = { { commonName = "CA" }, { C = "CN" } }
  self.alicedn = { { commonName = "Alice" }, { C = "CN" } }
  self.bobdn = { { commonName = "Bob" }, { C = "CN" } }

  local ca = helper.get_ca()

  self.ca = ca

  local req, pkey = helper.new_req(self.alicedn)
  local cert = ca:sign(req)
  self.alice = { key = pkey, cert = cert }

  cert, pkey = assert(helper.sign(self.bobdn))
  self.bob = { key = pkey, cert = cert }

  self.msg = openssl.hex(openssl.random(128))
  self.digest = "sha1WithRSAEncryption"
  self.castore = assert(ca:get_store())

  local c = cms.new()
  assert(c)
end

function TestCMS:testEncrypt()
  local opts = {
    self.alice.cert,
    key = "1234567890abcdef",
    keyid = "aes-128-cbc",
    password = "secret",
  }
  local msg = assert(cms.encrypt(self.msg, opts))
  local smime = assert(cms.export(msg))
  local ss = assert(cms.read(smime, "smime"))
  local raw = assert(cms.decrypt(ss, self.alice.key, self.alice.cert, nil, 0, opts))
  lu.assertEquals(raw, self.msg)
end

function TestCMS:testSign()
  local c1 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg, {}))
  assert(cms.export(c1))
  local msg = assert(cms.verify(c1, { self.bob.cert }, self.castore))
  lu.assertEquals(msg, self.msg)
  msg = assert(cms.verify(c1, {}, self.castore))
  lu.assertEquals(msg, self.msg)
  assert(c1:get_signers()[1] == self.bob.cert)
end

-- add_signers: step-by-step signing on a partial CMS, see issue #412
function TestCMS:testAddSigners()
  -- create a partial CMS without a signer, then add one later
  local c = assert(cms.sign(nil, nil, nil, {}, cms.flags.stream + cms.flags.partial))
  -- add_signers returns the cms object itself for chaining
  local ret = assert(c:add_signers(self.bob.cert, self.bob.key))
  lu.assertEquals(ret, c)
  assert(c:final(self.msg, cms.flags.binary))

  local msg = assert(cms.verify(c, { self.bob.cert }, self.castore))
  lu.assertEquals(msg, self.msg)
  assert(c:get_signers()[1] == self.bob.cert)

  -- second signer can be added as well
  local c2 = assert(cms.sign(nil, nil, nil, {}, cms.flags.stream + cms.flags.partial))
  assert(c2:add_signers(self.bob.cert, self.bob.key))
  assert(c2:add_signers(self.alice.cert, self.alice.key))
  assert(c2:final(self.msg, cms.flags.binary))
  local signers = assert(c2:get_signers())
  lu.assertEquals(#signers, 2)
  msg = assert(cms.verify(c2, { self.bob.cert, self.alice.cert }, self.castore))
  lu.assertEquals(msg, self.msg)
end

-- cms.sign accepts nil for the certs argument, see issue #411
function TestCMS:testSignNoCerts()
  local c1 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg))
  assert(cms.export(c1))
  local msg = assert(cms.verify(c1, { self.bob.cert }, self.castore))
  lu.assertEquals(msg, self.msg)

  -- explicit nil as 4th argument must work too
  local c2 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg, nil))
  msg = assert(cms.verify(c2, { self.bob.cert }, self.castore))
  lu.assertEquals(msg, self.msg)
end

-- methods on an empty cms.new() object must not segfault, see issue #413
function TestCMS:testEmptyObject()
  local c = cms.new()
  -- getters return a sane default instead of crashing
  lu.assertFalse(c:detached())
  lu.assertNil(c:content())
  -- setters/ops return nil, err, code instead of crashing
  local ok, err = c:detached(true)
  lu.assertNil(ok)
  lu.assertNotNil(err)
  ok, err = c:final("hi")
  lu.assertNil(ok)
  lu.assertNotNil(err)
end


function TestCMS:testSignReceipt()
  local c1 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg, { self.ca.cert }))
  assert(c1:add_receipt({ "alice" }, { "bob" }))

  local rc = assert(c1:sign_receipt(self.alice.cert, self.alice.key, { self.ca.cert }, 0))
  assert(rc:verify_receipt(c1, { self.bob.cert }, self.castore, 0))
end

function TestCMS:testEncryptedData()
  local key = openssl.random(16)
  local c1 = assert(cms.EncryptedData_encrypt(self.msg, key))
  assert(cms.export(c1))
  local msg = assert(cms.EncryptedData_decrypt(c1, key))
  lu.assertEquals(msg, self.msg)
end

function TestCMS:testDigest()
  local key = openssl.random(24)
  assert(key)
  local c1 = assert(cms.digest_create(self.msg))
  local smime = assert(cms.export(c1))
  assert(smime)
  local msg = assert(cms.digest_verify(c1))
  lu.assertEquals(msg, self.msg)

  c1 = assert(cms.digest_create(self.msg, "sha1"))
  smime = assert(cms.export(c1))
  assert(smime)
  msg = assert(c1:digest_verify())
  lu.assertEquals(msg, self.msg)

  assert(c1:detached(true))
  assert(c1:detached() == true)
  msg = assert(c1:digest_verify(self.msg))
  lu.assertEquals(msg, self.msg)
end

function TestCMS:testData()
  local c = cms.data("data")
  assert(c)
  assert(c:detached() == false)
  assert(c:type())
  assert(c:data() == "data")
  assert(c:content() == "data")

  local d = assert(c:export("data", 0, "der"))
  assert(cms.read(d, "auto"))
  d = cms.read(d, "der")
  assert(d)
  d = assert(c:export("data", 0, "pem"))
  d = cms.read(d, "pem")
  assert(d)
  d = assert(c:export("data", 0, "smime"))
  d = cms.read(d, "smime")
  assert(d)

  assert(c:detached(true))
  assert(c:detached() == true)
  -- NOTES: deatched not support data
  -- d = assert(c:export("data", 0, "der"))
  -- assert(d)

  c = assert(cms.data("data", cms.flags.stream + cms.flags.partial))
  assert(c:final("aaaa"))
  assert(c:data() == "aaaa")
end
