local lu = require 'luaunit'

local openssl = require 'openssl'
local cms, csr = openssl.cms, openssl.x509.req
local helper = require 'helper'
if not cms then
  print('Skip cms test')
  return
end

TestCMS = {}

-- need OpenSSL build with zlib support

function TestCMS:testCompress()
  local msg = openssl.random(1000)
  local cs = cms.compress(msg, 'zlib')
  if cs then
    local ret = assert(cms.uncompress(cs))
    lu.assertEquals(msg, ret)
    --FIXME:
    --c = cms.compress('data')
    --FIXME:
    --assert(c:bio_new())
    --FIXME:
    --cms.uncompress(c)
  end
end

function TestCMS:setUp()
  self.alg = 'sha1'
  self.cadn = {{commonName = 'CA'},  {C = 'CN'}}
  self.alicedn = {{commonName = 'Alice'},  {C = 'CN'}}
  self.bobdn = {{commonName = 'Bob'},  {C = 'CN'}}

  local ca = helper.get_ca()

  local req, pkey = helper.new_req(self.alicedn)
  local cert = ca:sign(req)
  self.alice = {key = pkey,  cert = cert}

  cert, pkey = assert(helper.sign(self.bobdn))
  self.bob = {key = pkey,  cert = cert}

  self.msg = openssl.hex(openssl.random(128))
  self.digest = 'sha1WithRSAEncryption'
  self.castore = assert(ca:get_store())
end

function TestCMS:testEncrypt()
  local recipts = {self.alice.cert}
  local msg = assert(cms.encrypt(recipts, self.msg))
  local smime = assert(cms.export(msg))
  local ss = assert(cms.read(smime, 'smime'))
  local raw = assert(cms.decrypt(ss, self.alice.key, self.alice.cert))
  lu.assertEquals(raw, self.msg)
end

function TestCMS:testSign()
  local c1 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg, {}))
  local smime = assert(cms.export(c1))
  local msg = assert(cms.verify(c1, {self.bob.cert}, self.castore))
  lu.assertEquals(msg, self.msg)
  msg = assert(cms.verify(c1, {}, self.castore))
  lu.assertEquals(msg, self.msg)
end

function TestCMS:testEncryptedData()
  local key = openssl.random(24)
  local c1 = assert(cms.EncryptedData_encrypt(self.msg, key))
  local smime = assert(cms.export(c1))
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

  c1 = assert(cms.create(self.msg, "sha1"))
  smime = assert(cms.export(c1))
  assert(smime)
  msg = assert(cms.digest_verify(c1))
  lu.assertEquals(msg, self.msg)
end

function TestCMS:testData()
  local c = cms.create()
  assert(c)

  c = cms.create("data")
  assert(c)
  assert(c:type())

  local d = assert(c:export("data", 0, "der"))
  d = cms.read(d, 'der')
  assert(d)
  d = assert(c:export("data", 0, "pem"))
  d = cms.read(d, 'pem')
  assert(d)
  d = assert(c:export("data", 0, "smime"))
  d = cms.read(d, 'smime')
  assert(d)

end

