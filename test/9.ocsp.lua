local lu = require 'luaunit'
local openssl = require 'openssl'
local helper = require 'helper'
local ocsp = openssl.ocsp
if ocsp == nil then
  print('Skip test srp')
  return
end

TestOCSP = {}

function TestOCSP:setUp()
  self.ca = helper.get_ca()
  self.alicedn = {{commonName = 'Alice'},  {C = 'CN'}}
  self.bobdn = {{commonName = 'Bob'},  {C = 'CN'}}
  self.ocspdn = {{commonName = 'OCSP'},  {C = 'CN'}}
end

function TestOCSP:tearDown()
end

function TestOCSP:testAll()
  local req, pkey = helper.new_req(self.alicedn)
  local cert = self.ca:sign(req)
  self.alice = {key = pkey,  cert = cert}

  cert, pkey = assert(helper.sign(self.bobdn))
  self.bob = {key = pkey,  cert = cert}

  local oreq = ocsp.request_new(self.ca.cacert, {self.bob.cert:serial(), self.alice.cert:serial()})
  assert(oreq)

  oreq = ocsp.request_new(self.ca.cacert, self.bob.cert:serial())
  assert(oreq)
  assert(type(oreq:export(true)))

  assert(oreq:add_ext(openssl.x509.extension.new_extension({
    object = 'subjectAltName',
    value = "IP:192.168.0.1"
  })))
  assert(type(oreq:export(true))=='string')
  assert(type(oreq:parse().extensions)=='table')

  oreq = ocsp.request_new(self.ca.cacert, self.bob.cert)
  assert(oreq)
  assert(type(oreq:export(false)))

  local der = oreq:export(false)
  assert(type(der)=='string')

  -- avoid resign a ocsp request object, or memleaks
  oreq = assert(ocsp.request_read(der, false))
  assert(oreq:sign(self.bob.cert, self.bob.key))
  oreq = assert(ocsp.request_read(der, false))
  assert(oreq:sign(self.bob.cert, self.bob.key, {self.ca.cert}))
  oreq = assert(ocsp.request_read(der, false))
  assert(oreq:sign(self.bob.cert, self.bob.key, {self.ca.cert}, 0))
  oreq = assert(ocsp.request_read(der, false))
  assert(oreq:sign(self.bob.cert, self.bob.key, { self.ca.cert}, 0, 'sha256'))
  der = oreq:export(true)
  assert(type(der)=='string')

  oreq = ocsp.request_read(der, true)
  assert(oreq)
  local t = oreq:parse()
  assert(type(t)=='table')
  oreq = ocsp.request_new(self.ca.cacert, {self.bob.cert, self.alice.cert})
  assert(oreq)

  local ocert, okey = helper.sign(self.ocspdn)

  local sn1 = tostring(self.bob.cert:serial())
  local sn2 = tostring(self.alice.cert:serial())
  local resp = ocsp.response_new(oreq, self.ca.cacert, ocert, okey, {
      [sn1] = {
        reovked = true,
        revoked_time = os.time(),
        reason = 0
      },
      [sn1] = {
        reovked = true,
        revoked_time = os.time(),
        reason = 'AACompromise'
      }
  })
  assert(resp)
  der = assert(resp:export(false))
  resp = ocsp.response_read(der, false)

  assert(resp:export(true))
  assert(resp:export(false))

  -- FIXME: do it
  -- local t= resp:parse()
  -- assert(type(t)=='table')
end

