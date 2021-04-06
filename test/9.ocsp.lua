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

  oreq = ocsp.request_new(self.ca.cacert, self.bob.cert:serial())
  assert(oreq)
  assert(type(oreq:export(false)))

  local der = oreq:export(false)
  assert(type(der)=='string')
  --FIXME: crash
  --oreq = ocsp.request_read(der, false)
  --assert(oreq)
  assert(oreq:sign(self.bob.cert, self.bob.key, nil, 0, 'sha256'))
  assert(oreq:sign(self.bob.cert, self.bob.key, {self.bob.cert, self.ca.cert}, 0, 'sha256'))
  der = oreq:export(true)
  assert(type(der)=='string')
  --FIXME: crash
  --oreq = ocsp.request_read(der, true)
  --assert(oreq)
  local t = oreq:parse()
  assert(type(t)=='table')
  oreq = ocsp.request_new(self.ca.cacert, {self.bob.cert, self.alice.cert})
  assert(oreq)

  local ocert, okey = helper.sign(self.ocspdn)

  local resp = ocsp.response_new(oreq, self.ca.cacert, ocert, okey, function(...)
    print(...)
    return true
  end )
  assert(resp)
  der = assert(resp:export(false))
  resp = ocsp.response_read(der, false)

  assert(resp:export(true))
  assert(resp:export(false))
  --FIXME
  pcall(resp.parse, resp)
end

