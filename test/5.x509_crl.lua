local lu = require 'luaunit'

local openssl = require 'openssl'
local crl, csr = openssl.x509.crl, openssl.x509.req

TestCRL = {}
function TestCRL:setUp()
  self.alg = 'sha1'

  self.cadn = openssl.x509.name.new({{commonName = 'CA'},  {C = 'CN'}})
  self.dn = openssl.x509.name.new({{commonName = 'DEMO'},  {C = 'CN'}})

  self.digest = 'sha1WithRSAEncryption'
end

function TestCRL:testNew()
  local pkey = assert(openssl.pkey.new())
  local req = assert(csr.new(self.cadn, pkey))
  local t = req:parse()
  lu.assertEquals(type(t), 'table')

  local cacert = openssl.x509.new(1, -- serialNumber
  req -- copy name and extensions
  )

  cacert:validat(os.time(), os.time() + 3600 * 24 * 365)
  assert(cacert:sign(pkey, cacert)) -- self sign
  lu.assertEquals(cacert:subject(), cacert:issuer())

  local list = assert(crl.new({
    {sn = 1,  time = os.time()},  {sn = 2,  time = os.time()},
    {sn = 3,  time = os.time()},  {sn = 4,  time = os.time()}
  }, cacert, pkey))
  assert(#list == 4)
  -- print_r(list:parse())
  local other = crl.new()
  assert(other:issuer(cacert:issuer()))
  assert(other:version(0))
  assert(other:updateTime(50000000))
  assert(other:lastUpdate(os.time()))
  assert(other:nextUpdate(os.time() + 50000000))

  assert(other:add('21234', os.time()))
  assert(other:add('31234', os.time()))
  assert(other:add('41234', os.time()))
  assert(other:add('11234', os.time()))

  assert(other:sign(pkey, cacert))
  assert(other:verify(cacert))

  assert(other:export())
  t = other:get(0)
  lu.assertIsTable(t)
end

function TestCRL:testRead()
  local dat = [[
-----BEGIN X509 CRL-----
MIIBNDCBnjANBgkqhkiG9w0BAQIFADBFMSEwHwYDVQQKExhFdXJvcGVhbiBJQ0Ut
VEVMIFByb2plY3QxIDAeBgNVBAsTF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05
NzA2MDkxNDQyNDNaFw05NzA3MDkxNDQyNDNaMCgwEgIBChcNOTcwMzAzMTQ0MjU0
WjASAgEJFw05NjEwMDIxMjI5MjdaMA0GCSqGSIb3DQEBAgUAA4GBAH4vgWo2Tej/
i7kbiw4Imd30If91iosjClNpBFwvwUDBclPEeMuYimHbLOk4H8Nofc0fw11+U/IO
KSNouUDcqG7B64oY7c4SXKn+i1MWOb5OJiWeodX3TehHjBlyWzoNMWCnYA8XqFP1
mOKp8Jla1BibEZf14+/HqCi2hnZUiEXh
-----END X509 CRL-----
]]
  local r = crl.read(dat)
  lu.assertIsTable(r:parse())
  -- print_r(r:parse())
  local e = r:export()
  lu.assertEquals(e, dat)
  e = r:export('der')
  local r1 = crl.read(e)
  assert(r:cmp(r1) == (r == r1))
  assert(r == r1)

  lu.assertEquals(r:version(), 0)
  lu.assertEquals(r:issuer():tostring(),
                  '/O=European ICE-TEL Project/OU=Certification Authority')
  lu.assertEquals(r:lastUpdate():toprint(), 'Jun  9 14:42:43 1997 GMT')
  lu.assertEquals(r:nextUpdate():toprint(), 'Jul  9 14:42:43 1997 GMT')
  lu.assertEquals(r:extensions(), nil)
  local l, n = r:updateTime()
  lu.assertEquals(r:lastUpdate(), l)
  lu.assertEquals(r:nextUpdate(), n)

  lu.assertEquals(r:count(), #r)
  lu.assertEquals(#r, 2)
end
