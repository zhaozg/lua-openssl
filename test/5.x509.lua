local lu = require 'luaunit'
local openssl = require 'openssl'

local csr, x509 = openssl.x509.req, openssl.x509

local helper = require('helper')

TestX509 = {}
function TestX509:setUp()
  self.alg = 'sha1'

  self.dn = {{commonName = 'DEMO'},  {C = 'CN'}}

  self.digest = 'sha1WithRSAEncryption'
end

function TestX509:testNew()
  local ca = helper.get_ca()
  local cert, pkey = helper.sign(self.dn)

  lu.assertEquals(ca.cacert:subject(), cert:issuer())
  assert(ca.cacert:parse().ca, 'invalid ca certificate')

  local c = cert:pubkey():encrypt('abcd')
  local d = pkey:decrypt(c)
  assert(d == 'abcd')
  assert(cert:check(pkey), 'self sign check failed')
  local store = assert(ca:get_store())
  assert(cert:check(store))
end

function TestX509:testIO()
  local raw_data = [=[
-----BEGIN CERTIFICATE-----
MIIBoDCCAUoCAQAwDQYJKoZIhvcNAQEEBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV
BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD
VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw05NzA5MDkwMzQxMjZa
Fw05NzEwMDkwMzQxMjZaMF4xCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0
YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFzAVBgNVBAMT
DkVyaWMgdGhlIFlvdW5nMFEwCQYFKw4DAgwFAANEAAJBALVEqPODnpI4rShlY8S7
tB713JNvabvn6Gned7zylwLLiXQAo/PAT6mfdWPTyCX9RlId/Aroh1ou893BA32Q
sggwDQYJKoZIhvcNAQEEBQADQQCU5SSgapJSdRXJoX+CpCvFy+JVh9HpSjCpSNKO
19raHv98hKAUJuP9HyM+SUsffO6mAIgitUaqW8/wDMePhEC3
-----END CERTIFICATE-----
]=]

  local x = assert(x509.read(raw_data))

  local t = x:parse()
  lu.assertEquals(type(t), 'table')
  assert(x:pubkey())

  lu.assertEquals(x:version(), 0)
  assert(x:notbefore())
  assert(x:notafter())

  lu.assertIsNil(x:extensions())

  assert(x:subject())
  assert(x:issuer())

  x = x509.purpose()
  assert(#x == 9)
end
