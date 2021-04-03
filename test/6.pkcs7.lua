local lu = require 'luaunit'

local openssl = require 'openssl'
local pkcs7, csr = openssl.pkcs7, openssl.x509.req
local helper = require 'helper'

TestPKCS7 = {}
function TestPKCS7:setUp()
  self.alg = 'sha1'
  self.dn = {{commonName = 'DEMO'},  {C = 'CN'}}

  self.digest = 'sha1WithRSAEncryption'
end

function TestPKCS7:testNew()
  local ca = helper.get_ca()

  local e = openssl.x509.extension.new_extension(
              {object = 'keyUsage',  value = 'smimesign'}, false)
  assert(e)
  local extensions = {
    {
      object = 'nsCertType',
      value = 'email'
      -- critical = true
    },  {object = 'extendedKeyUsage',  value = 'emailProtection'}
  }
  -- extensions:push(e)

  local cert, pkey = helper.sign(self.dn, extensions)

  local msg = 'abcd'

  local skcert = {cert}
  local p7 = assert(pkcs7.encrypt(msg, skcert))
  local ret = assert(pkcs7.decrypt(p7, cert, pkey))
  lu.assertEquals(msg, ret)
  -------------------------------------
  p7 = assert(pkcs7.sign(msg, cert, pkey))
  assert(p7:export())
  local store = openssl.x509.store.new({ca.cacert})
  ret = assert(p7:verify(skcert, store))
  assert(ret)

  local der = p7:export()
  p7 = openssl.pkcs7.read(der)
  p7:add(ca.cacert)
  p7:add(cert)
  p7:add(ca.crl)
  assert(p7:export())
  assert(p7:parse())
end

function TestPKCS7:testStep()
  local ca = helper.get_ca()

  local extensions = {
    {
      object = 'nsCertType',
      value = 'email'
      -- critical = true
    },  {object = 'extendedKeyUsage',  value = 'emailProtection'}
  }
  local cert, pkey = helper.sign(self.dn, extensions)

  local msg = 'abcd'

  local md = openssl.digest.get('sha1')
  local mdc = md:new()
  mdc:update(msg)
  mdc:update(msg)
  local hash = mdc:data()
  local p7 = assert(openssl.pkcs7.new())
  -- assert(p7:add(cert))
  assert(p7:add_signer(cert, pkey, md))
  local pp7 = p7:sign_digest(hash, pkcs7.DETACHED, true)
  assert(pp7)

  local ret, signer = assert(p7:verify(nil, nil, msg .. msg, pkcs7.DETACHED))
  assert(ret)
  --FIXME:
  --assert(signer)
  ret, signer =
    assert(p7:verify_digest(nil, nil, hash, pkcs7.DETACHED, true))
  assert(ret)
  --FIXME:
  --assert(signer)
end

