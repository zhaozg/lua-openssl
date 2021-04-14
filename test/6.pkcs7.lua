local lu = require 'luaunit'

local openssl = require 'openssl'
local pkcs7 = openssl.pkcs7
local helper = require 'helper'

TestPKCS7 = {}
function TestPKCS7:setUp()
  self.alg = 'sha1'
  self.dn = {{commonName = 'DEMO'},  {C = 'CN'}}

  self.digest = 'sha1WithRSAEncryption'
end

function TestPKCS7:testNew()
  local ca = helper.get_ca()
  local store = ca:get_store()
  assert(store:trust(true))
  store:add(ca.cacert)
  store:add(ca.crl)

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
  assert(p7:parse())
  -------------------------------------
  p7 = assert(pkcs7.sign(msg, cert, pkey))
  assert(p7:export())
  ret = assert(p7:verify(skcert, store))
  assert(ret==msg)
  assert(p7:parse())

  p7 = assert(pkcs7.sign(msg, cert, pkey, nil, openssl.pkcs7.DETACHED))
  assert(p7:export())
  ret = assert(p7:verify(skcert, store, msg, openssl.pkcs7.DETACHED))
  assert(type(ret)=='boolean')
  assert(ret)
  assert(p7:parse())

  local der = assert(p7:export('der'))
  p7 = assert(openssl.pkcs7.read(der, 'der'))

  der = assert(p7:export('smime'))
  p7 = assert(openssl.pkcs7.read(der, 'smime'))

  der = assert(p7:export())
  assert(openssl.pkcs7.read(der, 'auto'))

  p7 = openssl.pkcs7.new()
  p7:add(ca.cacert)
  p7:add(cert)
  p7:add(ca.crl)
  assert(p7:parse())
  assert(p7:export())

  der = p7:export('der')
  assert(der)
end

function TestPKCS7:testStep()
  local ca = helper.get_ca()
  local store = ca:get_store()

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

  --attach
  local p7 = assert(openssl.pkcs7.new())
  assert(p7:add_signer(cert, pkey, md))
  assert(p7:add(ca.cacert))
  local pp7 = p7:sign_digest(hash, 0, true)
  assert(pp7)

  local ret = assert(p7:verify(nil, store, msg .. msg))
  assert(type(ret)=='string')
  assert(ret==msg..msg)
  assert(p7:parse())

  --detach
  p7 = assert(openssl.pkcs7.new())
  assert(p7:add_signer(cert, pkey, md))
  assert(p7:add(ca.cacert))
  pp7 = p7:sign_digest(hash, pkcs7.DETACHED, true)
  assert(pp7)

  ret = assert(p7:verify(nil, store, msg .. msg, pkcs7.DETACHED))
  assert(ret)
  ret =
    assert(p7:verify_digest(nil, store, hash, pkcs7.DETACHED, true))
  assert(ret)
  assert(p7:parse())

  p7 = assert(openssl.pkcs7.new())
  assert(p7:add(ca.cacert))
  assert(p7:add_signer(cert, pkey, md))
  assert(p7:sign_digest(hash, 0, true))

  ret = p7:verify(nil, store)
  assert(not ret)
  ret = assert(p7:verify(nil, store, msg .. msg))
  assert(ret)

  ret = assert(p7:verify(nil, store, msg .. msg, pkcs7.DETACHED))
  assert(ret)

  if not helper.libressl then
    store = ca:get_store()
    assert(store:trust(true))
    store:add(ca.cacert)
    store:add(ca.crl)

    ret = assert(p7:verify(nil, store, msg .. msg, 0))
    assert(ret)
    ret =
      assert(p7:verify_digest(nil, store, nil, 0, true))
    assert(ret)
    local ln, sn = p7:type()
    assert(ln)
    assert(sn)
    end
end

function TestPKCS7:testFinal()

  local p7 = assert(openssl.pkcs7.new())
  assert(p7:final("context", 0))
  local ln, sn = p7:type()
  assert(ln)
  assert(sn)

end
