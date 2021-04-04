local lu = require 'luaunit'
local openssl = require 'openssl'
local algor = require'openssl'.x509.algor

TestX509Algor = {}

function TestX509Algor:testAll()
  local alg1 = algor.new()
  --FIXME
  --assert(alg1:dup() == nil)
  local alg2 = algor.new()
  if alg1.equals then
    assert(alg1:equals(alg2))
    assert(alg1==alg2)
  end

  alg1:md('sha1')
  alg2:md('sha256')

  assert(alg1~=alg2)

  local o1 = openssl.asn1.new_object('C')
  --FIXME
  --local s = openssl.asn1.new_string('CN',  openssl.asn1.UTF8STRING)
  --alg1:set(o1, s)
  alg1:set(o1)

  local a = alg1:get()
  assert(o1==a)
  local b = alg2:get()
  assert(a~=b)
end

