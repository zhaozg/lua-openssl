local openssl = require 'openssl'
local rsa = require'openssl'.rsa

TestRSA = {}
function TestRSA:TestRSA()
  local k = rsa.generate_key(2048)
  assert(k:isprivate())

  local t = k:parse()
  assert(t.bits == 2048)
  assert(t.size == 256)

  if rsa.encrypt then
    assert(k:size()==256)
    k:set_engine(openssl.engine('openssl'))

    local msg = openssl.random(200)

    local out = assert(rsa.encrypt(k,msg))
    local raw = assert(k:decrypt(out, nil, false))
    assert(msg == raw)

    msg = openssl.random(32)
    out = assert(rsa.sign(k, msg, 'sha256'))
    assert(k:verify(msg, out, 'sha256'))
  end

  local der = k:export()
  assert(rsa.read(der))

  der = k:export(false)
  k = rsa.read(der, false)
  assert(not k:isprivate())
end
