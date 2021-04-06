local openssl = require 'openssl'
local dsa = require'openssl'.dsa

TestDSA = {}
function TestDSA:Testdsa()
  local k = dsa.generate_key(1024)

  local t = k:parse()
  assert(t.bits == 1024)

  k:set_engine(openssl.engine('openssl'))
end
