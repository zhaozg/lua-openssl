local openssl = require 'openssl'
local dh = openssl.dh

TestDH = {}
function TestDH:Testdh()
  local p = dh.generate_parameters(512)
  local k = p:generate_key()

  local t = k:parse()
  assert(t.bits == 512)
  assert(t.size == 64)

  k:set_engine(openssl.engine('openssl'))
end
