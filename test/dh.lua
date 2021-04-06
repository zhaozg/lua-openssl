local openssl = require 'openssl'
local dh = require'openssl'.dh

TestDH = {}
function TestDH:Testdh()
  local k = dh.generate_key(512)

  local t = k:parse()
  assert(t.bits == 512)
  assert(t.size == 64)

  --FIXME: crash
  --k:set_engine(openssl.engine('openssl'))
end
