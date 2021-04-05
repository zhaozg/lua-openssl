local lu = require 'luaunit'

local openssl = require 'openssl'
local helper = require'helper'

TestStore = {}

function TestStore:testAll()
  local ca = helper.get_ca()
  local store = ca:get_store()
  assert(store:trust(true))
  store:add(ca.cacert)
  store:add(ca.crl)
  store:load('luasec/certs/serverA.pem', 'luasec/certs')
  store:add_lookup('luasec/certs', 'dir', 'pem')
  store:add_lookup('luasec/certs/serverA.pem', 'file', 'pem')
  store:depth(9)
  store:flags(0)
  store:add({ca.cacert, ca.crl})
  --FIXME
  --store:purpose()
end

