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
  store:load('certs/agent1-cert.pem', 'certs')
  store:add_lookup('certs', 'dir', 'pem')
  store:add_lookup('lcerts/agent1-cert.pem', 'file', 'pem')
  store:depth(9)
  store:flags(0)
  store:add({ca.cacert, ca.crl})
  --FIXME
  --store:purpose()
end

