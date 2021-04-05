local openssl = require('openssl')
local lu = require('luaunit')

local msg = 'The quick brown fox jumps over the lazy dog.'

function testHex()
  local ano = openssl.hex(msg)
  lu.assertEquals(openssl.hex(msg, true), ano)
  local raw = openssl.hex(ano, false)
  lu.assertEquals(raw, msg)
  lu.assertEquals(#msg * 2, #ano)
end

function testBase64()
  local ano = openssl.base64(msg)
  -- default without newline
  assert(#ano > #msg)
  assert(not string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true), ano)
  local raw = openssl.base64(ano, false)
  lu.assertEquals(raw, msg)

  -- without newline
  ano = openssl.base64(msg, true, true)
  assert(#ano > #msg)
  assert(not string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true, true), ano)
  raw = openssl.base64(ano, false, true)
  lu.assertEquals(raw, msg)

  -- with newline
  ano = openssl.base64(msg, true, false)
  assert(#ano > #msg)
  assert(string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true, false), ano)
  raw = openssl.base64(ano, false, false)
  lu.assertEquals(raw, msg)

  ano = openssl.base64(msg)
  -- default without newline
  assert(#ano > #msg)
  assert(not string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true), ano)
  raw = openssl.base64(ano, false)
  lu.assertEquals(raw, msg)

  -- without newline
  ano = openssl.base64(msg, true, true)
  assert(#ano > #msg)
  assert(not string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true, true), ano)
  raw = openssl.base64(ano, false, true)
  lu.assertEquals(raw, msg)

  -- with newline
  ano = openssl.base64(msg, true, false)
  assert(#ano > #msg)
  assert(string.find(ano, '\n'))
  lu.assertEquals(openssl.base64(msg, true, false), ano)
  raw = openssl.base64(ano, false, false)
  lu.assertEquals(raw, msg)
end

function testAll()
  local f = io.open('luasec/certs/rootB.cnf', 'r')
  if f then
    local data = f:read('*a')
    f:close()

    local conf = assert(openssl.lhash_read(data))
    local t = conf:parse(false)
    lu.assertIsTable(t)
    -- print_r(t)
    t = conf:parse()
    lu.assertIsTable(t)

    t = conf:parse(true)
    lu.assertIsTable(t)

    assert(conf:get_string('ca', 'default_ca'))
    assert(conf:get_string('CA_default', 'default_days'))
    assert(conf:get_number('req', 'default_bits')==1024)

    local c1 = openssl.lhash_load('luasec/certs/rootB.cnf')
    t = c1:parse()
    assert(type(c1:export())=='string')
    lu.assertIsTable(t)
  end
end
