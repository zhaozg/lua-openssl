
local openssl = require "openssl"
local bio = openssl.bio

local lu = require('luaunit')
------------------------------------------------------------------------------
TestBIO = {}

function TestBIO:testMem()
  local m = bio.mem(4)
  local s = m:get_mem()
  assert(s=='')

  m = bio.mem('abcd')
  s = m:get_mem()
  assert(s=='abcd')
  local rp, wp = m:pending()
  print(rp, wp)

  m:write('aa')
  s = m:read()
  assert(s=='abcdaa')

  m:puts("aa")
  s = m:gets(1024)
  assert(s=='aa')
  print(m:type())
  m:reset()
end

function TestBIO:testSocket()
  local s = bio.socket(555)
  s:close()

  local d = bio.dgram(555)
  d:close()

  --FIXME
  --s = bio.accept(899)
  --local c = bio.connect('127.0.0.1:899', true)
  --c:close()
  --s:close()
end

function TestBIO:testFile()
  local s = bio.fd(2)
  s:close()

  local f = bio.file('./test.lua')
  f:close()
end
