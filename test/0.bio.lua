
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
  assert(rp==4)
  assert(wp==0)

  m:write('aa')
  s = m:read()
  assert(s=='abcdaa')

  m:puts("aa")
  s = m:gets(1024)
  assert(s=='aa')
  assert(m:type()=="memory buffer")
  m:reset()
end

function TestBIO:testFilter()
  local b64 = bio.filter('base64')
  local mem = bio.mem()
  b64 = assert(b64:push(mem))
  b64:write('abcd')
  b64:flush()
  local s = b64:get_mem()
  assert(s=='YWJjZA==\n')

  local md = bio.filter('md', 'sha1')
  mem = bio.mem('abcd')
  md = assert(md:push(mem))
  md:write('abcd')
  md:flush()

  local m
  md, m = md:get_md()
  s = md:gets()
  --FIXME: howto get digest
  assert(md:next():get_md()==nil)

  m = '1234567812345678'
  local cipher = bio.filter('cipher', 'aes-128-ecb', '1234567812345678', '1234567812345678', true)
  mem = bio.mem()

  cipher = assert(cipher:push(mem))
  cipher:write(m)
  cipher:flush()
  s = cipher:read()
  assert(#s==32)
  assert(cipher:cipher_status())

  --
  cipher = bio.filter('cipher', 'aes-128-ecb', '1234567812345678', '1234567812345678', false)
  mem = bio.mem()

  cipher = assert(cipher:push(mem))
  cipher:write(s)
  cipher:flush()
  s = cipher:read()
  assert(#s==16)
  --FIXME:
  --assert(s==m)
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

