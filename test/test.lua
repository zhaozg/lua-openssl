local lu = require'luaunit'
local openssl = require'openssl'

openssl.rand_load()
print('VERSION:', openssl.version())

dofile('0.bio.lua')
dofile('0.bn.lua')
dofile('0.engine.lua')
dofile('0.misc.lua')
dofile('0.tcp.lua')
dofile('1.asn1.lua')
dofile('2.asn1.lua')
dofile('1.x509_algor.lua')
dofile('1.x509_name.lua')
dofile('1.x509_extension.lua')
dofile('1.x509_attr.lua')
dofile('2.digest.lua')
dofile('2.hmac.lua')
dofile('3.cipher.lua')
dofile('4.pkey.lua')
dofile('5.x509_req.lua')
dofile('5.x509_crl.lua')
dofile('5.x509_store.lua')
dofile('5.x509.lua')
dofile('5.ts.lua')
dofile('6.pkcs7.lua')
dofile('6.cms.lua')
dofile('7.pkcs12.lua')
dofile('8.ssl_options.lua')
dofile('8.ssl.lua')
dofile('9.ocsp.lua')
dofile('9.srp.lua')
dofile('9.issue.lua')
dofile('dh.lua')
dofile('dsa.lua')
dofile('rsa.lua')
dofile('ec.lua')
dofile('sm2.lua')

local runner = lu.LuaUnit.new()
runner:setOutputType("tap")
local retcode = runner:runSuite()
print(openssl.errors())
openssl.clear_error()
--FIXME: libressl gc fail
local helper = require'helper'
if not helper.libressl then
  collectgarbage()
end
os.exit(retcode)

