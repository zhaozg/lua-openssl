local openssl = require'openssl'
EXPORT_ASSERT_TO_GLOBALS = true
require'luaunit'

openssl.rand_load()
print('VERSION:', openssl.version())

dofile('0.engine.lua')
dofile('0.misc.lua')
dofile('0.tcp.lua')
dofile('1.asn1.lua')
dofile('2.asn1.lua')
dofile('1.x509_name.lua')
dofile('1.x509_extension.lua')
dofile('1.x509_attr.lua')
dofile('2.digest.lua')
dofile('2.hmac.lua')
dofile('3.cipher.lua')
dofile('4.pkey.lua')
dofile('5.x509_req.lua')
dofile('5.x509_crl.lua')
dofile('5.x509.lua')
dofile('5.ts.lua')
dofile('6.pkcs7.lua')
dofile('6.cms.lua')
dofile('7.pkcs12.lua')
dofile('8.ssl_options.lua')
dofile('8.ssl.lua')
dofile('9.srp.lua')
dofile('9.issue.lua')
dofile('rsa.lua')
dofile('ec.lua')
dofile('sm2.lua')

--LuaUnit.verbosity = 0
local runner = LuaUnit.new()
runner:setOutputType("tap")
local retcode = runner:runSuite()
print(openssl.print_errors():get_mem())
collectgarbage()
os.exit(retcode)

