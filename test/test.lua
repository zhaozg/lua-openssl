local openssl = require'openssl'
require'luaunit'

openssl.rand_load()

dofile('0.engine.lua')
dofile('0.misc.lua')

dofile('1.asn1.lua')
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
dofile('7.pkcs12.lua')
dofile('8.ssl_options.lua')

--LuaUnit:setVerbosity(0)
LuaUnit:run()
print(openssl.error(true))
collectgarbage()

