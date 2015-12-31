local openssl = require'openssl'
EXPORT_ASSERT_TO_GLOBALS = true
require'luaunit'

print('ENTER to continue,and need long time to finish')
io.read()

openssl.rand_load()

dofile('0.engine.lua')
dofile('0.misc.lua')
dofile('1.asn1.lua')
dofile('2.asn1.lua')
dofile('1.x509_name.lua')
dofile('1.x509_extension.lua')
dofile('1.x509_attr.lua')
dofile('2.digest.lua')
dofile('2.hmac.lua')
dofile('3.cipher.lua')
dofile('4.pkey.lua')
dofile('rsa.lua')
dofile('ec.lua')

dofile('5.x509_req.lua')
dofile('5.x509_crl.lua')
dofile('5.x509.lua')
dofile('5.ts.lua')
dofile('6.pkcs7.lua')
dofile('7.pkcs12.lua')
dofile('8.ssl_options.lua')
--[[
dofile('0.tcp.lua')
dofile('8.ssl.lua')
--]]
LuaUnit:setVerbosity(0)
for i=1, 1000000 do
    LuaUnit:run()
    print(openssl.error(true))
    collectgarbage()
end
collectgarbage()
io.read()
collectgarbage()
io.read()
collectgarbage()
io.read()
collectgarbage()
io.read()