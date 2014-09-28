require'luaunit'

dofile('1.asn1.lua')
dofile('1.x509_name.lua')
dofile('1.x509_extension.lua')
dofile('1.x509_attr.lua')
dofile('2.digest.lua')
dofile('2.hmac.lua')
dofile('3.cipher.lua')

LuaUnit:setVerbosity(10)
for i=1,1000000 do
LuaUnit:run()
end