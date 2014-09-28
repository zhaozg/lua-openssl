require'luaunit'

dofile('1.asn1.lua')
dofile('2.digest.lua')
dofile('2.hmac.lua')
dofile('3.cipher.lua')
dofile('4.pkey.lua')

LuaUnit:setVerbosity(10)
LuaUnit:run()
