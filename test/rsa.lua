local openssl = require'openssl'
local pkey = require'openssl'.pkey
local unpack = unpack or table.unpack

testRSA = {}
    function testRSA:testRSA()
        local nrsa =  {'rsa',1024,3}
        local rsa = pkey.new(unpack(nrsa))
        local k1 = pkey.get_public(rsa)
        assert(not k1:is_private())
        local t = k1:parse ()
        assert(t.bits==1024)
        assert(t.type=='rsa')
        assert(t.size==128)
        local r = t.rsa
        t = r:parse()
        t.alg = 'rsa'
        local r2 = pkey.new(t)
        local msg = openssl.random(128-11)

        local out = pkey.encrypt(r2,msg)
        local raw = pkey.decrypt(rsa,out)
        assert(msg==raw)
    end
