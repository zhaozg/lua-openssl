local pkey = require('openssl').pkey
local unpack = unpack or table.unpack

local function mk_key(args)
        assert(type(args),'table')
        
        local k = assert(pkey.new(unpack(args)))
        return k
end


TestPKEYMY = {}
    function TestPKEYMY:setUp()
        self.genalg = {
        --[[
                {nil}, --default to create rsa 1024 bits with 65537
                {'rsa',1024,3}, --create rsa with give bits length and e
                {'dsa',512},
                {'dh',512},
        --]]                
                {'ec','prime256v1'}
        }

    end
    function TestPKEYMY:testModule()
        for i,v in ipairs(self.genalg ) do
                --print(v)
                local k = mk_key(v)
                local k1 = pkey.get_public(k)
                assert(not k1:is_private())

                local t= k:parse()
                local len = t.bits/8
                --print_r(t)

                local msg = openssl.random(len-11)
                if t.type=='rsa' then
                        local out = pkey.encrypt(k1,msg)
                        local raw = pkey.decrypt(k,out)

                        assertEquals(len,#out)
                        assertEquals(msg,raw)

                        local out,sk,iv = pkey.seal(k1,msg)
                        local raw = pkey.open(k,out,sk,iv)
                        assertEquals(msg,raw)
                end
                if t.type ~='ec' and t.type ~='dh' then
                        local sig = assert(pkey.sign(k,msg))
                        assert(true==pkey.verify(k1,msg,sig))
                end

                assert(string.len(k1:export())>0)
                assert(string.len(k:export())>0)

                assertEquals(k1:export(),k:export())
                assertEquals(k1:export(false),k:export())

                assert(string.len(k1:export(true,true))>0)
                assert(string.len(k:export(true,true))>0)

                assert(string.len(k:export(true,true,true))>0)
                assert(string.len(k1:export(true,true,true))>0)
                assert(string.len(k:export(true,true,false))>0)
                assert(string.len(k1:export(true,true,false))>0)
                assert(string.len(k:export(true,false,false))>0)
                assert(string.len(k1:export(true,false,false))>0)
                assert(string.len(k:export(true,false,true))>0)
                assert(string.len(k1:export(true,false,true))>0)
                
                assert(string.len(k1:export(true,true,true,'secret'))>0)
                assert(string.len(k:export(true,true,true,'secret'))>0)

                assert(string.len(k1:export(true,true,true,'secret'))>0)
                assert(string.len(k:export(true,true,true,'secret'))>0)
                assert(string.len(k:export(false,true,'secret'))>0)

                assert(string.len(k1:export(true,true,true,'secret'))>0)
                assert(string.len(k:export(true,false,true,'secret'))>0)
                assert(string.len(k:export(false,false,true,'secret'))>0)

        end
    end

    function testRSA()
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
        assert(t.n)
        assert(t.e)
        t.alg = 'rsa'
        local r2 = pkey.new(t)
        assert(r2:is_private()==false)
        local msg = openssl.random(128-11)
        
        local out = pkey.encrypt(r2,msg)
        local raw = pkey.decrypt(rsa,out)
        assert(msg==raw)
    end
    