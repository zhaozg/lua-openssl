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
                {nil}, --default to create rsa 1024 bits with 65537
                {'rsa',1024,3}, --create rsa with give bits length and e
                {'dsa',512},
                {'dh',512},
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
                if t.type ~='dh' then
                        local sig = pkey.sign(k,msg)
                        assert(true==pkey.verify(k1,msg,sig))
                end

                if t.type ~='dh' then
                        local sig = k:sign(msg)
                        assert(true==k1:verify(msg,sig))
                end

                assert(k1:export())
                assert(k:export())

                assertEquals(k1:export(),k:export())
                assertEquals(k1:export(false),k:export())

                assert(k1:export(true,true))
                assert(k:export(true,true))

                assert(k1:export(true,true,true))
                assert(k:export(true,true,true))

                assert(k1:export(true,true,true,'secret'))
                assert(k:export(true,true,true,'secret'))

                assert(k1:export(true,true,true,'secret'))
                assert(k:export(true,true,true,'secret'))
                assert(k:export(false,true,'secret'))

                assert(k1:export(true,true,true,'secret'))
                assert(k:export(true,false,true,'secret'))
                assert(k:export(false,false,true,'secret'))

        end
    end
