local pkey = require('openssl').pkey
local print_r = require'function.print_r'

require('luaunit')

local function mk_key(args)
        assert(type(args),'table')
        local k = assert(pkey.new(table.unpack(args)))
        return k
end


TestMY = {}


    function TestMY:setUp()
        self.genalg = {
                {nil}, --default to create rsa 1024 bits with 65537
                {'rsa',2048,3}, --create rsa with give bits length and e
                {'dsa',512},
                {'dh',512},
                {'ec','prime256v1'}
        }

    end
    function TestMY:testModule()
        for i,v in ipairs(self.genalg ) do
                print(v)
                local k = mk_key(v)
                local k1 = pkey.get_public(k)
                assert(not k1:is_private())

                local t= k:parse()
                local len = t.bits/8
                print_r(t)

                local msg = openssl.random(len-11)
                if t.type=='rsa' then
                        local out = pkey.encrypt(k,msg)
                        local raw = pkey.decrypt(k1,out)

                        assertEquals(len,#out)
                        assertEquals(msg,raw)

                        local out,sk = pkey.seal(k1,msg)
                        local raw = pkey.open(k,out,sk)
                        assertEquals(msg,raw)
                end
                if t.type ~='dh' then
                        local sig = pkey.sign(k,msg)
                        assert(true==pkey.verify(k1,msg,sig))
                end

                if t.type=='rsa' then
                        local out = k:encrypt(msg)
                        local raw = k1:decrypt(out)

                        assertEquals(len,#out)
                        assertEquals(msg,raw)

                        local out,sk = k1:seal(msg)
                        local raw = k:open(out,sk)
                        assertEquals(msg,raw)
                end
                if t.type ~='dh' then
                        local sig = k:sign(msg)
                        assert(true==k1:verify(msg,sig))
                end
                assert(k1:export())
                assert(k:export())

                assertEquals(k1:export(),k:export(true))
                assertEquals(k1:export(true),k:export(true))

                assert(k1:export(true,true))
                assert(k:export(true,true))

                assert(k1:export(true,true,true))
                assert(k:export(true,true,true))

                assert(k1:export(true,true,true,'secret'))
                assert(k:export(true,true,true,'secret'))

                print(k1:export(true,true,true,'secret'))
                print(k:export(true,true,true,'secret'))
                print(k:export(false,true,'secret'))

                print(k1:export(true,true,true,'secret'))
                print(k:export(true,false,true,'secret'))
                print(k:export(false,false,true,'secret'))
        end
    end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
