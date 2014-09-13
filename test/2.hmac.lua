local hmac = require'openssl'.hmac
local print_r = require'function.print_r'
io.read()

require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.msg='abcd'
        self.alg='sha1'
        self.key = 'abcdefg'
    end

    function TestCompat:tearDown()
        print('Test END')
    end

    function TestCompat:testDigest()
        local a,b,c
        a = hmac(self.alg,self.msg,self.key,true)
        assertEquals(#a,20)

        b = hmac.hmac(self.alg,self.msg,self.key,false)
        assertEquals(#b,40)
        assertEquals(openssl.hex(a),b)

        a = hmac.new(self.alg,self.key)
        a:update(self.msg)
        a = a:final()
        assertEquals(a,b)
        
        c = hmac.new(self.alg,self.key)
        c = c:final(self.msg)
        assertEquals(c,b)        
    end

local lu = LuaUnit
lu:setVerbosity( 0 )
lu:run()
