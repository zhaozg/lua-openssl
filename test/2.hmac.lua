local hmac = require'openssl'.hmac
local print_r = require'function.print_r'
io.read()

require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.msg='abcd'
        self.alg='sha1'
        self.key = 'abcdefg'
        print('digest',digest)
        print('metatable',getmetatable(digest))
    end

    function TestCompat:tearDown()
        print('Test END')
    end

    function TestCompat:testDigest()
        local a,b,c
        a = hmac(self.alg,self.key,self.msg)
        assertEquals(#a,20)

        b = hmac.hmac(self.alg,self.key,self.msg)
        assertEquals(#b,20)
        assertEquals(a,b)
    end
    
    function TestCompat:testObject()
        local a,b,c,aa,bb,cc
        local obj,obj1
        obj = hmac.new(self.alg,self.key)
        obj:update(self.msg)
        a = obj:final()

        b = hmac(self.alg,self.key,self.msg)
        assert(a==b)
        
        obj = hmac.new(self.alg,self.key)
        c = obj:final(self.msg)
        assertEquals(c,a)
        
    end

local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
