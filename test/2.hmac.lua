local openssl = require'openssl'
local hmac = require'openssl'.hmac

TestHMACCompat = {}
    function TestHMACCompat:setUp()
        self.msg='abcd'
        self.alg='sha1'
        self.key = 'abcdefg'
    end

    function TestHMACCompat:tearDown()
    end

    function TestHMACCompat:testDigest()
        local a,b,c
        a = hmac.hmac(self.alg,self.msg,self.key,true)
        assertEquals(#a,20)

        b = hmac.hmac(self.alg,self.msg,self.key,false)
        assertEquals(#b,40)
        assertEquals(openssl.hex(a):lower(),b)

        a = hmac.new(self.alg,self.key)
        a:update(self.msg)
        a = a:final()
        assertEquals(a,b)

        c = hmac.new(self.alg,self.key)
        c = c:final(self.msg)
        assertEquals(c,b)
    end
