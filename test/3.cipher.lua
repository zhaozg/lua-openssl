local openssl = require'openssl'
local cipher = require'openssl'.cipher

TestCipherCompat = {}

    function TestCipherCompat:setUp()
        self.msg='abcdabcdabcdabcdabcdabcd'
        self.msg1='abcd'
        self.alg='des-ede-cbc'
        self.key=string.char(01,02,03,04,05,06,07,08,09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f)
        self.key=self.key..string.reverse(self.key)
        self.iv = string.rep(string.char(00),32)

        assertEquals('nil',type(getmetatable(cipher)))
    end
    function TestCipherCompat:tearDown()
    end
    function TestCipherCompat:testCipher()
        local a,b,c,d

        a = cipher.cipher(self.alg,true,self.msg,self.key)
        assert(#a>#self.msg)
        b = cipher.cipher(self.alg,false,a,self.key)
        assertEquals(b,self.msg)

        c = cipher.encrypt(self.alg,self.msg,self.key)
        assertEquals(c,a)
        d = cipher.decrypt(self.alg,c,self.key)
        assertEquals(d,self.msg)
    end

    function TestCipherCompat:testObject()
        local a,b,c,aa,bb,cc
        local obj,obj1

        obj = cipher.new(self.alg,true,self.key)
        a = assert(obj:update(self.msg))
        a = a..obj:final()

        obj1 = cipher.new(self.alg,false,self.key)
        b = assert(obj1:update(a))
        b = b..assert(obj1:final())
        assertEquals(b,self.msg)
        assert(#a>#self.msg)

        obj = cipher.encrypt_new(self.alg,self.key)
        aa = assert(obj:update(self.msg))
        aa = aa..assert(obj:final())

        obj1 = cipher.decrypt_new(self.alg,self.key)
        bb = assert(obj1:update(aa))
        local dd = assert(obj1:final())
        bb = bb..dd
        local ee = assert(obj1:final())
        assertEquals(dd,ee)
        assertEquals(self.msg,bb)
        assert(#self.msg < #aa)
    end


TestCipherMY = {}

    function TestCipherMY:setUp()
        self.msg='abcdabcdabcdabcdabcdabcd'
        self.msg1='abcd'
        self.alg='des-ede-cbc'
        self.key=string.char(01,02,03,04,05,06,07,08,09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f)
        self.key=self.key..string.reverse(self.key)
        self.iv = string.rep(string.char(00),32)
    end

    function TestCipherMY:testList()

        local t1,t2,t3
        t1 = cipher.list(true)
        t2 = cipher.list()
        assert(#t1==#t2)
        t3 = cipher.list(false)
        assert(#t1>#t3)

        local C = cipher.get('des')

        local a,b,c,aa,bb,cc
        local obj,obj1

        obj = C:new(true,self.key)
        a = assert(obj:update(self.msg))
        a = a..obj:final()

        obj1 = C:new(false,self.key)
        b = assert(obj1:update(a))
        b = b..assert(obj1:final())
        assertEquals(b,self.msg)
        assert(#a >= #self.msg)

        obj = C:encrypt_new(self.key)
        aa = assert(obj:update(self.msg))
        aa = aa..assert(obj:final())

        obj1 = C:decrypt_new(self.key)
        bb = assert(obj1:update(aa))
        bb = bb..assert(obj1:final())
        assertEquals(self.msg,bb)
        assert(#self.msg <= #aa)

        local r = openssl.random(16)
        local k,i = C:BytesToKey(r)

        local k1,i1 = C:BytesToKey(r)
        assertEquals(k,k1)
        assertEquals(i,i1)
        local t = obj:info()
        assertEquals(#k,t.key_length)
        assertEquals(#i,t.iv_length)
    end

    function TestCipherMY:testAesCTR()

        local C = cipher.get('aes-128-ctr')
        local key = '0123456789abcefg'
        local iv = string.rep('\0',16)

        local a,b,c,aa,bb,cc
        local obj,obj1

        obj = C:new(true,self.key)
        a = assert(obj:update(self.msg))
        a = a..obj:final()

        obj1 = C:new(false,self.key)
        b = assert(obj1:update(a))
        b = b..assert(obj1:final())
        assertEquals(b,self.msg)
        assert(#a>=#self.msg)

        obj = C:encrypt_new(self.key)
        aa = assert(obj:update(self.msg))
        aa = aa..assert(obj:final())

        obj1 = C:decrypt_new(self.key)
        bb = assert(obj1:update(aa))
        bb = bb..assert(obj1:final())
        assertEquals(self.msg,bb)
        assert(#self.msg <= #aa)
    end
