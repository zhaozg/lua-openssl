local openssl = require'openssl'
local digest = require'openssl'.digest
local unpack = unpack or table.unpack
TestDigestCompat = {}
    function TestDigestCompat:setUp()
        self.msg='abcd'
        self.alg='sha1'
    end

    function TestDigestCompat:tearDown()
    end

    function TestDigestCompat:testDigest()
        local a,b,c
        a = digest.digest(self.alg,self.msg)
        assertEquals(#a,40)

        b = digest.digest(self.alg,self.msg,false)
        assertEquals(#b,40)
        assertEquals(a,b)
        c = digest.digest(self.alg,self.msg,true)
        assertEquals(#c,20)
    end
    function TestDigestCompat:testObject()
        local a,b,c,aa,bb
        local obj = digest.new(self.alg)
        assert(obj:update(self.msg))
        a = obj:final()
        obj:reset()
        b = obj:final(self.msg,false)
        assert(a==b)
        assert(#a==40)

        obj:reset()
        assert(obj:update(self.msg))
        c = obj:final(self.msg,true)
        assertEquals(2*#c,#a)

        obj:reset()
        local obj1 = obj:clone()

        obj:update(self.msg)
        aa = obj:final(self.msg)
        bb = obj1:final(self.msg..self.msg)
        assertEquals(aa,bb)
    end

TestDigestMY = {}
    function TestDigestMY:testList()
        local t1,t2,t3,t
        t1 = digest.list(true)
        t2 = digest.list()
        assert(#t1==#t2)
        t3 = digest.list(false)
        assert(#t1>#t3)
        local md = digest.get('sha1')
        t = md:info()
        assert(t.size==20)

        local ctx1 = md:new()
        t1 = ctx1:info()
        local ctx = digest.new('sha1')
        t2 = ctx:info()
        for k,_ in pairs(t1) do
            if(k~='digest') then
                assert(t1[k]==t2[k])
            end
        end
        assert(t1.size==20)
    end

local function mk_key(args)
        assert(type(args),'table')

        local k = assert(openssl.pkey.new(unpack(args)))
        return k
end

TestSignVry = {}
    function TestSignVry:setUp()
        self.msg='abcd'
        self.alg='sha1'
        self.prik = mk_key({'rsa',2048,3})
        self.pubk = openssl.pkey.get_public(self.prik)
    end
    function TestSignVry:testSignVry()
        local md = digest.get(self.alg)
        local sctx = digest.signInit(md,self.pubk);
        assert(sctx:signUpdate(self.msg))
        assert(sctx:signUpdate(self.msg))
        local sig = sctx:signFinal(self.prik)
        assertEquals(#sig,256)
        local vctx = digest.verifyInit(md,self.pubk)
        assert(vctx:verifyUpdate(self.msg))
        assert(vctx:verifyUpdate(self.msg))
        assert(vctx:verifyFinal(sig))
    end
     function TestSignVry:testSignVry1()
        local md = digest.get(self.alg)
        local sctx = md:signInit(self.prik);
        assert(sctx:signUpdate(self.msg))
        assert(sctx:signUpdate(self.msg))
        local sig = sctx:signFinal(self.prik)
        assertEquals(#sig,256)
        local vctx = md:verifyInit(self.pubk)
        assert(vctx:verifyUpdate(self.msg))
        assert(vctx:verifyUpdate(self.msg))
        assert(vctx:verifyFinal(sig,self.pubk))
    end
