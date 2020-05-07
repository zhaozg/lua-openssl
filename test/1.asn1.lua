local openssl = require'openssl'
local asn1 = openssl.asn1
local first = true

TestObject = {}

    function TestObject:setUp()
        self.sn = 'C'
        self.ln = 'countryName'
        self.oid = '2.5.4.6'
        self.nid = 14
        assertIsTable(asn1)

        self.ne_sn = 'Good1'
        self.ne_ln = 'GoodString1'
        self.ne_oid = '1.2.3.4.1'
    end

    function TestObject:tearDown()
    end

    function TestObject:testAll()
        local o1, o2, o3, o4, o5, o6, o7
        o1 = asn1.new_object(self.sn)
        o2 = asn1.new_object(self.ln)
        o3 = asn1.new_object(self.nid)
        o4 = asn1.new_object(self.oid)
        o5 = asn1.new_object(self.oid,true)
        assert(o1)
        assert(o1==o2)
        assert(o1==o3)
        assert(o1==o4)
        assert(o1==o5)

        assertEquals(openssl.error(),nil)

        o6 = asn1.new_object(self.ln,true)
        assertNil(o6)
        assertNotNil(openssl.error())
        assertNil(openssl.error())

        o6 = o1:dup()
        assert(o1==o6)


        local sn,ln = o1:name()
        local nid = o1:nid()
        local sn1,ln1 = o1:sn(), o2:ln()
        local txt = o1:txt()
        local oid = o1:txt(true)
        local dat = o1:data()

        assertEquals(sn,self.sn)
        assertEquals(ln,self.ln)
        assertEquals(oid,self.oid)
        assertEquals(nid,self.nid)
        assertEquals(ln, dat)
        assertEquals(sn1,sn)
        assertEquals(ln1,ln)
        assertEquals(txt, ln)
        assertEquals(o1:txt(false), txt)

        local options = {
            oid ='1.2.840.10045.2.1.2.1',
            sn  ='gmsm21',
            ln  ='CCSTC GMSM2 EC1'
        }

        assertNil(openssl.error())
        o7 = asn1.new_object(options.sn)
        if not o7 then
            assertNotNil(openssl.error())
            o7 =  asn1.new_object(options)
            assertStrContains(tostring(o7), 'openssl.asn1_object')
            assertEquals(o7:txt(), options.ln)
            assertEquals(o7:txt(true), options.oid)
            assertEquals(asn1.txt2nid(options.sn), o7:nid())
            assertEquals(asn1.txt2nid(options.ln), o7:nid())
            assertEquals(asn1.txt2nid(options.oid), o7:nid())
        end

        if first then
            assertIsNil(asn1.txt2nid(self.ne_oid))
            first = false

            assertIsNil(asn1.new_object(self.ne_sn))
            assertNotNil(openssl.error())
            assertIsNil(asn1.new_object(self.ne_ln))
            assertNotNil(openssl.error())
            assert(asn1.new_object(self.ne_oid))

            o1 = assert(asn1.new_object({oid=self.ne_oid,sn=self.ne_sn,ln=self.ne_ln}))
            o2 = assert(asn1.new_object(self.ne_oid))
            assertEquals(o1,o2)

            assertNil(openssl.error())
        else
            assert(asn1.txt2nid(self.ne_oid))
            assert(asn1.new_object(self.ne_sn))
            assert(asn1.new_object(self.ne_ln))
            assert(asn1.new_object(self.ne_oid))
        end
    end

TestString = {}
    function TestString:setUp()
        self.bmp = 'abcd'
        self.bmp_cn = 'ÖÐÎÄÃû×Ö'
    end

    function TestString:tearDown()
    end

    function TestString:testAll()
        local s1,s2,s3,s4,s5,s6
        s1 = asn1.new_string(self.bmp,asn1.BMPSTRING)
        assertEquals(s1:tostring(), self.bmp)
        assert(#s1==#self.bmp)
        s2 = asn1.new_string(self.bmp_cn,asn1.BMPSTRING)
        local utf_cn = s2:toutf8()
        s3 = asn1.new_string(utf_cn,asn1.UTF8STRING)
        assertEquals(utf_cn,s3:data())

        assertEquals(#s3,#utf_cn)
        assertEquals(s3:length(),#utf_cn)
        assertEquals(s3:type(),asn1.UTF8STRING)
        assertEquals(s2:type(),asn1.BMPSTRING)
        s4 = asn1.new_string('',asn1.UTF8STRING)
        s4:data(utf_cn)
        assertEquals(s4, s3)
        s6 = asn1.new_string(self.bmp,asn1.IA5STRING)
        assertEquals(s6:toprint(),self.bmp)

        assertStrMatches(s1:toprint(),[[\U6162\U6364]])
        assertStrMatches(s4:toprint(),[[\UD6D0\UCEC4\UC3FB\UD7D6]])

        s5 = s4:dup()
        assertEquals(s5,s3)
        assert(s4==s3)
    end

TestTime = {}
    function TestTime:get_timezone()
        local now = os.time()
        local gmt = os.time(os.date("!*t", now))
        local tz =  os.difftime(now, gmt)
        return tz
    end

    function TestTime:setUp()
        self.time = os.time()
        self.gmt = self.time-self:get_timezone()
    end

    function TestTime:testUTCTime()
        local at = openssl.asn1.new_utctime()
        assert(at:set(self.time))
        local t1 = at:get()
        assertEquals(self.gmt,t1)
    end

    function TestTime:testGENERALIZEDTime()
        local at = openssl.asn1.new_generalizedtime()
        assert(at:set(self.time))
        local t1 = at:get()
        assertEquals(self.gmt, t1)
    end

TestNumber = {}
    function TestNumber:testBasic()
        local i = 0
        local n = asn1.new_integer(i):i2d()
        assert(n)
        local m = asn1.new_integer()
        m:d2i(n)
        assert(m:i2d()==n)
        n = asn1.new_integer():i2d()
        assert(n)
        n = asn1.new_integer(nil):i2d()
        assert(n)
    end
