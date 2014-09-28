local asn1 = require'openssl'.asn1

TestObject = {}

    function TestObject:setUp()
        self.sn = 'C'
        self.ln = 'countryName'
        self.oid = '2.5.4.6'
        self.nid = 14
        assertIsTable(asn1)
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

        o6 = asn1.new_object(self.ln,true)
        
        assert(o1==o2)
        assert(o1==o3)
        assert(o1==o4)
        assert(o1==o5)
        assertNil(o6)
        
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
        
        assertErrorMsgContains('(need accept paramater)', asn1.new_object)
        local options = {
            oid ='1.2.840.10045.2.1.2.1',
            sn  ='gmsm21',
            ln  ='CCSTC GMSM2 EC1'
        }
        o7 = asn1.new_object(options.sn)
        if not o7 then
            o7 =  asn1.new_object(options)
            assertStrContains(tostring(o7), 'openssl.asn1_object')
            assertEquals(o7:txt(), options.ln)
            assertEquals(o7:txt(true), options.oid)
            assertEquals(asn1.txt2nid(options.sn), o7:nid())
            assertEquals(asn1.txt2nid(options.ln), o7:nid())
            assertEquals(asn1.txt2nid(options.oid), o7:nid())
        end
    end
    
TestString = {}
    function TestString:setUp()
        self.bmp = 'abcd'
        self.bmp_cn = '’‘÷Œπ˙'
    end

    function TestString:tearDown()
    end

    function TestString:testAll()
        local s1,s2,s3,s4,s5,s6
        s1 = asn1.new_string(self.bmp,'bmp')
        s2 = asn1.new_string(self.bmp_cn,'bmp')
        local utf_cn = s2:toutf8()
        s3 = asn1.new_string(utf_cn,'utf8')
        assertEquals(utf_cn,s3:data())
        
        assertEquals(#s3,#utf_cn)
        assertEquals(s3:length(),#utf_cn)
        assertEquals(s3:type(),'utf8')
        assertEquals(s2:type(),'bmp')
        s4 = asn1.new_string('','utf8')
        s4:data(utf_cn)
        assertEquals(s4, s3)
        s6 = asn1.new_string(self.bmp,'ia5')
        assertEquals(s6:print(),self.bmp)
        
        assertStrMatches(s1:print(),[[\U6162\U6364]])
        assertStrMatches(s4:print(),[[\UD5D4\UD6CE\UB9FA]])
        
        s5 = s4:dup()
        assertEquals(s5,s3)
        assertStrContains(tostring(s2),'bmp:')
        assertStrContains(tostring(s3),'utf8:')
        assert(s4==s3)
    end    
