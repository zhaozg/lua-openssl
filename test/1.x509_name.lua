local openssl = require'openssl'
local name = require'openssl'.x509.name
local asn1 = require'openssl'.asn1

TestX509Name = {}
    function TestX509Name:setUp()
        self.names = {
            {C='CN'},
            {O='kkhub.com'},
            {CN='zhaozg'}
        }

    end

    function TestX509Name:tearDown()
    end

    function TestX509Name:testAll()
        local n1 = name.new(self.names)
        assertEquals(n1:tostring(),n1:oneline())
        local der = n1:i2d()
        local n2 = name.d2i(der)
        assert(n1:cmp(n2)==(n1==n2))
        assertEquals(n1,n2)
        assertEquals(n1:oneline(),'/C=CN/O=kkhub.com/CN=zhaozg')

        assertIsNumber(n1:hash())
        assertEquals(#n1:digest('SHA1'),20)

        local out = openssl.bio.mem()
        local out1 = openssl.bio.mem()
        n1:print(out)
        n2:print(out1)

        assert(out1:get_mem()==out:get_mem())
        assertEquals(out1:get_mem(),'C=CN, O=kkhub.com, CN=zhaozg')

        local info = n1:info()
        assertIsTable(info)
        assert(n1:entry_count(),3)

        assertEquals(n1:get_text('CN'),'zhaozg')
        assertEquals(n1:get_text('C'),'CN')
        assertEquals(n1:get_text('OU'),nil)

        assertIsTable(n1:get_entry(0))

        assertIsTable(n1:get_entry(1))
        assertIsTable(n1:get_entry(2))
        assertIsNil(n1:get_entry(3))

        local s2 = asn1.new_string('ÖÐÎÄÃû×Ö',asn1.BMPSTRING)
        local utf_cn = s2:toutf8()
        local s3 = asn1.new_string(utf_cn,asn1.UTF8STRING)

        assert(n1:add_entry('OU',utf_cn,true))
        local S, i = n1:get_text('OU')
        assertEquals(i,3)

        local t = n1:info()
        for i=1,#t do
                v = t[i]
                assertIsTable(v)
        end

        local k,v = n1:delete_entry(3)
        assertStrContains(tostring(k),'openssl.asn1_object')
        _,_,opensslv = openssl.version(true)
        if opensslv > 0x10002000 then
            assertEquals(v:toprint(),[[\UD6D0\UCEC4\UC3FB\UD7D6]])
            assertEquals(v:tostring(), v:toutf8())
        end
    end

