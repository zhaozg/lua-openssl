local name = require'openssl'.x509.name

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
        assertEquals(tostring(n1),n1:oneline())
        
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
        assertEquals(n1:get_index('CN'),2)
        
        assertEquals(n1:get_text('C'),'CN')
        assertEquals(n1:get_index('C'),0)
        assertEquals(n1:get_index('C',0),nil)
        
        assert(n1:add_entry('OU','DEV'))
        assertEquals(n1:get_index('OU'),3)
        local k,v = n1:delete_entry(3)
        assertStrContains(tostring(k),'openssl.asn1_object')
        assertEquals(tostring(v),'utf8:DEV')
        
    end
