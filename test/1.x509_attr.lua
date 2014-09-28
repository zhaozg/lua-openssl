local attr = require'openssl'.x509.attribute

TestX509attr = {}
    function TestX509attr:setUp()
        self.timeStamping = openssl.asn1.new_string('timeStamping','ia5')
        self.cafalse = openssl.asn1.new_string('CA:FALSE','octet')
        self.time = {
            object = 'extendedKeyUsage',
            type='ia5',
            value = 'timeStamping',
        }
        self.ca = {
            object='basicConstraints',
            type='octet',
            value=self.cafalse
        }
        self.cas = {
            object='basicConstraints',
            type='octet',
            value='CA:FALSE'
        }
        self.attrs = {
            self.time,
            self.ca,
            self.cas
        }
    end

    function TestX509attr:tearDown()
    end
    
    function TestX509attr:testsk()
        local sk  = attr.new_sk_attribute(self.attrs)
        assert(#sk,3)
    end
    
    function TestX509attr:testAll()
        local n1 = attr.new_attribute(self.ca)
        assertStrContains(tostring(n1),'openssl.x509_attribute')
        local info = n1:info()
        
        assertIsTable(info)
        assertEquals(info.object, "X509v3 Basic Constraints")
        assertEquals(info.single,false)
        assertEquals(info.value[1].type, "octet")
        assertEquals(info.value[1].value, "CA:FALSE")
        local n2 = n1:dup()
        assertEquals(n2:info(),info)
        
        local t = n1:type (0)
        assertIsTable(t)
        assertEquals(t.type,'octet')
        assertEquals(t.value,'CA:FALSE')

        local  n2 = attr.new_attribute(self.cas)
        assertEquals(n1:info(),n2:info())
        
        assertEquals(n1:object():ln(),'X509v3 Basic Constraints')
        n1:object('extendedKeyUsage')
        assertEquals(n1:object():sn(),'extendedKeyUsage')
 
        assertEquals(tostring(n1:data(0,'octet')),'octet:CA:FALSE')
        
        assert(n1:data('octet','CA:TRUE'))
        assertEquals(tostring(n1:data(0,'octet')),'octet:CA:TRUE')
    end
