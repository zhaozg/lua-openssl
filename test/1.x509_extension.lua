local openssl = require'openssl'
local ext = require'openssl'.x509.extension
local asn1 = require'openssl'.asn1
TestX509ext = {}

    function TestX509ext:setUp()
        self.timeStamping = openssl.asn1.new_string('timeStamping',asn1.IA5STRING)
        self.cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)
        self.time = {
            object = 'extendedKeyUsage',
            critical = true,
            value = 'timeStamping',
        }
        self.ca = {
            object='basicConstraints',
            value=self.cafalse
        }
        self.cas = {
            object='basicConstraints',
            value='CA:FALSE'
        }
        self.exts = {
            self.time,
            self.ca,
            self.cas
        }
    end

    function TestX509ext:tearDown()
    end

    function TestX509ext:testAll()
        local n1 = ext.new_extension(self.ca)
        assertStrContains(tostring(n1),'openssl.x509_extension')
        local info = n1:info()
        assertIsTable(info)
        assertEquals(info.object:ln(), "X509v3 Basic Constraints")
        assertEquals(info.critical,false)
        assertEquals(info.value:tostring(), "CA:FALSE")

        local n2 = n1:dup()
        assertEquals(n2:info(),info)
        assertEquals(n1:critical(),false)
        n1:critical(true)
        assertEquals(n1:critical(),true)

        local  n2 = ext.new_extension(self.cas)
        assertEquals(n1:object():ln(),'X509v3 Basic Constraints')
        n1:object('extendedKeyUsage')
        assertEquals(n1:object():sn(),'extendedKeyUsage')

        assertEquals(n1:data():tostring(),'CA:FALSE')
        assertErrorMsgEquals('bad argument #2 to \'?\' (asn1_string type must be octet)',n1.data, n1,self.timeStamping)
        assert(n1:data('CA:FALSE'))
        assertEquals(n1:data(), self.cafalse)

        local time = ext.new_extension(self.time)
        assertEquals(time:critical(),true)
        local der = time:export()
        local t1 = ext.read_extension(der)
        assert(der==t1:export())

    end
