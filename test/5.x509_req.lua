local openssl = require'openssl'
local csr = require'openssl'.x509.req
local asn1 = require'openssl'.asn1

TestCSR = {}

        function TestCSR:setUp()
                self.digest='md5'
                self.subject = openssl.x509.name.new({
                    {C='CN'},
                    {O='kkhub.com'},
                    {CN='zhaozg'}
                })

                self.timeStamping = openssl.asn1.new_string('timeStamping',asn1.IA5STRING)
                self.cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)

                self.exts = {
                        openssl.x509.extension.new_extension(
                        {
                                object = 'extendedKeyUsage',
                                critical = true,
                                value = 'timeStamping',
                        }),
                        openssl.x509.extension.new_extension({
                                object='basicConstraints',
                                value=self.cafalse
                        }),
                        openssl.x509.extension.new_extension({
                                object='basicConstraints',
                                value='CA:FALSE'
                        })
                }

                self.attrs = {
                        {
                                object = 'extendedKeyUsage',
                                type=asn1.IA5STRING,
                                value = 'timeStamping',
                        },
                        {
                                object='basicConstraints',
                                type=asn1.OCTET_STRING,
                                value=self.cafalse
                        },
                        {
                                object='basicConstraints',
                                type=asn1.OCTET_STRING,
                                value='CA:FALSE'
                        }
                }

                self.extensions = self.exts
                self.attributes = self.attrs
        end

        function TestCSR:testNew()
                local pkey = assert(openssl.pkey.new())
                local req1,req2
                req1 = assert(csr.new())
                req2 = assert(csr.new(pkey))
                local t = req1:parse()
                assertIsTable(t)
                t = req2:parse()
                assertIsTable(t)
                assert(req1:verify()==false);
                assert(req2:verify());

                req1 = assert(csr.new(self.subject))
                req2 = assert(csr.new(self.subject, pkey))

                t = req1:parse()
                assertIsTable(t)
                t = req2:parse()
                assertIsTable(t)
                assert(req1:verify()==false);
                assert(req2:verify());

                req1 = assert(csr.new(self.subject))
                req2 = assert(csr.new(self.subject))
                assert(req2:sign(pkey,'sha1WithRSAEncryption'))
                t = req1:parse()
                assertIsTable(t)
                t = req2:parse()
                assertIsTable(t)

                assert(req1:verify()==false);
                assert(req2:verify());

                req1 = assert(csr.new(self.subject))
                req1:attribute(self.attributes)
                req1:extensions(self.extensions)
                req2 = assert(csr.new(self.subject))
                req2:attribute(self.attributes)
                req2:extensions(self.extensions)
                assert(req2:sign(pkey))
                assert(req1:verify()==false);
                assert(req2:verify());

                t = req1:parse()
                assertIsTable(t)
                t = req2:parse()
                assertIsTable(t)

                assert(req1:verify()==false);
                assert(req2:verify());

                req1 = assert(csr.new(self.subject))
                req1:attribute(self.attributes)
                req1:extensions(self.extensions)
                assert(req1:sign(pkey))
                req2 = assert(csr.new(self.subject))
                req2:attribute(self.attributes)
                req2:extensions(self.extensions)
                assert(req2:sign(pkey,self.digest))

                t = req1:parse()
                assertIsTable(t)
                t = req2:parse()
                assertIsTable(t)

                assert(req1:verify());
                assert(req2:verify());

                local pem = req2:export('pem')
                assertIsString(pem)
                local req2 = assert(csr.read(pem,'pem'))
                assertIsNil(csr.read(pem,'der'))
                req2 = assert(csr.read(pem,'auto'))

                local der = req2:export('der')
                assertIsString(der)
                req2 = assert(csr.read(der,'der'))
                assertIsNil(csr.read(der,'pem'))
                req2 = assert(csr.read(der,'auto'))
                local pubkey = req2:public()
                assertStrContains(tostring(pubkey),"openssl.evp_pkey")
                assert(req1:public(pubkey))

                assertEquals(req1:attr_count(),3+1)
                local attr = req1:attribute(0)
                assertStrContains(tostring(attr),'openssl.x509_attribute')
                attr = req1:attribute(0,nil)
                assertStrContains(tostring(attr),'openssl.x509_attribute')
                assertEquals(req1:attr_count(),2+1)
                req1:attribute(attr)
                assertEquals(req1:attr_count(),3+1)

                assertEquals(req1:version(),0)
                assertEquals(req1:version(1),true)
                assertEquals(req1:version(),1)
                assert(req1:version(0))

                assertEquals(req1:subject():tostring(),self.subject:tostring())
                assert(req1:subject(self.subject))
                assertEquals(req1:subject():tostring(),self.subject:tostring())

                assertStrContains(type(req1:extensions()),'table')
                assert(req1:extensions(self.extensions))
                assertEquals(req1:subject():tostring(),self.subject:tostring())

                local s = req1:digest()
                local r = req1:digest('sha256')
                assertEquals(r,s)
                assert(req2:check(pkey))

                local cert = req2:to_x509(pkey, 3650) -- self sign
                t = cert:parse()
                assert(type(t)=='table')
                assertStrContains(tostring(req1:to_x509(pkey, 3650)),'openssl.x509')
                assertStrContains(tostring(req2:to_x509(pkey, 3650)),'openssl.x509')

        end

function TestCSR:testIO()
local csr_data = [==[
-----BEGIN CERTIFICATE REQUEST-----
MIIBvjCCAScCAQAwfjELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAkJKMRAwDgYDVQQH
EwdYSUNIRU5HMQ0wCwYDVQQKEwRUQVNTMQ4wDAYDVQQLEwVERVZFTDEVMBMGA1UE
AxMMMTkyLjE2OC45LjQ1MRowGAYJKoZIhvcNAQkBFgtzZGZAc2RmLmNvbTCBnzAN
BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0auDcE3VFsp6J3NvyPBiiZLLnAUnUMPQ
lxmGUcbGI12UA3Z0+hNcRprDX5vD7ODUVZrR4iAozaTKUGe5w2KrhElrV/3QGzGH
jMUKvYgtlYr/vK1cAX9wx67y7YBnPbIRVqdLQRLF9Zu8T5vaMx0a/e1dzQq7EvKr
xjPVjCSgZ8cCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAF3sMj2dtIcVTHAnLmHY
lemLpEEo65U7iLJUskUNMsDrNLEVt7kuWlz0uQDnuZ4qgrRVJ2BpxskTR5D5Yzzc
wSpxg0VN6+i6u9C9n4xwCe1VyteOC2In0LbxMAGL3rVFm9yDFRU3LDy3EWG6DIg/
4+QM/GW7qfmes65THZt0Hram
-----END CERTIFICATE REQUEST-----
]==]

        local x = assert(csr.read(csr_data))
        local t = x:parse()
        assertIsTable(t)
        assertIsUserdata(t.subject)
        assertIsNumber(t.version)
        assertIsTable(t.req_info)
        assertIsTable(t.req_info.pubkey)

        assertIsUserdata(t.req_info.pubkey.algorithm)
        assertIsUserdata(t.req_info.pubkey.pubkey)
end
