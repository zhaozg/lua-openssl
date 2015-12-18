local openssl = require'openssl'

local csr,x509 = openssl.x509.req, openssl.x509

TestX509 = {}
    function TestX509:setUp()
        self.alg='sha1'

        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.dn = openssl.x509.name.new({{commonName='DEMO'},{C='CN'}})

        self.digest = 'sha1WithRSAEncryption'
    end

function TestX509:testNew()
        --cacert, self sign
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(self.cadn,pkey))
        local t = req:parse()
        assertEquals(type(t),'table')

        local cacert = openssl.x509.new(
                1,      --serialNumber
                req     --copy name and extensions
        )

        cacert:validat(os.time(), os.time() + 3600*24*365)
        assert(cacert:sign(pkey, cacert))  --self sign
        assertEquals(cacert:subject(), cacert:issuer())

        local c = cacert:pubkey():encrypt('abcd')
        d = pkey:decrypt(c)
        assert(d=='abcd')
        assert(cacert:check(pkey),'self sign check failed')
        assert(cacert:check(openssl.x509.store.new({cacert}) ))

        --sign cert by cacert

        local dkey = openssl.pkey.new()
        req = assert(csr.new(self.dn,dkey))
        local cert = openssl.x509.new(2,req)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(pkey,cacert))

        local c = cert:pubkey():encrypt('abcd')
        d = dkey:decrypt(c)
        assert(d=='abcd')
        assert(cert:check(dkey),'self private match failed')

        assert(cert:check(openssl.x509.store.new({cacert})))
end

function TestX509:testIO()
local raw_data = [=[
-----BEGIN CERTIFICATE-----
MIIBoDCCAUoCAQAwDQYJKoZIhvcNAQEEBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV
BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD
VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw05NzA5MDkwMzQxMjZa
Fw05NzEwMDkwMzQxMjZaMF4xCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0
YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFzAVBgNVBAMT
DkVyaWMgdGhlIFlvdW5nMFEwCQYFKw4DAgwFAANEAAJBALVEqPODnpI4rShlY8S7
tB713JNvabvn6Gned7zylwLLiXQAo/PAT6mfdWPTyCX9RlId/Aroh1ou893BA32Q
sggwDQYJKoZIhvcNAQEEBQADQQCU5SSgapJSdRXJoX+CpCvFy+JVh9HpSjCpSNKO
19raHv98hKAUJuP9HyM+SUsffO6mAIgitUaqW8/wDMePhEC3
-----END CERTIFICATE-----
]=]

        local x = assert(x509.read(raw_data))

        local t = x:parse()
        assertEquals(type(t),'table')
        assert(x:pubkey())

        assertEquals(x:version(), 0)
        assert(x:notbefore())
        assert(x:notafter())

        print(os.date('%c', x:notafter():get()))

        assertIsNil(x:extensions())

        assert(x:subject())
        assert(x:issuer())


        x = x509.purpose()
        assert(#x==9)
end
