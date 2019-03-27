local openssl = require'openssl'
local csr = openssl.x509.req
local helper = require'helper'

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'
        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.dn = openssl.x509.name.new({{commonName='DEMO'},{C='CN'}})

        self.digest = 'sha1WithRSAEncryption'
    end


function TestCompat:testNew()
        local pkey, cacert = helper.new_ca(self.cadn)
        local dkey = openssl.pkey.new()
        local req = assert(csr.new(self.dn,dkey))

        local extensions =
        {{
            object='nsCertType',
            value = 'email',
            --critical = true
        },{
            object='extendedKeyUsage',
            value = 'emailProtection'
        }}

        local cert = openssl.x509.new(2,req,extensions)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(pkey,cacert))

        local ss = assert(openssl.pkcs12.export(cert,dkey,'secret','USER'))
        local tt = assert(openssl.pkcs12.read(ss,'secret'))
        assertIsTable(tt)
        assertStrContains(tostring(tt.cert),"openssl.x509")
        assertStrContains(tostring(tt.pkey),"openssl.evp_pkey")
end
