local csr = require'openssl'.csr

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'
        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.dn = openssl.x509.name.new({{commonName='DEMO'},{C='CN'}})

        self.digest = 'sha1WithRSAEncryption'
    end

    function TestCompat:testNew()
        local cakey = assert(openssl.pkey.new())
        local req = assert(csr.new(self.cadn,cakey))
        local t = req:parse()
        assertEquals(type(t),'table')

        local cacert = openssl.x509.new(
                1,      --serialNumber
                req     --copy name and extensions
        )
        cacert:validat(os.time(), os.time() + 3600*24*361)
        assert(cacert:sign(cakey, cacert))  --self sign

        local dkey = openssl.pkey.new()
        req = assert(csr.new(self.dn,dkey))
        
        local e = openssl.x509.extension.new_extension(
        {
            object='keyUsage',
            value = 'smimesign' 
        },false
        )
        local extensions = 
        openssl.x509.extension.new_sk_extension(
        {{
            object='nsCertType',
            value = 'email',
            --critical = true
        },{
            object='extendedKeyUsage',
            value = 'emailProtection' 
        }})
        --extensions:push(e)
        
        local cert = openssl.x509.new(2,req,extensions)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(cakey,cacert))
        
        msg = 'abcd'
        skcert = assert(x509.sk_x509_new({cert}))
        p7 = assert(pkcs7.encrypt(msg,skcert))
        --t = p7:parse()
        --print_r(t)
        local ret,signer = assert(pkcs7.decrypt(p7,cert,dkey))
        assertEquals(msg,ret)

        -------------------------------------
        p7 = assert(pkcs7.sign(msg,cert,dkey))
        --t = p7:parse()
        --print_r(t)
        assert(p7:export())
        local store = openssl.x509.store.new({cacert})
        local ret,signer = assert(p7:verify(skcert,store))
end

