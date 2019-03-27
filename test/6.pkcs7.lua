local openssl = require'openssl'
local pkcs7,csr = openssl.pkcs7,openssl.x509.req
local helper = require'helper'

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'
        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.dn = openssl.x509.name.new({{commonName='DEMO'},{C='CN'}})

        self.digest = 'sha1WithRSAEncryption'
    end

    function TestCompat:testNew()
        local cakey, cacert = helper.new_ca(self.cadn)
        local dkey = openssl.pkey.new()
        local req = assert(csr.new(self.dn,dkey))

        local e = openssl.x509.extension.new_extension(
        {
            object='keyUsage',
            value = 'smimesign'
        },false
        )
        assert(e)
        local extensions =
        {{
            object='nsCertType',
            value = 'email',
            --critical = true
        },{
            object='extendedKeyUsage',
            value = 'emailProtection'
        }}
        --extensions:push(e)

        local cert = openssl.x509.new(2,req,extensions)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(cakey,cacert))

        local msg = 'abcd'

        local skcert = {cert}
        local p7 = assert(pkcs7.encrypt(msg,skcert))
        local ret,signer = assert(pkcs7.decrypt(p7,cert,dkey))
        assertEquals(msg,ret)
        assert(signer)
        -------------------------------------
        p7 = assert(pkcs7.sign(msg,cert,dkey))
        assert(p7:export())
        local store = openssl.x509.store.new({cacert})
        ret,signer = assert(p7:verify(skcert,store))
        assert(ret)
        assert(signer)
    end

    function TestCompat:testStep()
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
        assert(e)
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
        assert(cert:sign(cakey,cacert))

        local msg = 'abcd'

        local md = openssl.digest.get('sha1')
        local mdc = md:new()
        mdc:update(msg)
        mdc:update(msg)
        local hash = mdc:data()
        local p7 = assert(openssl.pkcs7.new())
        --assert(p7:add(cert))
        assert(p7:add_signer(cert,dkey,md))
        local pp7 = p7:sign_digest(hash,pkcs7.DETACHED,true)
        assert(pp7)

        local ret,signer = assert(p7:verify(nil,nil,msg..msg,pkcs7.DETACHED))
        assert(ret)
        assert(signer)
        ret,signer = assert(p7:verify_digest(nil,nil,hash,pkcs7.DETACHED,true))
        assert(ret)
        assert(signer)
    end

