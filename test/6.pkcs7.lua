local csr = require'openssl'.csr
local print_r = require'function.print_r'

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'
        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.dn = openssl.x509.name.new({{commonName='DEMO'},{C='CN'}})

        self.digest = 'sha1WithRSAEncryption'
    end


    function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(self.cadn,pkey))
        local t = req:parse()
        assertEquals(type(t),'table')

        local cacert = openssl.x509.new(
                1,      --serialNumber
                req     --copy name and extensions
        )
        local dkey = openssl.pkey.new()
        req = assert(csr.new(self.dn,dkey))
        
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

        local cert = openssl.x509.new(2,req,extensions)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(pkey,cacert))

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
        skca = assert(x509.sk_x509_new({cacert}))
        local ret,signer = p7:verify(skcert,skca)
        for i=1, 5 do
        print(openssl.error(true))
        end
end

require('luaunit')
io.read()

local lu = LuaUnit
lu:setVerbosity( 0 )
for i=1,1000000 do
lu:run()
end
print(openssl.error(true))
