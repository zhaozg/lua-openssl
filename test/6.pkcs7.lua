
local csr = require'openssl'.csr
local print_r = require'function.print_r'


require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.cadn = {commonName='zhaozg'}
        self.certdn={commonName='demo'}
        self.digest = 'sha1WithRSAEncryption'
    end


function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,self.cadn))
        t = req:parse()
        print_r(t)

        assert(req:verify());


        local args = {}

        args.attribs = {}
        args.extentions = {}

        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 365


        args.serialNumber = 1
        cacert = assert(req:sign(nil,pkey,args))

        args.serialNumber = 2
        local pkey1 = assert(openssl.pkey.new())
        local req1 = assert(csr.new(pkey1,self.certdn))
        cert1 = assert(req1:sign(cert,pkey,args))

        msg = 'abcd'

        skcert = assert(x509.sk_x509_new({cert1}))
        p7 = assert(pkcs7.encrypt(msg,skcert))
        t = p7:parse()
        print_r(t)
        local ret,signer = assert(pkcs7.decrypt(p7,cert1,pkey1))
        assertEquals(msg,ret)

        -------------------------------------
        p7 = assert(pkcs7.sign(msg,cacert,pkey))
        t = p7:parse()
        print_r(t)

        assert(p7:export())
        skca = assert(x509.sk_x509_new({cacert}))
        local ret,signer = assert(p7:verify(skca,skca))
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
print(openssl.error(true))
