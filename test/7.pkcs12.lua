
local csr = require'openssl'.csr
local print_r = require'function.print_r'


require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.dn = {commonName='zhaozg'}
        self.digest = 'sha1WithRSAEncryption'
    end


function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,self.dn))
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
        local req1 = assert(csr.new(pkey1,{CN='user'}))
        cert1 = assert(req1:sign(cert,pkey,args))

        local cask = assert(x509.sk_x509_new({cacert}))

        local ss = assert(openssl.pkcs12.export(cert1,pkey1,'secret','USER'))
        local tt = assert(openssl.pkcs12.read(ss,'secret'))
        print_r(tt)
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
print(openssl.error(true))

