
local csr = require'openssl'.csr
local print_r = require'function.print_r'


require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.dn = {{commonName='zhaozg'},{C='CN'}}
--[[
        self.attribs = {}
        self.extentions = {}
--]]
        self.digest = 'sha1WithRSAEncryption'
    end

function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,self.dn))
        t = req:parse()
        --print_r(t)

        assert(req:verify());


        local args = {}

        args.attribs = {}
        args.extentions = {}

        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 365


        args.serialNumber = 1
        cacert = assert(req:sign(nil,pkey,args))

        cacert:parse()
        local list = assert(crl.new(cacert))

        assert(list:add('1234',os.time()))
        assert(list:sign(pkey))
        assert(list:verify(cacert))
        assert(list:export())

        local list = assert(crl.new())

        assert(list:add('1234',os.time()))
        assert(list:set_issuer(cacert))
        assert(list:sign(pkey))
        assert(list:verify(cacert))
        assert(list:export())

end

io.read()
local lu = LuaUnit
lu:setVerbosity( 0 )
for i=1,1000000 do
lu:run()
end

