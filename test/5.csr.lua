local csr = require'openssl'.csr
local print_r = require'function.print_r'

require('luaunit')



require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.dn = {commonName='zhaozg'}
--[[
        self.attribs = {}
        self.extentions = {}
--]]
        self.digest = 'sha1WithRSAEncryption'
    end

function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,self.dn))
        req = assert(csr.new(pkey,self.dn,self.attribs))
        req = assert(csr.new(pkey,self.dn,self.attribs,self.extentions))
        req = assert(csr.new(pkey,self.dn,self.attribs,self.extentions,self.digest))
        t = req:parse()
        print_r(t)

        assert(req:verify());


        local args = {}

        args.attribs = {}
        args.extentions = {}

        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 365


        args.serialNumber = 1
        cert = assert(req:sign(nil,pkey,args))

        print('产生自签名证书',string.rep('-',60))
        print_r(cert:parse());

        local c = pkey:encrypt('abcd')
        local d = cert:get_public():decrypt(c)
        assert(d=='abcd')

        local c = cert:get_public():encrypt('abcd')
        d = pkey:decrypt(c)
        assert(d=='abcd')
end

function TestCompat:testIO()
local csr_data = [[
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
]]

        local x = csr.read(csr_data)
        print(x)
        t = x:parse()
        print_r(t)
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
