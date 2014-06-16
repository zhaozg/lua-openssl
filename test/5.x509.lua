
local csr = require'openssl'.csr
local print_r = require'function.print_r'


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

        print('Self Sign Cert',string.rep('-',60))

        local c = pkey:encrypt('abcd')
        local d = cert:get_public():decrypt(c)
        assert(d=='abcd')

        local c = cert:get_public():encrypt('abcd')
        d = pkey:decrypt(c)
        assert(d=='abcd')

        print('sign by cacert',string.rep('-',60))

        args.serialNumber = 2
        local pkey1 = assert(openssl.pkey.new())
        local req1 = assert(csr.new(pkey1,self.dn))
        cert1 = assert(req1:sign(cert,pkey,args))

        local c = pkey:encrypt('abcd')
        local d = cert:get_public():decrypt(c)
        assert(d=='abcd')

        local c = cert:get_public():encrypt('abcd')
        d = pkey:decrypt(c)
        assert(d=='abcd')


        print_r(cert1:parse());
end

function TestCompat:testIO()
local raw_data = [[
-----BEGIN CERTIFICATE-----
MIIBoTCCAQqgAwIBAgIMA/016215epG+OPNOMA0GCSqGSIb3DQEBBQUAMBExDzAN
BgNVBAMTBnpoYW96ZzAeFw0xMTA3MDYwNTI3MDlaFw0xMjA3MDUwNTI3MDlaMBEx
DzANBgNVBAMTBnpoYW96ZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAy48u
FWSdZmSET1gdJqczdL6jxxssCCq/lEthPj9SRr1iZl/lkZ95VhwA/llJHVLpOA4m
DjIJd8jFW+g/Bo2XyqHa2unSHtYW7xT6iUMAQOGlvkF81NtXzmEffFNAj4Ud/T2r
pKdFY/5YZI+CFCi6m1hT/xbwR84bASL/dBXoOOUCAwEAATANBgkqhkiG9w0BAQUF
AAOBgQA8LAd0UXbzPN6v1lIM4KcR88mH/SKeRvNXJqv8JEF4qosXr6wN0XT4bIqN
fv/5OBot6ECcEm8aeGR08gBmjtsQAYtGc07ksvzYtytKsGWdcTLAf/+K2bKg6VGy
pM4KW8DPKCZ16zylyzRbVKbQJ/sjcCPqd55M3THg2gRnxywalw==
-----END CERTIFICATE-----
]]

        local x = x509.read(raw_data)
        print(x)
        t = x:parse()
        print_r(t)
        assert(x:get_public())
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()

