
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

