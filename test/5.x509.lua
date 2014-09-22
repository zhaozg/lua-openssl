
local csr = require'openssl'.csr
local print_r = require'function.print_r'


require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.cadn = {{commonName='CA'},{C='CN'}}
        self.dn = {{commonName='DEMO'},{C='CN'}}
--[[
        self.attribs = {}
        self.extentions = {}
--]]
        self.digest = 'sha1WithRSAEncryption'
    end

function TestCompat:testNew()
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,self.cadn))
        req = assert(csr.new(pkey,self.cadn,self.attribs))
        req = assert(csr.new(pkey,self.cadn,self.attribs,self.extentions))
        req = assert(csr.new(pkey,self.cadn,self.attribs,self.extentions,self.digest))
        local t = req:parse()
        assertEquals(type(t),'table')

        --print_r(t)
        assert(req:verify());


        local args = {}

        args.attribs = {}
        args.extentions = {}

        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 365


        args.serialNumber = 1
        cert = assert(req:sign(nil,pkey,args))

        local c = cert:get_public():encrypt('abcd')
        d = pkey:decrypt(c)
        assert(d=='abcd')

        assert(cert:check(pkey),'self sign check failed')
        assert(cert:check(openssl.x509.sk_x509_new({cert}) ))
        

        print('sign by cacert',string.rep('-',60))
        args.serialNumber = 2
        local pkey1 = assert(openssl.pkey.new())
        local req1 = assert(csr.new(pkey1,self.dn))
        cert1 = assert(req1:sign(cert,pkey,args))

        local c = cert1:get_public():encrypt('abcd')
        d = pkey1:decrypt(c)
        assert(d=='abcd')
        --print_r(cert1:parse());
        
        assert(cert1:check(pkey1),'self sign check failed')
        assert(cert1:check(openssl.x509.sk_x509_new({cert}) ))
        

        local check = cert1:check(openssl.x509.sk_x509_new({cert}) )
        if(check~=true) then
                print(openssl.error())
                assert(false,"check verify ca")
        end
--]]
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

        local x = assert(x509.read(raw_data))
        t = x:parse()
        assertEquals(type(t),'table')
        --print_r(table)
        assert(x:get_public())
end


local lu = LuaUnit
lu:setVerbosity( 0 )
io.read()
for i=1,1000000 do
        lu:run()
end

