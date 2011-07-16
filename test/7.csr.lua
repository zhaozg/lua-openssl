
local openssl = require('openssl')

function dump(t,i)
        for k,v in pairs(t) do
                if(type(v)=='table') then
                        print( string.rep('\t',i),k..'={')
                                dump(v,i+1)
                        print( string.rep('\t',i),k..'=}')
                else
                        print( string.rep('\t',i),k..'='..tostring(v))
                end
        end
end

function save(data,file)
        local f = assert(io.open(file,'w'))
        f:write(data)
        f:close()
end

function show_csr(csr)
        print(csp,string.rep('-',60))
        local t = csr:parse()
        dump(t,0)
end

function test_new()
        print('产生证书签名请求',string.rep('-',60))
        dn = {commonName='zhaozg'}

        args = {}
        args.attribs = {}
        args.extentions = {}
        args.digest = 'sha1WithRSAEncryption'

        local pkey = openssl.pkey_new()
        csr = openssl.csr_new(pkey,dn,args)
        show_csr(csr)

        print('产生自签名证书',string.rep('-',60))
        
        args = {}
        args.attribs = {}
        args.extentions = {}
        args.digest = 'sha1WithRSAEncryption'
        args.serialNumber = '1234567890123456789012345678'
        args.num_days = 365
        
        x509 = csr:sign(nil,pkey,args)
        
        dump(x509:parse(), 0);

        save(pkey:export(),'key.pem')
        save(x509:export(),'cert.pem')
        
        c = pkey:encrypt('abcd')
        print(#c,c)
        d = x509:get_public():decrypt(c)
        print(#d,d)
        assert(d=='abcd')

        c = x509:public_key():encrypt('abcd')
        print(#c,c)
        d = pkey:decrypt(c)
        print(#d,d)
        assert(d=='abcd')
        
        return csr
end


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

function test_csr()        
        local x = openssl.csr_read(csr_data)
        print(x)
        t = x:parse()
        dump(t,0)
--[[
        local pkey = openssl.pkey_new()
        x = openssl.csr_new(pkey,{commonName='zhaozg'})
        t = x:parse()
        dump(t,0)
        x509 = x:sign(nil,pkey,365)
        t = x509:parse()
        dump(t,0)
        
--]]
end

test_csr()
test_new()
