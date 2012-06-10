local openssl = require'openssl'
require 'util'

--[[
static BIT_STRING_BITNAME ns_cert_type_table[] = {
{0, "SSL Client", "client"},
{1, "SSL Server", "server"},
{2, "S/MIME", "email"},
{3, "Object Signing", "objsign"},
{4, "Unused", "reserved"},
{5, "SSL CA", "sslCA"},
{6, "S/MIME CA", "emailCA"},
{7, "Object Signing CA", "objCA"},
{-1, NULL, NULL}
};

static BIT_STRING_BITNAME key_usage_type_table[] = {
{0, "Digital Signature", "digitalSignature"},
{1, "Non Repudiation", "nonRepudiation"},
{2, "Key Encipherment", "keyEncipherment"},
{3, "Data Encipherment", "dataEncipherment"},
{4, "Key Agreement", "keyAgreement"},
{5, "Certificate Sign", "keyCertSign"},
{6, "CRL Sign", "cRLSign"},
{7, "Encipher Only", "encipherOnly"},
{8, "Decipher Only", "decipherOnly"},
{-1, NULL, NULL}
}; 
--]]

local temp=[[
[test]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment 
extendedKeyUsage = critical,timeStamping
]]

function mk_req(dat)
        local md = openssl.get_digest('sha1')
        local hash = md:digest(dat)
        local req = openssl.ts_req_new(hash,"sha1",{cert_req=1})
        return req, req:i2d()
end

function test_ts_req()
    print(string.rep('-',20),'1. make request')
    local req, rdat =  mk_req('abcd')
    print(string.rep('-',20),'2. parse request')
    dump(req:parse(),0)
    print(openssl.error_string())

    print(string.rep('-',20),'3. create sign cert request')
    local pkey = openssl.pkey_new()
    x = openssl.csr_new(pkey,{commonName='zhaozg'},{digest='md5',extentions={basicConstraints='CA:FALSE',extendedKeyUsage = 'critical,timeStamping',nsCertType='client, email, objsign'}})
    print(string.rep('-',20),'4. parse sign cert request and dump')
    t = x:parse()
    dump(t,0)

    print(string.rep('-',20),'5. self sign,parse and dump')
    x509 = x:sign(nil,pkey,{serialNumber=1,digest='md5',num_days=365},'test')
    t = x509:parse()
    dump(t,0)
    print(openssl.error_string())
    --savefile('ts.cer',x509:export())

    
    print(string.rep('-',20),'6. create tsa sign context,parse and dump')
    ctx = assert(openssl.ts_resp_ctx_new(x509,pkey,nil,'1.1.2',{digest={'md5','sha1'},policy={'1.1.3','1.1.4'} }))
    t = x:parse()
    dump(t,0)

    print(string.rep('-',20),'7. sign tsa request, parse and dump')
    res = ctx:sign(rdat)
    --savefile('ts1.res',res:i2d())
    --f = io.open('CACert.tsr','rb')
    --a = f:read('*a')
    --f:close()
    --res = openssl.ts_resp_d2i(a)
    t = res:parse()
    dump(t,0)
    info = res:tst_info()
    dump(t.tst_info,0)
    print(openssl.error_string())

    print(string.rep('-',20),'8. create verify tsa context from req')
    skx = openssl.sk_x509_new({x509})
    ctx = openssl.ts_verify_ctx_new(req,skx)
    print(0,openssl.error_string())
    print(x509:checkpurpose('timestamp_sign',skx))
    print(1,openssl.error_string())
    print(string.rep('-',20),'9. verify')
    if(ctx:verify_response(res)) then
        print('OK')
    else
        print('NO')
        print(openssl.error_string())
    end

    print(string.rep('-',20),'10. create verify tsa context from data')
    skx = openssl.sk_x509_new({x509})
    ctx = openssl.ts_verify_ctx_new({source='abcd'},skx)
    print(ctx)

    print(0,openssl.error_string())
    print(x509:checkpurpose('timestamp_sign',skx))
    print(1,openssl.error_string())
    print(string.rep('-',20),'9. verify')
    if(ctx:verify_response(res)) then
        print('OK')
    else
        print('NO')
        print(openssl.error_string())
    end

--]]
end
print('ENTER key to continue')
io.read("*l")
test_ts_req()