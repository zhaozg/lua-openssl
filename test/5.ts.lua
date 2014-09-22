local openssl = require'openssl'
local print_r = require'function.print_r'

require('luaunit')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.cadn = {{commonName='CA'},{C='CN'}}
        self.digest = 'sha1WithRSAEncryption'
        self.md = openssl.digest.get('sha1WithRSAEncryption')
        self.dat=[[
[test]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = critical,timeStamping
]]
        self.hash = assert(self.md:digest(self.dat))
    end

function TestCompat:testAll()

    local cakey = assert(openssl.pkey.new())
    local careq = assert(csr.new(cakey,self.cadn))

    local args = {}
    args.attribs = {}
    args.extentions = {}
    args.digest = 'sha1WithRSAEncryption'
    args.num_days = 3650
    args.serialNumber = 1

    local cacert = assert(careq:sign(nil,cakey,args))
--[[
    --x = openssl.csr.new(pkey,{{commonName='zhaozg'},{C='CN'}},nil,{basicConstraints='CA:FALSE',extendedKeyUsage = 'critical,timeStamping',nsCertType='client, email, objsign'})
    local pkey = assert(openssl.pkey.new())
    x = openssl.csr.new(pkey,{{commonName='zhaozg'},{C='CN'}},nil,{{basicConstraints='CA:FALSE'},{extendedKeyUsage = 'critical,timeStamping'}})
    t = assert(x:parse())
    --assertEquals(type(t),'table')

    x509 = x:sign(cacert,cakey,{serialNumber=1,digest='md5',num_days=365})
    t = assert(x509:parse())
    --assertEquals(type(t),'table')
    local req = assert(openssl.ts.req_new(self.hash,"sha1",{cert_req=1}))

    local der = assert(req:i2d())

    req = assert(openssl.ts.d2i(der)) 
    assertEquals(type(req:parse()),'table')

    ctx = assert(openssl.ts.resp_ctx_new(x509,pkey,nil,'1.1.2',{digest={'md5','sha1'},policy={'1.1.3','1.1.4'} }))
    t = x:parse()
    print_r(t)
    assertEquals(type(t),'table')

    res = ctx:sign(req)
    t = assert(res:parse())

    --print_r(t)

    info = res:tst_info()
    print(info)
    if t then
      local apr = require'apr'
      print(string.rep('-',78))
      print(apr.base64_encode(res:i2d()) )
      print(string.rep('-',78))
    end

    skx = openssl.x509.sk_x509_new({cacert})
    ctx = assert(openssl.ts.verify_ctx_new(req,skx))
    assert(x509:check(skx,nil,'timestamp_sign'))

    assertEquals(true,ctx:verify_response(res))

    skx = openssl.x509.sk_x509_new({cacert})
    ctx = assert(openssl.ts.verify_ctx_new(der,skx))
    assert(x509:check(skx,nil,'timestamp_sign'))

    assertEquals(true,ctx:verify_response(res))

    skx = openssl.x509.sk_x509_new({cacert})
    ctx = assert(openssl.ts.verify_ctx_new({source=self.dat},skx))

    assertEquals(true,ctx:verify_response(res))
--]]
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
for i=1,1000000 do
lu:run()
end
print(openssl.error(true))
