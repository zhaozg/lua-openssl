local openssl = require'openssl'
local print_r = require'function.print_r'


require('luaunit')



TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.dn = {commonName='zhaozg'}
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
    local req = assert(openssl.ts.req_new(self.hash,"sha1",{cert_req=1}))

    local der = assert(req:i2d())
    --req = assert(openssl.ts.d2i(der)) bugs
    --assert(type(req:parse())=='table')
    assertEquals(type(req:parse()),'table')

    local pkey = assert(openssl.pkey.new())
    x = openssl.csr.new(pkey,{commonName='zhaozg'},nil,{basicConstraints='CA:FALSE',extendedKeyUsage = 'critical,timeStamping',nsCertType='client, email, objsign'})
    t = assert(x:parse())
    assertEquals(type(t),'table')

    x509 = x:sign(nil,pkey,{serialNumber=1,digest='md5',num_days=365})
    t = assert(x509:parse())
    assertEquals(type(t),'table')

    ctx = assert(openssl.ts.resp_ctx_new(x509,pkey,nil,'1.1.2',{digest={'md5','sha1'},policy={'1.1.3','1.1.4'} }))
    t = x:parse()
    --print_r(t)
    assertEquals(type(t),'table')

    res = ctx:sign(req)
    t = assert(res:parse())
    print_r(t)
    info = res:tst_info()
    print_r(info)


    skx = openssl.x509.sk_x509_new({x509})
    ctx = assert(openssl.ts.verify_ctx_new(req,skx))
    assert(x509:check(skx,nil,'timestamp_sign'))

    assertEquals(true,ctx:verify_response(res))

    skx = openssl.x509.sk_x509_new({x509})
    ctx = assert(openssl.ts.verify_ctx_new(der,skx))
    assert(x509:check(skx,nil,'timestamp_sign'))

    assertEquals(true,ctx:verify_response(res))

    skx = openssl.x509.sk_x509_new({x509})
    ctx = assert(openssl.ts.verify_ctx_new({source=self.dat},skx))

    assertEquals(true,ctx:verify_response(res))

end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
lu:run()
print(openssl.error(true))
