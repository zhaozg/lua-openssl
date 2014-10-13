local openssl = require'openssl'
local print_r = require'function.print_r'
local ts,asn1 = openssl.ts,openssl.asn1
require('luaunit')


local timeStamping = openssl.asn1.new_string('timeStamping','octet')
local timeStamping=asn1.new_type('timeStamping')
timeStamping = timeStamping:i2d()
print(timeStamping)
local cafalse = openssl.asn1.new_string('CA:FALSE','octet')

TestCompat = {}
    function TestCompat:setUp()
        self.alg='sha1'

        self.cadn = {{commonName='CA'},{C='CN'}}
        self.tsadn = {{commonName='tsa'},{C='CN'}}
        
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

    local args = {}
    args.attribs = {}
    args.extentions = {}
    args.digest = 'sha1WithRSAEncryption'
    args.num_days = 3650
    args.serialNumber = 1

    local cakey = assert(openssl.pkey.new())
    local careq = assert(csr.new(openssl.x509.name.new(self.cadn),cakey))
    local cacert = assert(careq:to_x509(cakey))

    local pkey = assert(openssl.pkey.new())
    local subject = openssl.x509.name.new(self.tsadn)
    local attributes = openssl.x509.attribute.new_sk_attribute(
            {
                {
                    object='basicConstraints',
                    type='octet',
                    value=cafalse
                }
            }
        )
    local extensions = 
        openssl.x509.extension.new_sk_extension(
        {{
            object='extendedKeyUsage',
            value = 'timeStamping',
            critical = true
        }})
    x = openssl.csr.new(
        subject,
        pkey
        )
    --t = assert(x:parse())
    --assertEquals(type(t),'table')
    --print_r(t)

    local x509 = openssl.x509.new(
        1,
        x
    )
    assert(x509:validat(os.time(), os.time() + 3600*24*365))
    assert(x509:extensions(extensions))
    assert(x509:sign(cakey,cacert))
    --t = assert(x509:parse())   
    --assertEquals(type(t),'table')
    --print_r(t)
    --[[
    local exts = x509:extensions()
    print('EXTS:',#exts)
    for i=0,#exts-1 do
        e = exts:get(i)
        print(e)
        print_r(e:info())
    end
    --]]
    ---------------------------------------------------
    local req = assert(openssl.ts.req_new())
    assert(req:msg_imprint(self.hash,'sha1'))
    assert(req:cert_req(true))
    local der = assert(req:export())
    local req1 = assert(ts.req_read(der))
    --local t = req1:info()
    --assertIsTable(t)
    --print_r(t)
    
    local req_ctx = assert(ts.resp_ctx_new(x509, pkey, '1.2.3.4.1'))
    assert(req_ctx:md({'md5','sha1'}))
    --assert(req_ctx:policies({'1.1.3','1.1.4'}))
    local res = req_ctx:sign(req)
    --t = assert(res:info())
    --print_r(t)
    --t = res:tst_info()
    --print_r(t)
    
    local vry = assert(ts.verify_ctx_new(req))

    local skx = openssl.x509.sk_x509_new({cacert})
    assert(vry:store(skx))

    assert(x509:check(skx,nil,'timestamp_sign'))
    assertEquals(vry:verify(res),true)

    local vry = assert(ts.verify_ctx_new())
    assert(vry:data(self.dat))
    assert(vry:store(skx))
end

io.read()
local lu = LuaUnit
lu:setVerbosity( 1 )
for i=1,1000000 do
lu:run()
end
print(openssl.error(true))
