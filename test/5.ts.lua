local openssl = require'openssl'

local asn1,ts,asn1,csr = openssl.asn1,openssl.ts,openssl.asn1, openssl.x509.req

local timeStamping = openssl.asn1.new_string('timeStamping',asn1.OCTET_STRING)
local timeStamping=asn1.new_type('timeStamping')
timeStamping = timeStamping:i2d()
local cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)

local first = true
TestTS = {}
    function TestTS:setUp()
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
        if first then
            assert(asn1.new_object({oid='1.2.3.4.5.6',sn='1.2.3.4.5.6_sn',ln='1.2.3.4.5.6_ln'}))
            assert(asn1.new_object({oid='1.2.3.4.5.7',sn='1.2.3.4.5.7_sn',ln='1.2.3.4.5.7_ln'}))
            first = false
        end
    end

function TestTS:testAll()
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
    local attributes =
            {
                {
                    object='basicConstraints',
                    type=asn1.OCTET_STRING,
                    value=cafalse
                }
            }
    local extensions =
        {
            openssl.x509.extension.new_extension(
            {
            object='extendedKeyUsage',
            value = 'timeStamping',
            critical = true
        })}
    x = csr.new(
        subject,
        pkey
        )
    t = assert(x:parse())
    assertEquals(type(t),'table')
    --print_r(t)

    local x509 = openssl.x509.new(
        1,
        x
    )
    assert(x509:validat(os.time(), os.time() + 3600*24*365))
    assert(x509:extensions(extensions))
    assert(x509:sign(cakey,cacert))
    t = assert(x509:parse())
    assertEquals(type(t),'table')
    --print_r(t)

    ---------------------------------------------------
    local req = assert(openssl.ts.req_new())
    assert(req:msg_imprint(self.hash,'sha1'))
    assert(req:cert_req(true))
    local der = assert(req:export())
    local req1 = assert(ts.req_read(der))
    local t = req1:info()
    assertIsTable(t)
    --print_r(t)

    local req_ctx = assert(ts.resp_ctx_new(x509, pkey, '1.2.3.4.5.7'))
    assert(req_ctx:md({'md5','sha1'}))
    --assert(req_ctx:policies({'1.1.3','1.1.4'}))
    local res = req_ctx:sign(req)

    t = assert(res:info())
    assertIsTable(t)
    --print_r(t)
    t = res:tst_info()
    assertIsTable(t)
    --print_r(t)

    local skx = openssl.x509.store.new({cacert})

    assert(x509:check(skx,nil,'timestamp_sign'))

    local res = assert(openssl.ts.resp_read(res:export()))
    local vry = assert(req:to_verify_ctx())
    vry:store(skx)
    assert(vry:verify(res))

    local vry = ts.verify_ctx_new(req)
    vry:store(skx)
    assert(vry:verify(res))

    local vry = assert(ts.verify_ctx_new())
    vry:imprint(self.hash)
    vry:store(skx)
    assert(vry:verify(res))

    local vry = assert(ts.verify_ctx_new())
    vry:data(self.dat)
    vry:store(skx)
    assert(vry:verify(res))

    local vry = assert(ts.verify_ctx_new())
    vry:imprint(self.hash)
    vry:data(self.dat)
    vry:store(skx)
    assert(vry:verify(res))
    res = ts.resp_read(res:export())
    vry:verify(res)
end
