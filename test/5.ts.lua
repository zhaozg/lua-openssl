local openssl = require'openssl'
local helper = require'helper'

local asn1,ts,csr = openssl.asn1,openssl.ts, openssl.x509.req

local policy_oid = '1.2.3.4.100'
local policy_obj = assert(asn1.new_object(policy_oid))
local policies = {assert(asn1.new_object('1.1.3')),assert(asn1.new_object('1.1.4'))}
local obja = assert(asn1.new_object({oid='1.2.3.4.5.6',sn='1.2.3.4.5.6_sn',ln='1.2.3.4.5.6_ln'}))
local objb = assert(asn1.new_object({oid='1.2.3.4.5.7',sn='1.2.3.4.5.7_sn',ln='1.2.3.4.5.7_ln'}))

local function get_timezone()
    local now = os.time()
    return os.difftime(now, os.time(os.date("!*t", now)))
end
--[[
typedef struct TS_req_st {
	ASN1_INTEGER *version;
	TS_MSG_IMPRINT *msg_imprint;
	ASN1_OBJECT *policy_id;		/* OPTIONAL */
	ASN1_INTEGER *nonce;		/* OPTIONAL */
	ASN1_BOOLEAN cert_req;		/* DEFAULT FALSE */
	STACK_OF(X509_EXTENSION) *extensions;	/* [0] OPTIONAL */
} TS_REQ;
--]]

local function createQuery(self, policy_id, nonce, cert_req, extensions)
    local req = assert(openssl.ts.req_new())
    assert(req:msg_imprint(self.hash, self.alg))
    if cert_req~=nil then
        assert(req:cert_req(cert_req))
    else
        cert_req = false
    end
    if policy_id then
        assert(req:policy_id(policy_id))
    end
    if nonce then
        assert(req:nonce(nonce))
    end
    if extensions then
        assert(req:extensions(extensions))
    end

    local der = assert(req:export())
    local ano = assert(ts.req_read(der))
    local t = ano:info()
    assertIsTable(t)
    assertEquals(t.version,1)
    assertEquals(t.msg_imprint.hashed_msg, self.hash)
    assertEquals(t.msg_imprint.hash_algo:tostring(), self.alg)
    assertEquals(cert_req, t.cert_req)
    if nonce then
       assertEquals(t.nonce:data(), nonce:totext())
    else
       assertEquals(nil, t.nonce)
    end
    if policy_id then
        assert(policy_id:equals(t.policy_id))
        assert(policy_id:equals(ano:policy_id()))
        assert(policy_id:data(), t.policy_id:data())
        assert(ano:policy_id():data(), t.policy_id:data())
    end
    if extensions then
        assert(req:extensions())
    end

    return req
end

local function createTsa(self)
    --setUp private key and certificate
    local ca = {}
    self.ca = ca
    ca.dn = {{commonName='CA'},{C='CN'}}
    ca.pkey = assert(openssl.pkey.new())
    local subject = assert(openssl.x509.name.new(ca.dn))
    ca.req = assert(csr.new(subject,ca.pkey))
    ca.cert = assert(ca.req:to_x509(ca.pkey))

    local extensions =
    {
        openssl.x509.extension.new_extension(
        {
        object='extendedKeyUsage',
        value = 'timeStamping',
        critical = true
    })}

    local tsa = {}
    self.tsa = tsa
    tsa.dn  = {{commonName='tsa'},{C='CN'}}
    tsa.pkey = assert(openssl.pkey.new())
    subject = openssl.x509.name.new(tsa.dn)

    tsa.req = csr.new(subject,tsa.pkey)
    assertEquals(type(tsa.req:parse()),'table')

    tsa.cert = openssl.x509.new(1, tsa.req)
    assert(tsa.cert:validat(os.time(), os.time() + 3600*24*365))
    assert(tsa.cert:extensions(extensions))
    assert(tsa.cert:sign(ca.pkey,ca.cert))

    assertEquals(type(tsa.cert:parse()),'table')

    ca.store = openssl.x509.store.new({ca.cert})
    assert(tsa.cert:check(ca.store,nil,'timestamp_sign'))
    self.tsa = tsa
    return tsa
end

local function createRespCtx(self, serial_cb, time_cb)
    local tsa = self.tsa
    local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, self.policy_id))
    assert(req_ctx:md({'md5','sha1'}))

    if serial_cb then
        req_ctx:set_serial_cb(serial_cb, self)
    end

    if time_cb then
        req_ctx:set_time_cb(time_cb, self)
    end
    return req_ctx
end

local function signReq(self,req_ctx, req, sn, now)
    local res = req_ctx:sign(req:export())
    local t = assert(res:info())
    assertIsTable(t)

    assert(t.status_info.status:tostring()=='0')
    assert(not t.status_info.text)
    assert(not t.status_info.failure_info)
    assertIsTable(t.tst_info)
    assertIsUserdata(t.token)

    local tst = t.tst_info
    sn = sn or '01'
    assertEquals(sn, tst.serial:tostring())
    assertEquals(1, tst.version)
    assertEquals(tst.ordering,false)
    assertEquals(self.policy_id:txt(true), tst.policy_id:txt(true))

    if not now then
        now = os.time()
        local timezone = get_timezone()
        now = os.date('%Y%m%d%H%M%SZ', now-timezone)
    end
    assertEquals(tst.time:tostring(), now)

    if req:nonce() then
        assertIsString(tst.nonce:tostring())
        assertEquals(req:nonce(), tst.nonce)
    end

    res = assert(openssl.ts.resp_read(res:export()))
    local vry = assert(req:to_verify_ctx())
    vry:store(self.ca.store)
    assert(vry:verify(res))

    vry = assert(ts.verify_ctx_new())
    vry:imprint(self.hash)
    vry:store(self.ca.store)
    assert(vry:verify(res))

    vry = assert(ts.verify_ctx_new())
    vry:data(self.dat)
    vry:store(self.ca.store)
    assert(vry:verify(res))

    vry = assert(ts.verify_ctx_new())
    vry:imprint(self.hash)
    vry:data(self.dat)
    vry:store(self.ca.store)
    assert(vry:verify(res))
end

testTS = {}

    function testTS:setUp()
        math.randomseed(os.time())
        self.msg = 'abcd'
        self.alg = 'sha1'
        self.hash = assert(openssl.digest.digest(self.alg, self.msg, true))
        --FIXME: libressl will crash random
        if not helper.libressl then
            self.nonce = openssl.bn.text(openssl.random(16))
        end
        self.digest = 'sha1WithRSAEncryption'
        self.md = openssl.digest.get('sha1WithRSAEncryption')
        self.policy_id = policy_obj

        local der = policy_obj:i2d()
        local ano = openssl.asn1.new_object()
        assert(ano:d2i(der))
        assert(ano:equals(policy_obj))

        local timeStamping = asn1.new_type('timeStamping')
        self.timeStamping = timeStamping:i2d()
        self.cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)

        self.dat=openssl.random(256)
        assert(createTsa(self))
    end

    function testTS:testBasic()
        local req = createQuery(self)
        local req_ctx = createRespCtx(self)
        assertEquals(false, req:cert_req())
        signReq(self, req_ctx, req)
    end
    function testTS:testPloicyId()
        --FIXME: libressl will crash random
        if not helper.libressl then
            local req = createQuery(self, self.policy_id, nil, true)
            local req_ctx = createRespCtx(self)
            signReq(self, req_ctx, req)
        end
    end
    function testTS:testCertReq()
        local req = createQuery(self, nil, nil, true)
        local req_ctx = createRespCtx(self)
        assert(req:cert_req())
        signReq(self, req_ctx, req)
    end

    function testTS:testNonce()
        local req = createQuery(self, nil, self.nonce)
        local req_ctx = createRespCtx(self)
        assert(helper.libressl or req:nonce())
        signReq(self, req_ctx, req)
    end

    --FIXME: real do it
    function testTS:testExtensions()
        local extensions = nil
        local req = createQuery(self, nil, nil, extensions)
        local req_ctx = createRespCtx(self)
        signReq(self, req_ctx, req)
    end

    function testTS:testSerialCallback()
        local req = createQuery(self)

        local serial_cb = function(self)
            self.sn = 0x7fffffff;
            return self.sn
        end
        local req_ctx = createRespCtx(self, serial_cb)
        signReq(self, req_ctx, req, '7FFFFFFF')
    end

    function testTS:testTimeCallback()
        local req = createQuery(self)

        local time_cb = function(self)
            self.time = 0x7fffffff;
            return self.time
        end
        local req_ctx = createRespCtx(self, nil, time_cb)
        signReq(self, req_ctx, req, nil, '20380119031407Z')
    end

