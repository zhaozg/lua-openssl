local openssl = require'openssl'

local asn1,ts,csr = openssl.asn1,openssl.ts, openssl.x509.req

local policy_oid = '1.2.3.4.100'
local policy_obj = assert(asn1.new_object(policy_oid))
local policies = {assert(asn1.new_object('1.1.3')),assert(asn1.new_object('1.1.4'))}
local obja = assert(asn1.new_object({oid='1.2.3.4.5.6',sn='1.2.3.4.5.6_sn',ln='1.2.3.4.5.6_ln'}))
local objb = assert(asn1.new_object({oid='1.2.3.4.5.7',sn='1.2.3.4.5.7_sn',ln='1.2.3.4.5.7_ln'}))

testTSRequest = {}

    function testTSRequest:setUp()
        self.msg = 'abcd'
        self.alg = 'sha1'
        self.hash = assert(openssl.digest.digest(self.alg, self.msg, true))
    end

    function testTSRequest:testReq1()
        local req = assert(openssl.ts.req_new())
        assert(req:msg_imprint(self.hash, self.alg))
        assert(req:cert_req(true))
        local der = assert(req:export())
        local req1 = assert(ts.req_read(der))
        local t = req1:info()
        assertIsTable(t)
        assertEquals(t.cert_req,true)
        assertEquals(t.version,1)
        assertEquals(t.msg_imprint.hashed_msg,self.hash)
        assertEquals(t.msg_imprint.hash_algo:tostring(), self.alg)
        return req
    end

    function testTSRequest:testReq2()
        local req = assert(openssl.ts.req_new())
        assert(req:msg_imprint(self.hash, self.alg))
        local nonce = openssl.bn.text(openssl.random(16))
        assert(req:nonce(nonce))

        local der = assert(req:export())
        local req1 = assert(ts.req_read(der))
        local t = req1:info()
        assertIsTable(t)
        assertEquals(t.cert_req,false)
        assertEquals(t.version,1)

        assertEquals(t.nonce:data(), nonce:totext())
        assertEquals(t.msg_imprint.hashed_msg,self.hash)
        assertEquals(t.msg_imprint.hash_algo:tostring(), self.alg)
        self.nonce = nonce
        return req
    end

    function testTSRequest:testReq3()
        local req = assert(openssl.ts.req_new())
        assert(req:msg_imprint(self.hash, self.alg))
        local nonce = openssl.bn.text(openssl.random(16))
        assert(req:nonce(nonce))

        assert(req:policy_id(policy_obj))

        local der = assert(req:export())
        local req1 = assert(ts.req_read(der))
        local t = req1:info()
        assertIsTable(t)
        assertEquals(t.cert_req,false)
        assertEquals(t.version,1)

        assertEquals(t.nonce:data(), nonce:totext())
        assertEquals(t.policy_id:data(), policy_oid)
        assertEquals(t.msg_imprint.hashed_msg,self.hash)
        assertEquals(t.msg_imprint.hash_algo:tostring(), self.alg)
        return req
    end

testTSSign = {}

    function testTSSign:setUp()
        local timeStamping = openssl.asn1.new_string('timeStamping',asn1.OCTET_STRING)
        timeStamping = asn1.new_type('timeStamping')
        self.timeStamping = timeStamping:i2d()
        self.cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)

        self.dat=[[
[test]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = critical,timeStamping
]]
        self.alg='sha1'
        self.digest = 'sha1WithRSAEncryption'
        self.md = openssl.digest.get('sha1WithRSAEncryption')
        self.hash = assert(self.md:digest(self.dat))

        --setUp private key and certificate
        local ca = {}
        self.ca = ca
        ca.dn = {{commonName='CA'},{C='CN'}}
        ca.pkey = assert(openssl.pkey.new())
        local subject = assert(openssl.x509.name.new(ca.dn))
        ca.req = assert(csr.new(subject,ca.pkey))
        ca.cert = assert(ca.req:to_x509(ca.pkey))

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

        local args = {}
        args.attribs = {}
        args.extentions = {}
        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 3650
        args.serialNumber = 1
    end

    function testTSSign:testSign1()
        testTSRequest:setUp()
        local req = testTSRequest:testReq1()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)
        assert(t.status_info.status:tostring()=='02')
        assertEquals(#t.status_info.text,1)
        assertEquals(t.status_info.text[1],'Error during response generation.')
    end

    function testTSSign:testSign2()
        testTSRequest:setUp()
        local req = testTSRequest:testReq2()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        res = assert(openssl.ts.resp_read(res:export()))
        local vry = assert(req:to_verify_ctx())
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign3()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        res = assert(openssl.ts.resp_read(res:export()))
        local vry = assert(req:to_verify_ctx())
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign4()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        res = assert(openssl.ts.resp_read(res:export()))
        local vry = ts.verify_ctx_new(req)
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign5()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        local vry = assert(ts.verify_ctx_new())
        vry:imprint(self.hash)
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign6()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        local vry = assert(ts.verify_ctx_new())
        vry:data(self.dat)
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign7()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        local vry = assert(ts.verify_ctx_new())
        vry:imprint(self.hash)
        vry:data(self.dat)
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

    function testTSSign:testSign8()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        assert(req_ctx:policies(policies))
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),'01')
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)
        local now = os.time()
        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())

        local vry = assert(ts.verify_ctx_new())
        vry:imprint(self.hash)
        vry:data(self.dat)
        vry:store(self.ca.store)
        assert(vry:verify(res))
    end

testTSComplex = {}

    function testTSComplex:setUp()
        local timeStamping = openssl.asn1.new_string('timeStamping',asn1.OCTET_STRING)
        timeStamping = asn1.new_type('timeStamping')
        self.timeStamping = timeStamping:i2d()
        self.cafalse = openssl.asn1.new_string('CA:FALSE',asn1.OCTET_STRING)

        self.dat=[[
[test]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = critical,timeStamping
]]
        self.alg='sha1'
        self.digest = 'sha1WithRSAEncryption'
        self.md = openssl.digest.get('sha1WithRSAEncryption')
        self.hash = assert(self.md:digest(self.dat))

        --setUp private key and certificate
        local ca = {}
        self.ca = ca
        ca.dn = {{commonName='CA'},{C='CN'}}
        ca.pkey = assert(openssl.pkey.new())
        local subject = assert(openssl.x509.name.new(ca.dn))
        ca.req = assert(csr.new(subject,ca.pkey))
        ca.cert = assert(ca.req:to_x509(ca.pkey))

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

        local args = {}
        args.attribs = {}
        args.extentions = {}
        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 3650
        args.serialNumber = 1
    end

    function testTSComplex:testCallback()
        testTSRequest:setUp()
        local req = testTSRequest:testReq3()

        local tsa = self.tsa
        local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, policy_obj))
        assert(req_ctx:md({'md5','sha1'}))
        assert(req_ctx:policies(policies))

        local sn = 0
        req_ctx:set_serial_cb(function(self)
            sn = sn + 1
            return sn
        end)

        local now = os.time()
        req_ctx:set_time_cb(function(self)
            return now
        end)

        assert(pcall(function()
        local res = req_ctx:sign(req)
        local t = assert(res:info())
        assertIsTable(t)

        assert(t.status_info.status:tostring()=='0')
        assert(not t.status_info.text)
        assert(not t.status_info.failure_info)
        assertIsTable(t.tst_info)
        assertIsUserdata(t.token)

        local tst = t.tst_info
        assertEquals(tst.serial:tostring(),string.format('%02x',sn))
        assertEquals(tst.version,1)
        assertEquals(tst.ordering,false)
        assertEquals(tst.policy_id:txt(true),policy_oid)

        local function get_timezone()
          local now = os.time()
          return os.difftime(now, os.time(os.date("!*t", now)))
        end
        local timezone = get_timezone()

        assertEquals(tst.time:tostring(),os.date('%Y%m%d%H%M%SZ',now-timezone))
        assertIsString(tst.nonce:tostring())
        local vry = assert(ts.verify_ctx_new())
        vry:imprint(self.hash)
        vry:data(self.dat)
        vry:store(self.ca.store)
        assert(vry:verify(res))

        end))
    end
