local lu = require 'luaunit'
local openssl = require 'openssl'
local helper = require 'helper'

local asn1, ts, csr = openssl.asn1, openssl.ts, openssl.x509.req

local policy_oid = '1.2.3.4.100'
local policy_obj = assert(asn1.new_object(policy_oid))
local policies = {
  assert(asn1.new_object('1.1.3')),  assert(asn1.new_object('1.1.4'))
}
local obja = assert(asn1.new_object({
  oid = '1.2.3.4.5.6',
  sn = '1.2.3.4.5.6_sn',
  ln = '1.2.3.4.5.6_ln'
}))
local objb = assert(asn1.new_object({
  oid = '1.2.3.4.5.7',
  sn = '1.2.3.4.5.7_sn',
  ln = '1.2.3.4.5.7_ln'
}))
assert(policies)
assert(obja)
assert(objb)

local function get_timezone()
  local now = os.time()
  return os.difftime(now, os.time(os.date("!*t", now)))
end

local function notAfter(a, b)
  a = a:sub(1, -2)
  b = b:sub(1, -2)
  return a <= b
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
  local m, a = req:msg_imprint()
  assert(m and a)
  if cert_req ~= nil then
    assert(req:cert_req(cert_req))
  else
    cert_req = false
  end
  if policy_id then assert(req:policy_id(policy_id)) end
  if nonce then assert(req:nonce(nonce)) end
  if extensions then assert(req:extensions(extensions)) end

  local der = assert(req:export())
  local ano = assert(ts.req_read(der))
  local t = ano:info()
  lu.assertIsTable(t)
  lu.assertEquals(t.version, 1)
  lu.assertEquals(t.msg_imprint.hashed_msg, self.hash)
  lu.assertEquals(t.msg_imprint.hash_algo:tostring(), self.alg)
  lu.assertEquals(cert_req, t.cert_req)
  if nonce then
    lu.assertEquals(t.nonce:totext(), nonce:totext())
  else
    lu.assertEquals(nil, t.nonce)
  end
  if policy_id then
    assert(policy_id:equals(t.policy_id))
    assert(policy_id:equals(ano:policy_id()))
    assert(policy_id:data(), t.policy_id:data())
    assert(ano:policy_id():data(), t.policy_id:data())
  end
  if extensions then assert(req:extensions()) end
  return req
end

local function createTsa(self)
  -- setUp private key and certificate
  local ca = {}
  self.ca = ca
  ca.dn = {{commonName = 'CA'},  {C = 'CN'}}
  ca.pkey = assert(openssl.pkey.new())
  local subject = assert(openssl.x509.name.new(ca.dn))
  ca.req = assert(csr.new(subject, ca.pkey))
  ca.cert = assert(ca.req:to_x509(ca.pkey))

  local extensions = {
    openssl.x509.extension.new_extension(
      {object = 'extendedKeyUsage',  value = 'timeStamping',  critical = true})
  }

  local tsa = {}
  self.tsa = tsa
  tsa.dn = {{commonName = 'tsa'},  {C = 'CN'}}
  tsa.pkey = assert(openssl.pkey.new())
  subject = openssl.x509.name.new(tsa.dn)

  tsa.req = csr.new(subject, tsa.pkey)
  lu.assertEquals(type(tsa.req:parse()), 'table')

  tsa.cert = openssl.x509.new(1, tsa.req)
  assert(tsa.cert:validat(os.time(), os.time() + 3600 * 24 * 365))
  assert(tsa.cert:extensions(extensions))
  assert(tsa.cert:sign(ca.pkey, ca.cert))

  lu.assertEquals(type(tsa.cert:parse()), 'table')

  ca.store = openssl.x509.store.new({ca.cert})
  assert(tsa.cert:check(ca.store, nil, 'timestamp_sign'))
  self.tsa = tsa
  return tsa
end

local function createRespCtx(self, serial_cb, time_cb)
  local tsa = self.tsa
  local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, self.policy_id))
  assert(req_ctx:md({'md5',  'sha1'}))

  if serial_cb then req_ctx:set_serial_cb(serial_cb, self) end

  if time_cb then req_ctx:set_time_cb(time_cb, self) end
  assert(req_ctx:md('sha256')==true)
  return req_ctx
end

local function signReq(self, req_ctx, req, sn, now)
  local res = req_ctx:sign(req:export())
  local t = assert(res:info())
  lu.assertIsTable(t)
  local status = t.status_info.status:tonumber()
  --FIXME: libressl
  if status ~= 0 then
    return
  end
  assert(t.status_info.status:tostring() == '0')
  assert(not t.status_info.text)
  assert(not t.status_info.failure_info)
  lu.assertIsTable(t.tst_info)
  lu.assertIsUserdata(t.token)

  local tst = t.tst_info
  sn = sn or '01'
  lu.assertEquals(sn, tst.serial:tohex())
  lu.assertEquals(1, tst.version)
  lu.assertEquals(tst.ordering, false)
  lu.assertEquals(self.policy_id:txt(true), tst.policy_id:txt(true))

  if not now then
    now = os.time()
    local timezone = get_timezone()
    now = os.date('%Y%m%d%H%M%SZ', now - timezone + 1)
  end
  assert(notAfter(tst.time:tostring(), now))

  if req:nonce() then
    lu.assertIsString(tst.nonce:tostring())
    lu.assertEquals(req:nonce(), tst.nonce)
  end

  res = res:dup()
  res = assert(openssl.ts.resp_read(res:export()))
  assert(type(res:tst_info())=='table')
  assert(type(res:tst_info(true))=='table')
  local vry = assert(req:to_verify_ctx())
  vry:store(self.ca.store)
  assert(vry:verify(res:info().token))

  vry = assert(ts.verify_ctx_new())
  vry:imprint(self.hash)
  vry:store(self.ca.store)
  assert(vry:verify(res:export()))

  vry = assert(ts.verify_ctx_new())
  vry:data(self.dat)
  vry:store(self.ca.store)
  assert(vry:verify(res))

  vry = assert(ts.verify_ctx_new())
  vry:imprint(self.hash)
  vry:data(self.dat)
  vry:store(self.ca.store)
  assert(vry:verify(res))

  vry = assert(ts.verify_ctx_new(req:export()))
  vry:imprint(self.hash)
  vry:data(self.dat)
  vry:store(self.ca.store)
  assert(vry:verify(res))

  vry = assert(ts.verify_ctx_new(req))
  vry:imprint(self.hash)
  vry:data(self.dat)
  vry:store(self.ca.store)
  assert(vry:verify(res))

  return res
end

testTS = {}

function testTS:setUp()
  math.randomseed(os.time())
  self.msg = 'abcd'
  self.alg = 'sha1'
  self.hash = assert(openssl.digest.digest(self.alg, self.msg, true))
  -- FIXME: libressl will crash random
  if not helper.libressl then self.nonce = openssl.bn.text(openssl.random(16)) end
  self.digest = 'sha1WithRSAEncryption'
  self.md = openssl.digest.get('sha1WithRSAEncryption')
  self.policy_id = policy_obj

  local der = policy_obj:i2d()
  local ano = openssl.asn1.new_object()
  assert(ano:d2i(der))
  assert(ano:equals(policy_obj))

  local timeStamping = asn1.new_type('timeStamping')
  self.timeStamping = timeStamping:i2d()
  self.cafalse = openssl.asn1.new_string('CA:FALSE', asn1.OCTET_STRING)

  self.dat = openssl.random(256)
  assert(createTsa(self))
end

function testTS:testBasic()
  local req = createQuery(self)
  assert(req:add_ext(openssl.x509.extension.new_extension({
    object = 'subjectAltName',
    value = "IP:192.168.0.1"
  })))
  local req_ctx = createRespCtx(self)
  assert(req_ctx:signer(self.tsa.cert, self.tsa.pkey))
  assert(req_ctx:certs({self.ca.cert, self.tsa.cert}))
  assert(req_ctx:default_policy(policy_obj))
  assert(req_ctx:policies(policies))
  assert(req_ctx:accuracy(1, 1, 1))
  assert(req_ctx:clock_precision_digits(20))
  req_ctx:add_flags(openssl.ts.VFY_SIGNATURE)
  req_ctx:tst_info()
  req_ctx:tst_info(false, "version")
  req_ctx:tst_info(true, "version")
  req_ctx:tst_info(false, "version")
  req_ctx:request()
  lu.assertEquals(false, req:cert_req())

  signReq(self, req_ctx, req)
  assert(req:dup():export()==req:export())
  assert(req:version(2))
  assert(req:version()==2)

  --assert(req_ctx:set_status_info(0, "OK"))
  --assert(req_ctx:set_status_info(1, "XX"))
  --assert(req_ctx:set_status_info_cond(7, "XX"))
  --assert(req_ctx:add_failure_info(8, "xx"))
end

function testTS:testPloicyId()
  -- FIXME: libressl will crash random
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

-- FIXME: real do it
function testTS:testExtensions()
  local extensions = nil
  local req = createQuery(self, nil, nil, extensions)
  local req_ctx = createRespCtx(self)
  signReq(self, req_ctx, req)
end

function testTS:testSerialCallback()
  local req = createQuery(self)

  local serial_cb = function(this)
    self.sn = 0x7fffffff;
    return this.sn
  end
  local req_ctx = createRespCtx(self, serial_cb)
  signReq(self, req_ctx, req, '7FFFFFFF')
end

function testTS:testTimeCallback()
  local req = createQuery(self)

  local time_cb = function(this)
    self.time = 0x7fffffff;
    return this.time
  end
  local req_ctx = createRespCtx(self, nil, time_cb)
  local res = signReq(self, req_ctx, req, nil, '20380119031407Z')
  local t = assert(res:info())
  lu.assertIsTable(t)

  assert(t.status_info.status:tostring() == '0')
  assert(not t.status_info.text)
  assert(not t.status_info.failure_info)
  for k, v in pairs(t.tst_info) do
    local V = res:tst_info(k)
    assert(type(V)==type(v))
  end

  assert(res:dup():export()==res:export())
end

