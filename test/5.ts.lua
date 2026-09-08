local lu = require("luaunit")
local openssl = require("openssl")
local helper = require("helper")

local asn1, ts, csr = openssl.asn1, openssl.ts, openssl.x509.req

local policy_oid = "1.2.3.4.100"
local policy_obj = assert(asn1.new_object(policy_oid))
local policies = {
  assert(asn1.new_object("1.1.3")),
  assert(asn1.new_object("1.1.4")),
}
local obja = assert(asn1.new_object({
  oid = "1.2.3.4.5.6",
  sn = "1.2.3.4.5.6_sn",
  ln = "1.2.3.4.5.6_ln",
}))
local objb = assert(asn1.new_object({
  oid = "1.2.3.4.5.7",
  sn = "1.2.3.4.5.7_sn",
  ln = "1.2.3.4.5.7_ln",
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

local function createQuery(self, policy_id, nonce, cert_req, extensions)
  local req = assert(openssl.ts.req_new())
  local msg = openssl.ts.ts_msg_imprint_new(self.hash, self.alg)
  assert(msg:msg())
  assert(msg:algo())
  lu.assertIsTable(msg:totable())
  local ano = assert(msg:dup())
  ano = assert(msg:export())
  ano = openssl.ts.ts_msg_imprint_read(ano)
  assert(req:msg_imprint(msg))
  local m = req:msg_imprint()
  assert(msg:export() == m:export())
  if cert_req ~= nil then
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
  if extensions then
    assert(req:extensions())
  end
  return req
end

local function createTsa(self)
  -- setUp private key and certificate
  local ca = {}
  self.ca = ca
  ca.dn = { { commonName = "CA" }, { C = "CN" } }
  ca.pkey = assert(openssl.pkey.new())
  local subject = assert(openssl.x509.name.new(ca.dn))

  local exts = {
    openssl.x509.extension.new_extension({ object = "basicConstraints", value = "CA:TRUE" }),
    openssl.x509.extension.new_extension({ object = "keyUsage", value = "cRLSign, keyCertSign" }),
  }

  local attrs = {
    {
      object = "basicConstraints",
      type = asn1.OCTET_STRING,
      value = "CA:TRUE",
    },
  }

  ca.req = assert(csr.new(subject))
  if exts then
    ca.req:extensions(exts)
  end
  if attrs then
    ca.req:attribute(attrs)
  end
  assert(ca.req:sign(ca.pkey))
  ca.cert = assert(ca.req:to_x509(ca.pkey))

  local extensions = {
    openssl.x509.extension.new_extension({ object = "extendedKeyUsage", value = "timeStamping", critical = true }),
  }

  local tsa = {}
  self.tsa = tsa
  tsa.dn = { { commonName = "tsa" }, { C = "CN" } }
  tsa.pkey = assert(openssl.pkey.new())
  subject = openssl.x509.name.new(tsa.dn)

  tsa.req = csr.new(subject, tsa.pkey)
  lu.assertEquals(type(tsa.req:parse()), "table")

  tsa.cert = openssl.x509.new(1, tsa.req)
  assert(tsa.cert:validat(os.time(), os.time() + 3600 * 24 * 365))
  assert(tsa.cert:extensions(extensions))
  assert(tsa.cert:sign(ca.pkey, ca.cert))

  lu.assertEquals(type(tsa.cert:parse()), "table")

  ca.store = openssl.x509.store.new({ ca.cert })
  assert(tsa.cert:check(ca.store, nil, "timestamp_sign"))
  self.tsa = tsa
  return tsa
end

local function createRespCtx(self, serial_cb, time_cb)
  local tsa = self.tsa
  local req_ctx = assert(ts.resp_ctx_new(tsa.cert, tsa.pkey, self.policy_id))
  assert(req_ctx:md({ "md5", "sha1" }))

  if serial_cb then
    req_ctx:set_serial_cb(serial_cb, self)
  end

  if time_cb then
    req_ctx:set_time_cb(time_cb, self)
  end
  assert(req_ctx:md("sha256") == true)
  assert(req_ctx:accuracy(1, 1, 1))
  return req_ctx
end

local function signReq(self, req_ctx, req, sn, now)
  local res = req_ctx:sign(req:export())
  local t = assert(res:status_info())

  lu.assertIsTable(t)
  local status = t.status:tonumber()
  if status ~= 0 then
    assert(t.failure_info or helper.libressl)
    assert(#t > 0)
    return
  end

  assert(t.status:tostring() == "0")
  assert(#t == 0)
  assert(not t.failure_info)

  local token = res:token()
  lu.assertIsUserdata(token)

  local tst = res:tst_info()
  lu.assertIsUserdata(tst)

  sn = sn or "01"
  lu.assertEquals(sn, tst:serial():tohex())
  lu.assertEquals(1, tst:version())
  lu.assertEquals(tst:ordering(), false)
  lu.assertEquals(self.policy_id:txt(true), tst:policy_id():txt(true))

  if not now then
    now = os.time()
    local timezone = get_timezone()
    now = os.date("%Y%m%d%H%M%SZ", now - timezone + 1)
  end
  assert(notAfter(tst:time():tostring(), now))

  if req:nonce() then
    lu.assertIsString(tst:nonce():tostring())
    lu.assertEquals(req:nonce(), tst:nonce())
  end

  res = res:dup()
  res = assert(openssl.ts.resp_read(res:export()))
  assert(type(res:tst_info()) == "userdata")
  local vry = assert(req:to_verify_ctx())
  vry:store(self.ca.store)
  local flags = vry:flags(0, true)
  assert(vry:flags(9))
  assert(9 == vry:flags(0, true))
  vry:flags(flags)
  assert(vry:verify(res:token()))

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

  -- Reverse check: a response whose embedded message digest has been changed
  -- (yet validly signed by the same TSA) must NOT verify with the request
  -- derived context used for the positive checks above.
  local badmsg = openssl.random(32)
  local badhash = assert(openssl.digest.digest(self.alg, badmsg, true))
  local req_bad = assert(req:dup())
  assert(req_bad:msg_imprint(openssl.ts.ts_msg_imprint_new(badhash, self.alg)))
  local res_bad = assert(req_ctx:sign(req_bad:export()))
  vry = assert(ts.verify_ctx_new(req))
  vry:imprint(self.hash)
  vry:data(self.dat)
  vry:store(self.ca.store)
  local ok_bad = vry:verify(res_bad)
  lu.assertIsNil(ok_bad)

  return res
end

TestTS = {}

function TestTS:setUp()
  math.randomseed(os.time())
  self.msg = openssl.random(32)
  self.alg = "sha1"
  self.hash = assert(openssl.digest.digest(self.alg, self.msg, true))
  self.nonce = openssl.bn.text(openssl.random(16))
  self.digest = "sha1WithRSAEncryption"
  self.md = openssl.digest.get("sha1WithRSAEncryption")
  self.policy_id = policy_obj

  local der = policy_obj:i2d()
  assert(der)
  local ano = openssl.asn1.new_object()
  assert(ano:d2i(der))
  assert(ano:equals(policy_obj))

  local timeStamping = asn1.new_type("timeStamping")
  self.timeStamping = timeStamping:i2d()
  self.cafalse = openssl.asn1.new_string("CA:FALSE", asn1.OCTET_STRING)

  self.dat = openssl.random(256)
  assert(createTsa(self))
end

function TestTS:testBasic()
  local req = createQuery(self)
  assert(req:add_ext(openssl.x509.extension.new_extension({
    object = "subjectAltName",
    value = "IP:192.168.0.1",
  })))
  assert(req:msg_imprint())
  req = assert(req:dup())

  local req_ctx = createRespCtx(self)
  local res = req_ctx:sign(req:export())
  assert(res)
  assert(req_ctx:signer(self.tsa.cert, self.tsa.pkey))
  assert(req_ctx:certs({ self.ca.cert, self.tsa.cert }))
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
  assert(req:dup():export() == req:export())
  assert(req:version(2))
  assert(req:version() == 2)
end

function TestTS:testPloicyId()
  local req = createQuery(self, self.policy_id, nil, true)
  local req_ctx = createRespCtx(self)
  signReq(self, req_ctx, req)
end

function TestTS:testCertReq()
  local req = createQuery(self, nil, nil, true)
  local req_ctx = createRespCtx(self)
  assert(req:cert_req())
  signReq(self, req_ctx, req)
end

function TestTS:testNonce()
  local req = createQuery(self, nil, self.nonce)
  local req_ctx = createRespCtx(self)
  assert(req:nonce())
  signReq(self, req_ctx, req)
end

function TestTS:testExtensions()
  local extensions = nil
  local req = createQuery(self, nil, nil, extensions)
  local req_ctx = createRespCtx(self)
  signReq(self, req_ctx, req)
end

function TestTS:testSerialCallback()
  local req = createQuery(self)

  local serial_cb = function(this)
    self.sn = 0x7fffffff
    return this.sn
  end
  local req_ctx = createRespCtx(self, serial_cb)
  signReq(self, req_ctx, req, "7FFFFFFF")
end

function TestTS:testAccuracy()
  local sec, mil, mic = 100000, 10, 1
  local accuracy = openssl.ts.ts_accuracy_new(sec, mil, mic)
  assert(accuracy:seconds() == sec)
  assert(accuracy:seconds(sec + 1))
  assert(accuracy:seconds() == sec + 1)
  assert(accuracy:millis() == mil)
  assert(accuracy:millis(mil + 1))
  assert(accuracy:millis() == mil + 1)
  assert(accuracy:micros() == mic)
  assert(accuracy:micros(mic + 1))
  assert(accuracy:micros() == mic + 1)
  local dup = assert(accuracy:dup())
  local ano = assert(dup:export())
  ano = assert(openssl.ts.ts_accuracy_read(ano))
  dup, ano = dup:totable(), ano:totable()
  lu.assertEquals(dup, ano)
  accuracy = openssl.ts.ts_accuracy_new(sec)
  accuracy = accuracy:totable()
  lu.assertEquals(accuracy, { seconds = sec, millis = 0, micros = 0 })
end

function TestTS:testTimeCallback()
  local req = createQuery(self)

  local time_cb = function(this)
    self.time = 0x7fffffff
    return this.time
  end
  local req_ctx = createRespCtx(self, nil, time_cb)
  local res = signReq(self, req_ctx, req, nil, "20380119031407Z")
  local t = assert(res:status_info())
  lu.assertIsTable(t)

  assert(t.status:tostring() == "0")
  assert(#t == 0)
  assert(not t.failure_info)
  assert(res:dup():export() == res:export())

  local tst = res:tst_info()
  assert(tst:version() == 1)
  assert(tst.policy_id)
  assert(tst:policy_id():txt() == "1.2.3.4.100")
  assert(tst:msg_imprint())
  assert(tst:serial():tostring())
  assert(tst:time():tostring())
  assert(tst:accuracy())
  assert(tst:ordering() == false)
  local sec, mil, mic = 100000, 10, 1
  local accuracy = openssl.ts.ts_accuracy_new(sec, mil, mic)
  tst:accuracy(accuracy)

  tst:nonce()
  tst:tsa()
  tst:extensions()
end

function TestTS:testVerifyRejections()
  -- Reverse (negative) tests: a TimeStampResp that has been tampered with
  -- (wrong message digest, wrong signature value, issued for other data,
  --  or with a nonce / policy different from the request) must be rejected
  -- by TS_RESP_verify_response / TS_RESP_verify_token.
  local V = openssl.ts

  -- toggle the lowest bit of byte i (pure Lua, works on every interpreter)
  local function flipbyte(s, i)
    local b = s:byte(i)
    local nb = (b % 2 == 0) and (b + 1) or (b - 1)
    return s:sub(1, i - 1) .. string.char(nb) .. s:sub(i + 1)
  end

  -- request bound to this message, with policy + nonce and certReq = true so
  -- that the response embeds the signer certificate (needed to verify the
  -- signature value).
  local req = assert(createQuery(self, self.policy_id, self.nonce, true))
  local req_ctx = assert(createRespCtx(self))
  -- accept alternate policies too, so a request asking for a *different*
  -- policy is still signed and the verifier has to reject the mismatch.
  assert(req_ctx:policies(policies))
  local res = assert(req_ctx:sign(req:export()))
  assert(res:status_info().status:tostring() == "0")

  -- verify context configured like the positive checks in signReq: derived
  -- from the request, with the expected digest (imprint) and original data.
  local function ctxFromReq()
    local vry = assert(ts.verify_ctx_new(req))
    vry:imprint(self.hash)
    vry:data(self.dat)
    vry:store(self.ca.store)
    return vry
  end

  -- sanity: the unmodified response must still verify
  assert(ctxFromReq():verify(res))

  -- (1) wrong digest value: validly signed response carrying the digest of a
  --     different message
  local badmsg = openssl.random(32)
  local badhash = assert(openssl.digest.digest(self.alg, badmsg, true))
  local req_imprint = assert(createQuery(self, self.policy_id, self.nonce, true))
  assert(req_imprint:msg_imprint(openssl.ts.ts_msg_imprint_new(badhash, self.alg)))
  local res_imprint = assert(req_ctx:sign(req_imprint:export()))
  local ok = ctxFromReq():verify(res_imprint)
  lu.assertIsNil(ok)

  -- (2) wrong signature value: flip one byte of the DER signature (the very
  --     last byte of the response, inside the RSA signature octets) and parse
  --     the tampered response again
  local vry_sig = ctxFromReq()
  vry_sig:flags(V.VFY_SIGNATURE, true)
  assert(vry_sig:verify(res))
  local der = res:export()
  local tampered = assert(ts.resp_read(flipbyte(der, #der)))
  ok = vry_sig:verify(tampered)
  lu.assertIsNil(ok)

  -- (3) nonce mismatch: response issued for a request with a different nonce
  local req_nonce =
      assert(createQuery(self, self.policy_id, openssl.bn.text(openssl.random(16)), true))
  local res_nonce = assert(req_ctx:sign(req_nonce:export()))
  ok = ctxFromReq():verify(res_nonce)
  lu.assertIsNil(ok)

  -- (4) policy mismatch: response issued under a policy different from the
  --     one requested by `req`
  local req_policy = assert(createQuery(self, policies[1], self.nonce, true))
  local res_policy = assert(req_ctx:sign(req_policy:export()))
  assert(res_policy:status_info().status:tostring() == "0")
  local vry_policy = assert(ts.verify_ctx_new(req_policy))
  vry_policy:store(self.ca.store)
  assert(vry_policy:verify(res_policy)) -- same request + policy verifies fine
  ok = ctxFromReq():verify(res_policy)
  lu.assertIsNil(ok)

  -- (5) wrong data (VFY_DATA): verify the token against the original data
  --     payload; the response must embed the digest of *that* payload
  local dat_digest = assert(openssl.digest.digest(self.alg, self.dat, true))
  local req_data = assert(ts.req_new())
  assert(req_data:msg_imprint(openssl.ts.ts_msg_imprint_new(dat_digest, self.alg)))
  local res_data = assert(req_ctx:sign(req_data:export()))
  local vry_data = assert(ts.verify_ctx_new())
  vry_data:data(self.dat)
  vry_data:store(self.ca.store)
  vry_data:flags(V.VFY_DATA, true)
  assert(vry_data:verify(res_data))
  -- response digesting a different payload must not verify against self.dat
  local other = openssl.random(64)
  local other_digest = assert(openssl.digest.digest(self.alg, other, true))
  local req_other = assert(ts.req_new())
  assert(req_other:msg_imprint(openssl.ts.ts_msg_imprint_new(other_digest, self.alg)))
  local res_other = assert(req_ctx:sign(req_other:export()))
  ok = vry_data:verify(res_other)
  lu.assertIsNil(ok)

  -- (6) VFY_IMPRINT on a fresh context (no request object): only the expected
  --     digest is compared against the digest embedded in the response
  local vry_imprint = assert(ts.verify_ctx_new())
  vry_imprint:imprint(self.hash)
  vry_imprint:store(self.ca.store)
  vry_imprint:flags(V.VFY_IMPRINT, true)
  assert(vry_imprint:verify(res))
  ok = vry_imprint:verify(res_imprint)
  lu.assertIsNil(ok)
end

function TestTS:testTokenVerifyWithoutCertReq()
  -- RFC 3161 certReq flag: when the request sets certReq = false the TSA
  -- keeps its signing certificate out of the time stamp token. The token is
  -- then still a plain PKCS#7 SignedData, but TS_RESP_verify_* cannot run its
  -- signature check any more: without an embedded signer certificate (and
  -- with no way to inject an untrusted one into the TS verify ctx) it cannot
  -- even locate the signer key. The signature can however be checked directly
  -- through the openssl.pkcs7 API by handing the TSA public key over
  -- explicitly, as done below.
  local V = openssl.ts

  -- toggle the lowest bit of byte i (pure Lua, works on every interpreter)
  local function flipbyte(s, i)
    local b = s:byte(i)
    local nb = (b % 2 == 0) and (b + 1) or (b - 1)
    return s:sub(1, i - 1) .. string.char(nb) .. s:sub(i + 1)
  end

  -- crypto check of a token (openssl.pkcs7) against the trusted TSA
  -- certificate. PKCS7_verify defaults to the S/MIME sign purpose and would
  -- reject the timeStamping EKU of the TSA certificate, so PKCS7_NOVERIFY is
  -- used: it skips the purpose / chain step while still verifying the
  -- signature value itself against the signer certificate given explicitly.
  -- Returns the signed content (the DER TSTInfo, as attached eContent) on
  -- success, nil on any failure.
  local function p7CryptoVerify(p7)
    return p7:verify({ self.tsa.cert }, nil, nil, openssl.pkcs7.NOVERIFY)
  end

  -- datum being timestamped, with certReq explicitly false
  local data = openssl.random(96)
  local digest = assert(openssl.digest.digest(self.alg, data, true))
  local req = assert(ts.req_new())
  assert(req:msg_imprint(ts.ts_msg_imprint_new(digest, self.alg)))
  assert(req:cert_req(false))
  local req_ctx = assert(createRespCtx(self))
  local res = assert(req_ctx:sign(req:export()))
  assert(res:status_info().status:tostring() == "0")

  -- fact: the granted token carries NO embedded certificate ...
  local token = res:token()
  local p = assert(token:parse())
  lu.assertEquals("pkcs7-signedData", p.type)
  lu.assertNil(p.certs)
  lu.assertEquals(1, #p.signer_info)

  -- ... therefore the TS verify ctx cannot validate the signature even though
  -- the trusted store is supplied
  local vry = assert(ts.verify_ctx_new())
  vry:imprint(digest)
  vry:data(data)
  vry:store(self.ca.store)
  vry:flags(V.VFY_SIGNATURE, true)
  lu.assertNil(vry:verify(res))

  -- positive: the token itself verifies cryptographically once the TSA
  -- certificate is provided, and the signed content is the DER TSTInfo
  local content = assert(p7CryptoVerify(token))
  lu.assertEquals(0x30, content:byte(1)) -- TSTInfo ::= SEQUENCE
  -- and the imprint inside that TSTInfo is exactly the digest of `data`
  local imprinted = assert(res:tst_info())
  imprinted = assert(imprinted:msg_imprint())
  lu.assertEquals(digest, imprinted:msg():data())

  -- (1) reverse: signature bytes tampered (DER stays valid, only the RSA
  --     signature octets change) -> crypto verification must fail
  local der = assert(token:export("der"))
  local tok_a = assert(openssl.pkcs7.read(flipbyte(der, #der - 20), "der"))
  lu.assertNil(p7CryptoVerify(tok_a))

  -- (2) reverse: the very same TSA issues a perfectly valid token over a
  --     DIFFERENT datum. Its signature verifies fine, so the crypto layer
  --     alone is not enough - the imprint must also match the expected
  --     digest of the original data.
  local other = openssl.random(96)
  local req2 = assert(ts.req_new())
  assert(req2:msg_imprint(
      ts.ts_msg_imprint_new(assert(openssl.digest.digest(self.alg, other, true)), self.alg)))
  assert(req2:cert_req(false))
  local res2 = assert(req_ctx:sign(req2:export()))
  assert(res2:status_info().status:tostring() == "0")
  lu.assertIsString(assert(p7CryptoVerify(res2:token()))) -- signature is valid
  local im2 = assert(res2:tst_info())
  im2 = assert(im2:msg_imprint())
  lu.assertEquals(openssl.digest.digest(self.alg, other, true), im2:msg():data())
  lu.assertNotEquals(digest, im2:msg():data()) -- ... but not for `data`

  -- (3) reverse: the hashedMessage OCTET STRING embedded in the signed
  --     TSTInfo is modified (message digest data changed). The token DER is
  --     still perfectly parseable, but the messageDigest signed attribute no
  --     longer matches the signed content -> crypto verification must fail.
  local cstart = der:find(content:sub(1, 8), 1, true)
  local hpat = content:find("\4\20" .. digest, 1, true)
  lu.assertIsTrue(cstart ~= nil and hpat ~= nil)
  local badcontent = flipbyte(content, hpat + 2)
  local badder = der:sub(1, cstart - 1) .. badcontent .. der:sub(cstart + #content)
  local tok_c = assert(openssl.pkcs7.read(badder, "der"))
  lu.assertNil(p7CryptoVerify(tok_c))
end
