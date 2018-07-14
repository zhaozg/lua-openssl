local openssl = require'openssl'
local bio, x509,cms,csr = openssl.bio,openssl.x509,openssl.cms,openssl.x509.req

TestCMS = {}

--need OpenSSL build with zlib support
--[[
  function TestCMS:testCompress()
    local msg = openssl.random(1000)
    local cs = assert(cms.compress(msg, 'rle'))
    local out = bio.mem()
    local ret = assert(cms.uncompress (cs, msg, out))
    assertEquals(msg, out:get_mem())
  end
--]]
    function TestCMS:setUp()
        self.alg='sha1'
        self.cadn = openssl.x509.name.new({{commonName='CA'},{C='CN'}})
        self.alicedn = openssl.x509.name.new({{commonName='Alice'},{C='CN'}})
        self.bobdn = openssl.x509.name.new({{commonName='Bob'},{C='CN'}})

        local cakey = assert(openssl.pkey.new())
        local req = assert(csr.new(self.cadn,cakey))
        local t = req:parse()
        assertEquals(type(t),'table')

        local cacert = openssl.x509.new(
                1,      --serialNumber
                req     --copy name and extensions
        )
        cacert:validat(os.time(), os.time() + 3600*24*361)
        assert(cacert:sign(cakey, cacert))  --self sign
        self.cakey, self.cacert = cakey, cacert
        self.castore = openssl.x509.store.new({cacert})

        local pkey = openssl.pkey.new()
        req = assert(csr.new(self.alicedn, pkey))
        local cert = openssl.x509.new(2,req)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(cakey,cacert))
        self.alice = {
          key = pkey,
          cert = cert
        }

        pkey = openssl.pkey.new()
        req = assert(csr.new(self.bobdn, pkey))
        cert = openssl.x509.new(2,req)
        cert:validat(os.time(), os.time() + 3600*24*365)
        assert(cert:sign(cakey,cacert))
        self.bob = {
          key = pkey,
          cert = cert
        }

        self.msg = openssl.hex(openssl.random(128))
        self.digest = 'sha1WithRSAEncryption'
    end

    function TestCMS:testEncrypt()
        local recipts = {self.alice.cert}
        local msg = assert(cms.encrypt(recipts, self.msg))
        local smime = assert(cms.write(msg))
        local ss = assert(cms.read(smime,'smime'))
        local raw = assert(cms.decrypt(ss,self.alice.key, self.alice.cert))
        assertEquals(raw,self.msg)
    end

    function TestCMS:testSign()
        local c1 = assert(cms.sign(self.bob.cert, self.bob.key, self.msg, {}))
        local smime = assert(cms.write(c1))
        local msg = assert(cms.verify(c1, {self.bob.cert}, self.castore))
        assertEquals(msg, self.msg)
        msg = assert(cms.verify(c1, {}, self.castore))
        assertEquals(msg, self.msg)
    end

    function TestCMS:testEncryptedData()
        local key = openssl.random(24)
        local c1 = assert(cms.EncryptedData_encrypt(self.msg, key))
        local smime = assert(cms.write(c1))
        local msg = assert(cms.EncryptedData_decrypt(c1, key))
        assertEquals(msg, self.msg)
    end
    function TestCMS:testDigest()
        local key = openssl.random(24)
        local c1 = assert(cms.digest_create(self.msg))
        local smime = assert(cms.write(c1))
        local msg = assert(cms.digest_verify(c1))
        assertEquals(msg, self.msg)
    end
