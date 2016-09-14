local openssl = require'openssl'
local pkey = openssl.pkey
local unpack = unpack or table.unpack

testEC = {}

    function testEC:testCompat()
        local factor = {
          alg = "ec",
          ec_name = 415,
          x = assert(openssl.base64('fBEMZtz9qAf25p5F3bPHT2mhSE0gPo3Frajpqd18s8c=',false)),
          y = assert(openssl.base64('DfRImG5RveXRV2+ZkB+cLGqAakf9kHZDpyuDVZfvyMY=',false)),
          d = assert(openssl.base64('H+M5UMX0YRJK6ZLCvf3xxzsWFfVxvVZ+YNGaofSM30I=',false)),
        }
        local ec = assert(pkey.new(factor))

        local pem = assert(ec:export(true))
        assertEquals(pem,[[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH+M5UMX0YRJK6ZLC
vf3xxzsWFfVxvVZ+YNGaofSM30KhRANCAAR8EQxm3P2oB/bmnkXds8dPaaFITSA+
jcWtqOmp3Xyzxw30SJhuUb3l0VdvmZAfnCxqgGpH/ZB2Q6crg1WX78jG
-----END PRIVATE KEY-----
]])
    end

    function testEC:testEC()
        local nec =  {'ec','prime256v1'}
        local ec = pkey.new(unpack(nec))
        local t = ec:parse().ec:parse(true) --make basic table
        assertEquals(type(t.curve_name), 'number')
        assertStrContains(t.x.version, 'bn library')
        assertStrContains(t.y.version, 'bn library')
        assertStrContains(t.d.version, 'bn library')

        local k1 = pkey.get_public(ec)
        assert(not k1:is_private())
        local t = k1:parse()
        assert(t.bits==256)
        assert(t.type=='ec')
        assert(t.size==72)
        local r = t.ec
        t = r:parse(true) --make basic table
        assertEquals(type(t.curve_name), 'number')
        assertStrContains(t.x.version, 'bn library')
        assertStrContains(t.y.version, 'bn library')
        assertEquals(t.d, nil)
        t = r:parse()
        assertStrContains(tostring(t.pub_key), 'openssl.ec_point')
        assertStrContains(tostring(t.group), 'openssl.ec_group')
        local x, y = t.group:affine_coordinates(t.pub_key)
        assertStrContains(x.version, 'bn library')
        assertStrContains(y.version, 'bn library')
        local ec2p = {
            alg = 'ec',
            ec_name = t.group:parse().curve_name,
            x = x,
            y = y,
        }
        local ec2 = pkey.new(ec2p)
        assert(not ec2:is_private())

        ec2p.d = ec:parse().ec:parse().priv_key
        local ec2priv = pkey.new(ec2p)
        assert(ec2priv:is_private())
    end

    function testEC:testEC()
        local nec =  {'ec','prime256v1'}
        local key1 = pkey.new(unpack(nec))
        local key2 = pkey.new(unpack(nec))
        local ec1 = key1:parse().ec
        local ec2 = key2:parse().ec
        local secret1 = ec1:compute_key(ec2)
        local secret2 = ec2:compute_key(ec1)
        assert(secret1==secret2)

        local pub1 = pkey.get_public(key1)
        local pub2 = pkey.get_public(key2)
        pub1 = pub1:parse().ec
        pub2 = pub2:parse().ec

        secret1 = ec1:compute_key(pub2)
        secret2 = ec2:compute_key(pub1)
        assert(secret1==secret2)
    end
