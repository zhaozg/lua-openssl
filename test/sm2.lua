local openssl = require'openssl'
local pkey = openssl.pkey
local sm2  = openssl.sm2
local unpack = unpack or table.unpack
local helper = require'helper'

_,_,opensslv = openssl.version(true)
print(opensslv)
if opensslv >= 0x10101007 and (not helper.libressl) then
  print('Support SM2')
  testSM2 = {}

    function testSM2:testSM2()
        local nec =  {'ec','SM2'}
        local ec = pkey.new(unpack(nec))
        local t = ec:parse().ec:parse('pem') --make basic table
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

        local nec =  {'ec','SM2'}
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
else
  print('Skip SM2')
end

