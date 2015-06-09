local pkey = require'openssl'.pkey
local unpack = unpack or table.unpack

testEC = {}
    function testEC:testEC()
        local nec =  {'ec','prime256v1'}
        local ec = pkey.new(unpack(nec))
        local k1 = pkey.get_public(ec)
        assert(not k1:is_private())
        local t = k1:parse()
        assert(t.bits==256)
        assert(t.type=='ec')
        assert(t.size==72)
        local r = t.ec
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
