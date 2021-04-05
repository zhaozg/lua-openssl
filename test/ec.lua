local lu = require 'luaunit'
local openssl = require 'openssl'
local pkey = openssl.pkey
local unpack = unpack or table.unpack

TestEC = {}

function TestEC:testCompat()
  local factor = {
    alg = "ec",
    ec_name = 415,
    x = assert(openssl.base64('fBEMZtz9qAf25p5F3bPHT2mhSE0gPo3Frajpqd18s8c=',
                              false)),
    y = assert(openssl.base64('DfRImG5RveXRV2+ZkB+cLGqAakf9kHZDpyuDVZfvyMY=',
                              false)),
    d = assert(openssl.base64('H+M5UMX0YRJK6ZLCvf3xxzsWFfVxvVZ+YNGaofSM30I=',
                              false))
  }
  local ec = assert(pkey.new(factor))

  local pem = assert(ec:export('pem'))
  lu.assertEquals(pem, [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH+M5UMX0YRJK6ZLC
vf3xxzsWFfVxvVZ+YNGaofSM30KhRANCAAR8EQxm3P2oB/bmnkXds8dPaaFITSA+
jcWtqOmp3Xyzxw30SJhuUb3l0VdvmZAfnCxqgGpH/ZB2Q6crg1WX78jG
-----END PRIVATE KEY-----
]])
end

function TestEC:TestEC()
  local nec = {'ec',  'prime256v1'}
  local ec = pkey.new(unpack(nec))
  local t = ec:parse().ec:parse('pem') -- make basic table
  lu.assertEquals(type(t.curve_name), 'number')
  lu.assertStrContains(t.x.version, 'bn library')
  lu.assertStrContains(t.y.version, 'bn library')
  lu.assertStrContains(t.d.version, 'bn library')

  local k1 = pkey.get_public(ec)
  assert(not k1:is_private())
  t = k1:parse()
  assert(t.bits == 256)
  assert(t.type == 'ec')
  assert(t.size == 72)
  local r = t.ec
  t = r:parse(true) -- make basic table
  lu.assertEquals(type(t.curve_name), 'number')
  lu.assertStrContains(t.x.version, 'bn library')
  lu.assertStrContains(t.y.version, 'bn library')
  lu.assertEquals(t.d, nil)
  t = r:parse()
  lu.assertStrContains(tostring(t.pub_key), 'openssl.ec_point')
  lu.assertStrContains(tostring(t.group), 'openssl.ec_group')
  local x, y = t.group:affine_coordinates(t.pub_key)
  lu.assertStrContains(x.version, 'bn library')
  lu.assertStrContains(y.version, 'bn library')
  local ec2p = {
    alg = 'ec',
    ec_name = t.group:parse().curve_name,
    x = x,
    y = y
  }
  local ec2 = pkey.new(ec2p)
  assert(not ec2:is_private())

  ec2p.d = ec:parse().ec:parse().priv_key
  local ec2priv = pkey.new(ec2p)
  assert(ec2priv:is_private())
end

function TestEC:TestEC2()
  local nec = {'ec',  'prime256v1'}
  local key1 = pkey.new(unpack(nec))
  local key2 = pkey.new(unpack(nec))
  local ec1 = key1:parse().ec
  local ec2 = key2:parse().ec
  local secret1 = ec1:compute_key(ec2)
  local secret2 = ec2:compute_key(ec1)
  assert(secret1 == secret2)

  local pub1 = pkey.get_public(key1)
  local pub2 = pkey.get_public(key2)
  pub1 = pub1:parse().ec
  pub2 = pub2:parse().ec

  secret1 = ec1:compute_key(pub2)
  secret2 = ec2:compute_key(pub1)
  assert(secret1 == secret2)
end

if openssl.ec then
  function TestEC:TestEC2()
    local lc = openssl.ec.list()
    assert(type(lc)=='table')
    local grp, pnt = openssl.ec.group('prime256v1', "uncompressed", "named_curve")
    assert(grp:asn1_flag() == 'named_curve')
    assert(grp:point_conversion_form() == 'uncompressed')

    local oct = grp:point2oct(pnt)
    assert(#oct==65)
    local pnt1 = grp:oct2point(oct)
    assert(grp:point_equal(pnt, pnt1))

    assert(grp:point_conversion_form('compressed'))
    oct = grp:point2oct(pnt)
    print(#oct, oct)
    assert(#oct==33)
    local pnt2 = grp:oct2point(oct, 'compressed')
    assert(grp:point_equal(pnt2, pnt1))

    local bn = grp:point2bn(pnt)
    pnt2 = grp:bn2point(bn)
    assert(grp:point_equal(pnt2, pnt1))

    local hex = grp:point2hex(pnt)
    pnt2 = grp:hex2point(hex)
    assert(grp:point_equal(pnt2, pnt1))

    local ec = grp:generate_key()
    local t = ec:parse()
    assert(type(t)=='table')
    local grp1 = ec:group()
    print(grp1, pnt)

    assert(grp==grp1)

    pnt = assert(grp:point_new())
    pnt1 = assert(grp:point_dup(pnt))
    assert(grp:point_equal(pnt, pnt1))
  end
end
