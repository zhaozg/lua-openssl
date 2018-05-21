local openssl = require'openssl'
local srp = assert(openssl.srp)

--both
local GN = srp.get_default_gN('1024');

local function test(username, clipass, srvpass)
  assert(username)
  assert(clipass)
  srvpass = srvpass or clipass
  --server
  local salt, v = GN:create_verifier(username,srvpass)
  print('salt:', salt:tohex())
  print('verifier:',v:tohex())

  local Bpub, Brnd = GN:calc_b(v)
  print("Bpnb:",Bpub:tohex())
  print("Brnd:",Brnd:tohex())

  --client
  local Apub, Arnd = GN:calc_a()
  print("Apnb:",Apub:tohex())
  print("Arnd:",Arnd:tohex())

  --both
  local u = GN:calc_u(Apub, Bpub)
  print("u:",u:tohex())

  --client
  local x = GN.calc_x(salt, username, clipass)
  local Kclient = GN:calc_client_key(Bpub,x, Arnd, u)

  --server
  local Kserver = GN:calc_server_key(Apub, v, u, Brnd)

  return Kclient==Kserver
end

local cnt = 1
for i=1,cnt do
assert(test('zhaozg','password','password'))
assert(not test('zhaozg','password','password1'))
end
