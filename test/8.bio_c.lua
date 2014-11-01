local openssl = require'openssl'
local csr,bio,ssl = openssl.csr,openssl.bio, openssl.ssl
local sslctx = require'sslctx'

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";

local params = {
   mode = "client",
   protocol = "tlsv1",
   key = "luasec/certs/clientAkey.pem",
   certificate = "luasec/certs/clientA.pem",
   cafile = "luasec/certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = {"all", "no_sslv2"},
}

local ctx = assert(sslctx.new(params))

print(string.format('CONNECT to %s:%s with %s',host,port,ctx))

function mk_connection(host,port,i)
  local cli = assert(ctx:bio(host..':'..port,false,true))
  if(cli) then
    if(i%2==2) then
        assert(cli:handshake())
    else
        assert(cli:connect())
    end
    s = 'aaa'
    io.write('.')
    for j=1,100 do
          assert(cli:write(s))
          assert(cli:read())
    end
    cli:shutdown()
    cli:close()
    cli = nil
    collectgarbage()
  end
  openssl.error(true)
end

for i=1,1000000 do
  mk_connection(host,port,i)
end
