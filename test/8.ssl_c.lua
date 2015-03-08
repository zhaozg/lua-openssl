local openssl = require'openssl'
local csr,bio,ssl = openssl.csr,openssl.bio, openssl.ssl
local sslctx = require'sslctx'

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100

local params = {
   mode = "client",
   protocol = "tlsv1",
   key = "luasec/certs/clientAkey.pem",
   certificate = "luasec/certs/clientA.pem",
   cafile = "luasec/certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = {"all", "no_sslv2"},
}

print(string.format('CONNECT to %s:%s',host,port))
local certstore = openssl.x509.store:new()
local cas = require'root_ca'
for i=1,#cas do
      local cert = assert(openssl.x509.read(cas[i]))
      assert(certstore:add(cert))
end


function mk_connection(host,port,i)

      local ctx = assert(sslctx.new(params))
      ctx:cert_store(certstore)
      ctx:verify_mode({'peer'},function(arg) 
      --[[
            print(arg)
            --do some check
            for k,v in pairs(arg) do
                  print(k,v)
            end
      --]]
            return true --return false will fail ssh handshake
      end)
      
  local cli = assert(bio.connect(host..':'..port,true))
  if(cli) then
    S = ctx:ssl(cli,false)
    if(i%2==2) then
        assert(S:handshake())
    else
        assert(S:connect())
    end
    local b,r = S:getpeerverification()
    assert(b)
    s = 'aaa'
    io.write('.')
    for j=1,100 do
          assert(S:write(s))
          assert(S:read())
    end
    S:shutdown()
    cli:shutdown()
    cli:close()
    cli = nil
    collectgarbage()
    
  end
  openssl.error(true)
end

for i=1,loop do
  mk_connection(host,port,i)
end
