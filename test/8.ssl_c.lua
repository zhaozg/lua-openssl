local openssl = require'openssl'
local bio,ssl = openssl.bio, openssl.ssl
local sslctx = require'sslctx'
local _,_,opensslv = openssl.version(true)
local host, port, loop

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100

local params = {
   mode = "client",
   protocol = "tlsv1",
   key = "luasec/certs/clientAkey.pem",
   certificate = "luasec/certs/clientA.pem",
   cafile = "luasec/certs/rootA.pem",
   verify = ssl.peer+ssl.fail,
   options = {"all", "no_sslv2"},
}

print(string.format('CONNECT to %s:%s',host,port))

local certstore = nil
if opensslv > 0x10002000 then
    certstore = openssl.x509.store:new()
    local cas = require'root_ca'
    for i=1,#cas do
      local cert = assert(openssl.x509.read(cas[i]))
      assert(certstore:add(cert))
    end
end

local function mk_connection(host,port,i)

      local ctx = assert(sslctx.new(params))
      if (certstore) then
          ctx:cert_store(certstore)
      end
      ctx:verify_mode(ssl.peer,function(arg)
      --[[
            print(arg)
            --do some check
            for k,v in pairs(arg) do
                  print(k,v)
            end
      --]]
            return true --return false will fail ssh handshake
      end)
      ctx:set_cert_verify(function(arg)

            --do some check
            --[[
            for k,v in pairs(arg) do
                  print(k,v)
            end
            --]]
            return true --return false will fail ssh handshake
      end)

  local cli = assert(bio.connect(host..':'..port,true))
  if(cli) then
    local S = ctx:ssl(cli,false)
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
