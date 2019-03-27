local openssl = require'openssl'
local ssl = openssl.ssl
local sslctx = require'sslctx'
local _,_,opensslv = openssl.version(true)
local host, port, loop

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100

local params = {
   mode = "server",
   protocol = "tlsv1",
   key = "luasec/certs/serverAkey.pem",
   certificate = "luasec/certs/serverA.pem",
   cafile = "luasec/certs/rootA.pem",
   verify = ssl.peer + ssl.fail,
   options = {"all", "no_sslv2"},
}

local certstore
if opensslv > 0x10002000 then
    certstore = openssl.x509.store:new()
    local cas = require'root_ca'
    for i=1,#cas do
          local cert = assert(openssl.x509.read(cas[i]))
          assert(certstore:add(cert))
    end
end

local ctx = assert(sslctx.new(params))
    if certstore then
        ctx:cert_store(certstore)
    end

      ctx:verify_mode(ssl.peer,function(arg)
            --[[
            --do some check
            for k,v in pairs(arg) do
                  print(k,v)
            end
            --]]
            return true --return false will fail ssh handshake
      end)

print(string.format('Listen at %s:%s with %s',host,port,tostring(ctx)))
ctx:set_cert_verify(function(arg)
      --do some check
      --[[
      for k,v in pairs(arg) do
            print(k,v)
      end
      --]]
      return true --return false will fail ssh handshake
end)

local function ssl_mode()
    local srv = assert(ctx:bio(host..':'..port,true))
    local i = 0
    if srv then
      print('listen BIO:',srv)
      assert(srv:accept(true),'Error in accept BIO')  -- make real listen
      while i<loop do
          local cli = assert(srv:accept(),'Error in ssl connection') --bio tcp
          assert(cli:handshake(),'handshake fail')
          repeat
              local d = cli:read()
              if d then
                cli:write(d)
              end
          until not d
          cli:close()
          cli = nil
          collectgarbage()
          i = i + 1
      end
      srv:close()
    end
end

ssl_mode()
debug.traceback()
print(openssl.error(true))
