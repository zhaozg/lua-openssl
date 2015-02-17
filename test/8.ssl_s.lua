local openssl = require'openssl'
local csr,bio,ssl = openssl.csr,openssl.bio, openssl.ssl
local sslctx = require'sslctx'

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100

local params = {
   mode = "server",
   protocol = "tlsv1",
   key = "luasec/certs/serverAkey.pem",
   certificate = "luasec/certs/serverA.pem",
   cafile = "luasec/certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = {"all", "no_sslv2"},
}

local ctx = assert(sslctx.new(params))
--ctx:set_cert_verify({always_continue=true,verify_depth=4})
--[[
ctx:set_cert_verify(function(arg) 

      --do some check
      for k,v in pairs(arg) do
            print(k,v)
      end

      return true --return false will fail ssh handshake
end)
--]]

print(string.format('Listen at %s:%s with %s',host,port,tostring(ctx)))

function ssl_mode()
    local srv = assert(bio.accept(host..':'..port))
    local i = 0
    if srv then
      assert(srv:accept(true))  -- make real listen
      while i<loop do
          local cli = assert(srv:accept()) --bio tcp
          local s = ctx:ssl(cli,true)
          if(i%2==0) then
            assert(s:handshake())
          else
            assert(s:accept())
          end
          
          repeat 
              d = s:read()
              if d then 
                s:write(d)
              end
          until not d
          s:shutdown()
          cli:close()
          cli = nil
          collectgarbage()
          i = i + 1
      end
    end
end

print(pcall(ssl_mode))
debug.traceback()
print(openssl.error(true))
