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

print(string.format('Listen at %s:%s with %s',host,port,tostring(ctx)))

function ssl_mode()
    local srv = assert(ctx:bio(host..':'..port,true))
    local i = 0
    if srv then
      print('listen BIO:',srv)
      assert(srv:accept(true),'Error in accept BIO')  -- make real listen
      while i<loop do
          local cli = assert(srv:accept(),'Error in ssl connection') --bio tcp
          assert(cli:handshake(),'handshake fail')
          repeat 
              d = cli:read()
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

pcall(ssl_mode)
debug.traceback()
print(openssl.error(true))
