local uv = require 'luv'
local ssl = require 'luv.ssl'

-----------------------------------------------
---[[
local count = 0

local function setInterval (fn, ms)
  local handle = uv.new_timer()
  uv.timer_start(handle, ms, ms, fn)
  return handle
end

setInterval(function ()
    print(os.date(), count)
    print(ssl.error())
    collectgarbage()
  end, 1000)
--]]
--------------------------------------------------------------
host = arg[1] or "127.0.0.1" --only ip
port = arg[2] or "8383"

local address = {
  port = tonumber(port),
  address = host,

}

local ctx = ssl.new_ctx {
  protocol = "TLSv1_2_server",
  key = "../luasec/certs/serverAkey.pem",
  certificate = "../luasec/certs/serverA.pem",
  cafile = "../luasec/certs/rootA.pem",
  verify = ssl.none,
  --   options = {"all", "no_sslv2"}

}

function create_server (host, port, on_connection)
  local server = uv.new_tcp()
  uv.tcp_bind(server, host, port)
  uv.listen(server, 64, function (self)
      local client = uv.new_tcp()
      uv.accept(server, client)
      on_connection(client)
    end)
  return server
end

local p = print
local server = create_server(address.address, address.port, function (client)

    local scli = ssl.new_ssl(ctx, client, true)
    scli:handshake(function (scli)
        print 'CONNECTED'
        count = count + 1
      end)

    function scli:ondata (chunk)
      print("ondata", chunk)
      self:close()
    end
    function scli:onerror (err)
      print('onerr', err, ssl.error())
    end

    function scli:onend ()
      print "onend"
      uv.shutdown(client, function ()
          print "onshutdown"
          uv.close(client)
        end)
    end
  end)

local address = uv.tcp_getsockname(server)
p("server", server, address)

uv.run 'default'

print "done"
