local uv = require('luv')
local ssl = require('luv.ssl')

-----------------------------------------------
---[[
local count = 0

local function setInterval(fn, ms)
  local handle = uv.new_timer()
  function handle:ontimeout()
    fn();
  end
  uv.timer_start(handle, ms, ms)
  return handle
end

setInterval(function()
	print(os.date(),count)
end,
1000)
--]]
--------------------------------------------------------------
local address = {
	port = 4433,
	address = '192.168.0.248'
}

local address = {
	port = 12456,
	address = '127.0.0.1'
}

local ctx = ssl.new_ctx({
   protocol = "SSLv3_server",
   verify = {"none"},
   key = "certs/serverAkey.pem",
   certificate = "certs/serverA.pem",
   cafile = "certs/rootA.pem",
   verify = {"none"},   
--   options = {"all", "no_sslv2"}
})

function create_server(host, port, on_connection)
  local server = uv.new_tcp()
  uv.tcp_bind(server, host, port)
  function server:onconnection()
    local client = uv.new_tcp()
    uv.accept(server, client)
    on_connection(client)
  end
  uv.listen(server)
  return server
end

local p = print
local server = create_server(address.address, address.port, function (client)

	local srv = ssl.new_ssl(ctx,client,true)
	srv:handshake(function(self)
		count = count + 1
	end)

	function srv:ondata(chunk)
		print("ondata", chunk)
		uv.write(client, chunk, function ()
		  print("written", chunk)
		end)
	end
	
	function srv:onend()
		print("onend")
		uv.shutdown(client, function ()
		  print("onshutdown")
		  uv.close(client)
		end)
	end
	
	function srv:onclose()
		print("client onclose")
	end

	function srv:onerror(err)
		print('onerr',err,ssl.error())
	end
	uv.read_start(client)
end)
function server:onclose()
  p("server closed")
end
local address = uv.tcp_getsockname(server)
p("server", server, address)

uv.run('default')

print("done")
