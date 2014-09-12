local uv = require('luv')
local ssl = require('luv.ssl')

-----------------------------------------------
local count = 0
local ncount = 20000
local step = 1000/2

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
--------------------------------------------------------------
local address = {
	port = 4433,
	address = '192.168.0.248'
}
local address = {
	port = 4433,
	address = '192.168.0.155'
}
---[[
local address = {
	port = 12456,
	address = '127.0.0.1'
}
--]]
local ctx = ssl.new_ctx({
   protocol = "SSLv3_client",
   verify = {"none"},
--   options = {"all", "no_sslv2"}
})


local new_connection

function new_connection(i)
	local scli = ssl.connect(address.address,address.port,ctx, function(scli)
		count = count + 1
		
		--scli:write('GET / HTTP/1.0\r\n\r\n')
		if count <= ncount then
			new_connection(i)
		end
		--]]
	end)

		
		function scli:ondata(chunk)
			--print(chunk)
		end
		
		function scli:onerror(err)
			print('onerror',err)
		end
		
		function scli:onend()
			--print('onend********8')
			--count = count -1
			scli:close()
		end
		function scli:onclose()
			scli:close()
		end
	return scli
end

local conns = {}
for i=1, step do 
	conns[i] = new_connection(i)
--	print('create ',i,conns[i])
end

uv.run('default')

print("done")
