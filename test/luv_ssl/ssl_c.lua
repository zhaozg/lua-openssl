local uv = require('luv')
local ssl = require('luv.ssl')
-----------------------------------------------
local count = 0
local ncount = arg[3] and tonumber(arg[3]) or 40000
ncount = ncount or 40000
local step = 1000/2
local tmp = true

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
	print(ssl.error())
	collectgarbage()
end,
1000)
--------------------------------------------------------------
local address = {
	port = arg[2] and tonumber(arg[2]) or 12456,
	address = arg[1] and arg[1] or '127.0.0.1'
}

local ctx = ssl.new_ctx({
   protocol = "SSLv3_client",
   verify = {"none"},
--   options = {"all", "no_sslv2"}
})


local new_connection

function new_connection(i)

	local scli = ssl.connect(address.address,address.port,ctx, function(self)
		count = count + 1
		self:write('GET / HTTP/1.0\r\n\r\n')
		if tmp then
			self:close()
		end
		if count <= ncount then
			new_connection(i)
		end
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
		self:close()
	end
	function scli:onclose()
		count = count -1
		--print('closed')
	end
	return scli
end

local conns = {}
for i=1, step do 
	new_connection(i)
end

uv.run('default')

print("done")
