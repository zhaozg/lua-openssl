local openssl = require 'openssl'
local bio = openssl.bio
local host,port,loop

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100
print(string.format('CONNECT to %s:%s',host,port))

local function mk_connection(host,port)
  local cli = assert(bio.connect(host..':'..port,true))
  if(cli) then
    s = 'aaa'
    io.write('.')
    for j=1,100 do
          assert(cli:write(s))
          assert(cli:flush())
          assert(cli:read())
    end
    cli:shutdown()
    cli:close()
    cli = nil
    collectgarbage()
  end
end

for i=1,loop do
  mk_connection(host,port)
end
print(openssl.error(true))
