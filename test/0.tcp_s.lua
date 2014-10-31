local openssl = require 'openssl'
local bio = openssl.bio
io.read()

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
print(string.format('Listen at %s:%s',host,port))

local srv = assert(bio.accept(host..':'..port))
if srv then
  assert(srv:accept(true))  -- make real listen
  while true do
      local cli = assert(srv:accept())
      local s
      print('accept',cli)
      repeat 
          s = cli:read()
          if s then 
            cli:write(s)
            cli:flush()
          end
      until not s
      cli:close()
      cli = nil
      collectgarbage()
  end
end
