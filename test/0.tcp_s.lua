local openssl = require 'openssl'
local bio = openssl.bio
local host, port, loop

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
loop = arg[3] and tonumber(arg[3]) or 100

print(string.format('Listen at %s:%s',host,port))
local i = 0;
local srv = assert(bio.accept(host..':'..port))
if srv then
  assert(srv:accept(true))  -- make real listen
  while i<loop do
      local cli = assert(srv:accept())
      repeat
        local s = cli:read()
          if s then
            cli:write(s)
            cli:flush()
          end
      until not s
      cli:close()
      cli = nil
      collectgarbage()
      i = i + 1
  end
  srv:close()
end
