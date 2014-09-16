require 'openssl'

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
print(string.format('Listen at %s:%s',host,port))

local srv = assert(bio.accept(host..':'..port))
if srv then
  local cli = assert(srv:accept())  -- make real listen
  while true do
      cli = assert(srv:accept())
      local s
      print('cli',cli)
      repeat 
          s = cli:read()
          if s then 
            cli:write(s)
            cli:flush()
          end
      until not s
      cli:close()
      openssl.error(true)
  end
end
