require 'openssl'

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";
print(string.format('CONNECT to %s:%s',host,port))

function mk_connection(host,port)
  local cli = assert(bio.connect(host..':'..port,true))
  if(cli) then
    s = 'aaa'
    for j=1,100 do
          assert(cli:write(s))
          assert(cli:flush())
          assert(cli:read())
    end
    cli:close()
  end
  openssl.error(true)
end

for i=1,1000000 do
  mk_connection(host,port)
end
