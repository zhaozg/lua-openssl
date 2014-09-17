local openssl = require'openssl'
local bio = openssl.bio
io.read()

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";

local ctx = openssl.ssl.ctx_new('SSLv23','ALL')
print(string.format('Connect to %s:%s with %s',host,port,ctx))

function mode_ssl()
    local bio = assert(bio.connect(host..':'..port,true)) --tcp
    if bio then
        local cli = assert(ctx:ssl(bio,false))
        if cli then
            print('connected',cli:connect() )--ssl
            cli:write('aaa')
            cli:shutdown()
            cli = nil
        end
        bio:shutdown()
        bio,cli = nil,nil
        collectgarbage()
    end
end

function mode_bio()
    local cli = assert(ctx:bio(host..':'..port,false)) 
    print(cli)
    if cli then
        assert(cli:connect())
        cli:write('aaa')
        cli = nil
    end
    collectgarbage()
end

for i=1,100000 do
    mode_bio()
    mode_ssl()
end
