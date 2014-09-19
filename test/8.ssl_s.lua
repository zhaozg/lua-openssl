local openssl = require'openssl'
local bio = openssl.bio

host = arg[1] or "127.0.0.1"; --only ip
port = arg[2] or "8383";

local function get_cert_pkey()
        local dn = {commonName='zhaozg'};
        local pkey = assert(openssl.pkey.new())
        local req = assert(csr.new(pkey,dn))
        local args = {}

        args.attribs = {}
        args.extentions = {}

        args.digest = 'sha1WithRSAEncryption'
        args.num_days = 365


        args.serialNumber = 1
        local cert = assert(req:sign(nil,pkey,args))
        return cert,pkey
end

local ctx = openssl.ssl.ctx_new('SSLv23','ALL')
local cert,pkey = get_cert_pkey()

ctx:use(pkey, cert)

print(string.format('Listen at %s:%s with %s',host,port,ctx))

--SSL Server
local srv,ssl = assert(ctx:bio(host..':'..port,true,true))
local cli = assert(srv:accept())
print(srv,ssl,cli)

while cli do
    cli = assert(srv:accept()) -- bio
    print(cli)
    
    local s 
    repeat
        s = assert(cli:read())
        print('get',s)
    until not s
    cli:shutdown()
end

--[[
local srv = assert(bio.accept(host..':'..port))
local cli = assert(srv:accept())

while cli do
    assert(srv:accept()) --tcp
    cli = assert(ctx:new(cli,true))
    assert(cli:accept()) --ssl
    print('CLI:',cli)
    while cli do
        local s = assert(cli:read())
        print(s)
        assert(cli:write(s))
    end
    print(openssl.error(true))
end

--]]


--[[

socket = require("socket");
ssl = require'openssl'.ssl



server = assert(socket.bind(host, port));

ack = "\n";
while 1 do
    print("server: waiting for client connection...");
    control = assert(server:accept());
    while 1 do 
        command = assert(control:receive());
        assert(control:send(command..'\n'));
        print(command);
    end
end
--]]


--[[
server = assert(socket.bind(host, port));
ctx = ssl.ctx_new()

while 1 do
    print("server: waiting for client connection...");
    control = assert(server:accept());
    print('accept',control)
    SC = ctx:new(control)
    print(SC:accept())
    print(SC:state())
    while false do 
        command = assert(SC:read());
        assert(SC:write(command..'\n'));
        print(command);
    end
    print(openssl.error(true))
end
--]]
