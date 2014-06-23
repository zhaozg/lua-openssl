local openssl = require'openssl'
local bio = openssl.bio
io.read()

host = host or "127.0.0.1"; --only ip
port = port or "8383";

--TCP Client
--[[
local cli = assert(bio.connect(host..':'..port,true))

while cli do
    s = io.read()
    if(#s>0) then
        print(cli:write(s))
        ss = cli:read()
        assert(#s==#ss)
    end
end
print(openssl.error(true))
--]]

--SSL Client
--[[
local ctx = openssl.ssl.ctx_new('SSLv23','ALL')

local cli = assert(bio.connect(host..':'..port,true)) --tcp
cli = assert(ctx:new(cli,false))
print(cli:connect() )--ssl
print(openssl.error(true))
 
while cli do
    s = io.read()
    if(#s>0) then
        print(cli:write(s))
        ss = cli:read()
        assert(#s==#ss)
    end
end
print(openssl.error(true))
--]]

--SSL BIO Client
local ctx = openssl.ssl.ctx_new('SSLv23','ALL')

local cli,ssl = assert(ctx:bio(host..':'..port,false,true))
print(cli:connect() )--ssl
print(openssl.error(true))
 
while cli do
    s = io.read()
    if(#s>0) then
        print(cli:write(s))
        ss = cli:read()
        assert(#s==#ss)
    end
end
print(openssl.error(true))

--[[
local socket = require("socket")
ssl = require'openssl'.ssl

host = host or "localhost"
port = port or 8383
if arg then
	host = arg[1] or host
	port = arg[2] or port
end

print("Attempting connection to host '" ..host.. "' and port " ..port.. "...")
c = assert(socket.connect(host, port))
print("Connected! Please type stuff (empty line to stop):")
l = io.read()
while l and l ~= "" and not e do
    l = l..'\n'
	assert(c:send(l))
    ll = c:receive(#l)
    assert(ll==l)
	l = io.read()
end
--]]
--[[
ctx = ssl.ctx_new()

c = assert(socket.connect(host, port))
CLI = ctx:new(c)
assert(CLI:connect())
print("Connected! Please type stuff (empty line to stop):")
l = io.read()
while l and l ~= "" and not e do
    l = l..'\n'
	assert(c:CLI(l))
    ll = c:CLI(#l)
    assert(ll==l)
	l = io.read()
end
--]]

