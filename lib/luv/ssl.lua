local uv = require('luv')
local openssl=require'openssl'
local ssl = openssl.ssl
local bio = openssl.bio
local bit = require'bit'

local M = {}

local function load(path)
    local f = io.open(path,'rb')
    if f then
        local c = f:read('*a')
        f:close()
        return c
    end
end

function M.new_ctx(params)
    params = params or {}
    local protocol = params.protocol or  'SSLv3_client'
    local ctx = ssl.ctx_new(protocol, params.ciphers)

	local xkey,xcert = nil,nil

    if (params.certificate) then
        xcert = assert(x509.read(load(params.certificate)))
    end

	if params.key then
		if (type(params.password)=='nil') then
			xkey = assert(pkey.read(load(params.key),true,'pem'))
		elseif (type(params.password)=='string')  then
			xkey = assert(pkey.read(load(params.key),true,'pem',params.password))
		elseif (type(params.password)=='function') then
			local p = assert(params.password())
			xkey = assert(pkey.read(load(params.key),true,'pem',p))
		end
		assert(ctx:use(xkey, xcert))
	end

    if(params.cafile or params.capath) then
        ctx:verify_locations(params.cafile,params.capath)
    end

    local unpack = unpack or table.unpack   
    if(params.verify) then
        ctx:set_verify(params.verify)
    end
    if params.options and #params.options>0 then
        local args = {}
        for i=1,#params.options do
            table.insert(arg,params.options[i])
        end
        ctx:options(ssl.none)
    end
    
    if params.verifyext then
        ctx:set_cert_verify(params.verifyext)
    end
    if params.dhparam then
        ctx:set_tmp('dh',params.dhparam)
    end
    if params.curve then
        ctx:set_tmp('ecdh',params.curve)
    end
	return ctx
end

local S = {}
S.__index = {
    handshake = function(self, connected_cb)
		if not self.connecting then
			function self.socket.ondata(socket,chunk)
				self.inp:write(chunk)
				self:handshake(connected_cb)
			end
            function self.socket.onclose()
                if self.onclose then
                    self:onclose()
                else
                    self:close()
                end
            end
            function self.socket.onerror()
                if self.onerror then
                    self:onerror()
                else
                    self:close()
                end
            end
            uv.read_start(self.socket)
            self.connecting = true
		end

		local ret,err = self.ssl:handshake()
        if ret==nil then
            if (self.onerror) then
                self:onerror()
            elseif (self.onclose) then
                self:onclose()
            else
                self:close()
            end
        else
			local i, o = self.out:pending()
			if i > 0 then  --客户端握手使用
				uv.write(self.socket, self.out:read(), function()
                    self:handshake(connected_cb)
                end)
                return
			end

			self.connected = true
			self.connecting = nil

            function self.socket.ondata(socket,chunk)
                local ret,err = self.inp:write(chunk)
                if ret==nil then
                    if self.onerror then
                        self.onerror(self)
                    elseif self.onend then
                        self.onend(self)
                    end
                    return
                end
                
                local i,o = self.inp:pending()
                if i>0 then
                    local ret, msg = self.ssl:read()
                    if ret then
                        self:ondata(ret)
                    end
                end
                if o > 0 then
                    assert(false,'never here')
                end
            end
            connected_cb(self)
        end

		return self.connected
	end,
    shutdown = function(self,both)
        self.ssl:shutdown()
    end,
    close = function(self)
        if self.connected then
            self.connected = nil
            if (self.onclose) then
                self.onclose(self)
            end
            self.inp:close()
            self.out:close()
            self.inp = nil
            self.out = nil
        end
    end,
    write = function(self,data,cb)
        local ret,err = self.ssl:write(data)
        if ret==nil then
            if self.onerror then
                self.onerror(self)
            elseif self.onend then
                self.onend(self)
            end
            return
        end
        local i,o = self.out:pending()
        if i>0 then
            uv.write(self.socket,self.out:read(),cb)
        end
        if o > 0 then
            assert(false,'never here')
        end
    end
}

function M.new_ssl(ctx,socket,server)
    local s = {}
    s.inp,s.out  =  bio.mem(),bio.mem()
    s.socket    =  socket
    s.mode = server and server or false
    s.ssl = ctx:new(s.inp,s.out,s.mode)
	uv.tcp_nodelay(socket,true)
    
    setmetatable(s,S)
    return s
end

function M.connect(host,port,ctx,connected_cb)
    if type(ctx)=='table' then
        ctx = ssl.new_ctx(ctx)
    end
    local socket = uv.new_tcp()
    local scli = M.new_ssl(ctx, socket) 
    
    uv.tcp_connect(socket, host, port, function(err)
		scli:handshake(function(scli)
            if connected_cb then
                connected_cb(scli)
            end
		end)
    end)
    function socket:onend()
        if (scli.onend) then
            scli:onend()
        end
    end
    return scli    
end

function M.error()
    return openssl.error(true)
end

return M
