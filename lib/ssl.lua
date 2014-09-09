local openssl = require'openssl'
local ssl,pkey,x509 = openssl.ssl,openssl.pkey,openssl.x509

local M = {}

local function load(path)
    local f = assert(io.open(path,'r'))
    if f then
        local c = f:read('*all')
        f:close()
        return c
    end
end

function M.newcontext(params)
--[[
local params = {
   mode = "server",
   protocol = "tlsv1",
   key = "../certs/serverAkey.pem",
   certificate = "../certs/serverA.pem",
   cafile = "../certs/rootA.pem",
   verify = {"peer", "fail_if_no_peer_cert"},
   options = {"all", "no_sslv2"},
   password = 'password'
}
--]]
    if params.mode=='server' then io.read() end
    
    local protocol = string.upper(string.sub(params.protocol,1,3))
        ..string.sub(params.protocol,4,-1)
    local ctx = ssl.ctx_new(protocol,params.ciphers)
    local xkey = nil
    if (type(params.password)=='nil') then
        xkey = assert(pkey.read(load(params.key),true,'pem'))
    elseif (type(params.password)=='string')  then
        xkey = assert(pkey.read(load(params.key),true,'pem',params.password))
    elseif (type(params.password)=='function') then
        local p = assert(params.password())
        xkey = assert(pkey.read(load(params.key),true,'pem',p))
    end

    assert(xkey)
    local xcert = nil
    if (params.certificate) then
        xcert = assert(x509.read(load(params.certificate)))
    end
    assert(ctx:use( xkey, xcert))

    if(params.cafile or params.capath) then
        ctx:verify_locations(params.cafile,params.capath)
    end

    unpack = unpack or table.unpack   
    if(params.verify) then
        local args = {}
        for i=1,#params.verify do
            table.insert(args, params.verify[i])
        end
        ctx:set_verify(args)
    end
    if params.options then
        local args = {}
        for i=1,#params.options do
            table.insert(arg,params.options[i])
        end
        ctx:options(unpack(args))
    end
    if params.verifyext then
        for k,v in pairs(params.verifyext) do
            params.verifyext[k] = string.gsub(v,'lsec_','')        
        end
        ctx:set_cert_verify(params.verifyext)
    end
    local t = {}
    t.ctx = ctx 
    t.mode = params.mode
    t.params = params
    return t
end
----------------------------------------------------------
local S = {}

S.__index = {
    dohandshake = function(self)
        local ret,msg = self.ssl:handshake()
        if not self.timeout then
            while not ret do
                if (msg=='want_read' or msg=='want_write') then
                    ret,msg = self.ssl:handshake()
                else
                    print(ret,msg)
                    return ret,msg
                end
            end           
        end
        if ret then
            local b = assert(openssl.bio.filter('buffer'))
            local s = assert(openssl.bio.filter('ssl',self.ssl,'noclose'))

            self.bio = assert(b:push(s))
        else
            msg = msg and string.gsub(msg,'_','') or msg
        end
        return ret,msg
    end,
    getpeercertificate = function(self)
        self.peer,self.peerchain = self.ssl:peer()
        return self.peer
    end,
    getpeerverification = function(self)
        local r, t = self.ssl:getpeerverification()
        if not r then
            local tt = {}
            for i,err in pairs(t) do
                tt[i] = {}
                tt[i][1] = string.format('error=%d string=%s level=%s',err.error,err.error_string,err.error_level)
            end
            return r,tt
        end        
        return r        
    end,
    getpeerchain = function(self)
        self.peer,self.peerchain = self.ssl:peer()
        local chains = {}
        if (self.peerchain) then
            chains = self.peerchain:totable()
        end
        return {}
    end,
    close = function(self)
        self.ssl:shutdown()
        self.ssl = nil
    end,
    send = function(self,msg,i,j)
        local m = msg
        if i then
            j = j or -1
            m = string.sub(msg,i,j)
        end
        return self.bio:write(m) and self.bio:flush()
    end,
    receive = function(self,fmt)
        if type(fmt)=='number' then
            return self.bio:read(fmt)
        end
        fmt = fmt and string.sub(fmt,1,2) or '*a'
        if (fmt=='*l') then
            local r, m = self.bio:gets()
            while m==-1 do
                local r,rd,wr,sp = self.bio:retry()
                if r then
                    r,m = self.bio:gets()
                    if r then
                        return r
                    end
                end
            end
            return r,msg
        end
        
        local n = self.bio:read(65535)
    end,
    settimeout = function(self,n,b)
        self.timeout = n
        return self.socket:settimeout(n,b)
    end,
    info = function(self,field)
        --[[
        algbits
        authentication
        bits
        cipher
        compression
        encryption
        export
        key
        mac
        protocol
        --]]
        local cc = self.ssl:current_cipher()
        if cc then
            local info = {
                bits = cc.bits,
                algbits = cc.algbits,
                protocol = cc.protocol
            }
            if cc.description then
                info.cipher, info.protocol, info.key,
                info.authentication, info.encryption, info.mac =
                    string.match(cc.description, 
                      "^(%S+)%s+(%S+)%s+Kx=(%S+)%s+Au=(%S+)%s+Enc=(%S+)%s+Mac=(%S+)")
                info.export = (string.match(cc.description, "%sexport%s*$") ~= nil)
            end
            self.compression = self.ssl:current_compression()
            if field then
                return info[field]
            end
            return info    
        end
    end
}


function M.wrap(sock, cfg)
   local ctx, msg
   if type(cfg) == "table" and not cfg.ctx then
      ctx, msg = M.newcontext(cfg)
      if not ctx then return nil, msg end
   else
      ctx = cfg
   end
   
   local s, msg = ctx.ctx:new(sock:getfd())
   if s then
      if(ctx.mode=='server') then
        s:set_accept_state()
      else
        s:set_connect_state()
      end
      local t = {}
      t.ssl = s
      t.socket = sock
      setmetatable(t,S)
      return t
   end
   return nil, msg 
end

function M.loadcertificate(pem)
    return openssl.x509.read(pem,'pem')
end

return M
