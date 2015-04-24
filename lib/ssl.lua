local openssl = require'openssl'
local socket = require'socket'
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
    local protocol = params.protocol and string.upper(string.sub(params.protocol,1,3))
        ..string.sub(params.protocol,4,-1) or 'SSLv3'
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
        ctx:verify_mode(args)
    end
    if params.options then
        ctx:options(unpack(params.options))
    end
    if params.verifyext then
        for k,v in pairs(params.verifyext) do
            params.verifyext[k] = string.gsub(v,'lsec_','')        
        end
        ctx:set_cert_verify(params.verifyext)
    end
    if params.dhparam then
        ctx:set_tmp('dh',params.dhparam)
    end
    if params.curve then
        ctx:set_tmp('ecdh',params.curve)
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
        local ret,msg
        
        socket.select({self.ssl}, {self.ssl}, self.timeout)
    
        ret,msg = self.ssl:handshake()
        while not ret do
            if (msg=='want_read' or msg=='want_write') then
                ret,msg = self.ssl:handshake()
            else
                print(ret,msg)
                return ret,msg
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
                tt[i][1] = string.format('error=%d string=%s depth=%s',err.error,err.error_string,err.error_depth)
            end
            return r,tt
        end        
        return r        
    end,
    getfd = function(self)
        local fd = self.ssl:getfd()
        return fd
    end,
    getpeerchain = function(self)
        self.peer,self.peerchain = self.ssl:peer()
        local chains = {}
        --[[
        print(self.peerchain,#self.peerchain)
        for i=1,#self.peerchain do 
            table.insert(chains,self.peerchain:get(i-1))
        end
        --]]
        if (self.peerchain) then
            chains = self.peerchain:totable()
        end
        return chains
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
        self.buff = self.buff or ''
        local r,m = socket.select({self.ssl},nil,self.timeout)
        if #r==0 then
            return nil,'timeout'
        end
        
        local s = nil
        if type(fmt)=='number' then
            if len > #self.buf then
                s = self.bio:read(len-#self.buf)
                if s == nil then
                    return nil, 'closed'
                else
                    self.buff = self.buff..s
                end
            else
                s = self.bio:gets()
                if s == nil then
                    return nil,'closed'
                else
                    self.buf = self.buf..s
                end
            end
            
            if #self.buf>=len then
                s = string.sub(self.buf,1,len)
                self.buf = string.sub(self.buf,len+1,-1)
            else
                s = self.buff 
                self.buff = ''
            end
            return s
        end
        
        fmt = fmt and string.sub(fmt,1,2) or '*a'
        if (fmt=='*l') then
            _,_,s, s1 = string.find(self.buff,'(.-)\n(.*)')
            if not s then
                local r, m = self.bio:gets(245)
                if r then
                    self.buff = self.buff .. r
                elseif(m==-2) then
                    return nil,'closed',self.buff
                else
                    if not self.timeout then
                        repeat
                            r, m = self:receive(fmt)
                        until (not r) or (m=='closed')
                        return r,m
                    end
                end
                _,_,s, s1 = string.find(self.buff,'(.-)\n(.*)')
            end
            if s then
                self.buff = s1
                return s
            else
                return nil, 'wantread',self.buff
            end
        end
        
        s = self.bio:read(65535)
        if s then
            s = self.buff .. s
            self.buff = ''
        end
    end,
    sni = function(self,arg)
        if type(arg) =='string'  then
            self.ssl:set('hostname',arg)
        elseif type(arg)=='table' then
            local t = {}
            for k,v in pairs(arg) do
                t[k] = v.ctx
            end
            self.ssl:ctx():set_servername_callback(t)
        end
    end,
    
    settimeout = function(self,n,b)
        self.timeout = n
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
   
   local s, msg = ctx.ctx:ssl(sock:getfd())
   if s then
      if(ctx.mode=='server') then
        s:set_accept_state()
      else
        s:set_connect_state()
      end
      local t = {}
      t.ssl = s
      t.socket = sock
      t.timeout = type(cfg)=='table' and cfg.timeout or nil
      setmetatable(t,S)
      return t
   end
   return nil, msg 
end

function M.loadcertificate(pem)
    return openssl.x509.read(pem,'pem')
end

return M
