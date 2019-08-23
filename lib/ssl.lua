local openssl = require'openssl'
local socket = require'socket'
local ssl,pkey,x509 = openssl.ssl,openssl.pkey,openssl.x509
local unpack = unpack or table.unpack

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
        ..string.sub(params.protocol,4,-1) or 'TLSv1_2'
    local ctx = ssl.ctx_new(protocol,params.ciphers)
    local xkey = nil

    if params.key then
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
    end

    if(params.cafile or params.capath) then
        ctx:verify_locations(params.cafile,params.capath)
    end

    if(params.verify) then
        if type(params.verify) ~= "table" then
            params.verify = {params.verify}
        end

        local luasec_flags = {
            ["none"] = "none",
            ["peer"] = "peer",
            ["client_once"] = "once",
            ["fail_if_no_peer_cert"] = "fail"
        }

        local verify = 0
        for i,v in ipairs(params.verify) do
            verify = verify + (ssl[luasec_flags[v] or v] or v)
        end
        ctx:verify_mode(verify)
    end
    if params.options then
        if type(params.options) ~= "table" then
            params.options = {params.options}
        end
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
                return ret,msg
            end
        end

        if ret then
            self._bbf = assert(openssl.bio.filter('buffer'))
            self._sbf = assert(openssl.bio.filter('ssl',self.ssl,'noclose'))

            self.bio = assert(self._bbf:push(self._sbf))
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
        if self.ssl then
           self.ssl:shutdown()
           self.ssl = nil
        end
    end,
    send = function(self,msg,i,j)
        local m = msg
        if i then
            j = j or -1
            m = string.sub(msg,i,j)
        end
        local n = self.bio:write(m)
        if self.bio:flush() then
            return n
        end
        return nil, "bio flush error", j
    end,
    receive = function(self,fmt,prev)
        if type(fmt) == 'number' then
            local buff = prev and {prev} or {''}
            local buffsize = string.len(buff[1])
            local s = nil
            local len = fmt

            while buffsize < len do
                s = self.bio:read(len - buffsize)
                if s == nil then
                    return nil, 'closed', table.concat(buff)
                elseif s=='' then
                    return nil, 'timeout', table.concat(buff)
                elseif type(s) == "string" and s ~= '' then
                    table.insert(buff, s)
                    buffsize = buffsize + string.len(s)
                end
            end

            buff = table.concat(buff)
            if buffsize > len then
                s = string.sub(buff, len + 1, -1)
                buff = string.sub(buff, 1, len)
            end

            return buff
        end

        fmt = fmt and string.sub(fmt, 1, 2) or '*l'
        if (fmt == '*l') then
            local s = nil
            local buff = prev or ''
            local _, _, p1, p2 = string.find(buff, '(.-)\r\n(.*)')

            while not p1 do
                s = self.bio:gets(1024)
                if s == nil then
                    return nil, 'closed', buff
                elseif s=='' then
                    return nil, 'timeout', buff
                elseif type(s) == "string" and s ~= '' then
                    buff = buff .. s
                end
                _, _, p1, p2 = string.find(buff, '(.-)\r\n(.*)')
            end

            return p1
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
