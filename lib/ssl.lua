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
}
--]]
    local protocol = string.upper(string.sub(params.protocol,1,3))
        ..string.sub(params.protocol,4,-1)
    local ctx = ssl.ctx_new(protocol,params.ciphers)
    if (params.key and params.certificate) then
        assert(ctx:use( assert(pkey.read(load(params.key),true)),
                        assert(x509.read(load(params.certificate)))))
    end
    if(params.cafile or params.capath) then
        ctx:verify_locations(params.cafile,params.capath)
    end

    unpack = unpack or table.unpack   
    if(params.verify) then
        local args = {}
        for i=1,#params.verify do
            table.insert(args, string.sub(params.verify[i],1,4))
        end
        ctx:verify_mode(args)
    end
    if params.options then
        local args = {}
        for i=1,#params.options do
            table.insert(arg,params.options[i])
        end
        ctx:options(unpack(args))
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
        while not ret do
            if (msg=='want_read' or msg=='want_write') then
                ret,msg = self.ssl:handshake()
            else
                print(ret,msg)
                return ret,msg
            end
        end
        return ret
    end,
    getpeercertificate = function(self)
        self.peer,self.peerchain = self.ssl:peer()
        return self.peer
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
      setmetatable(t,S)
      return t
   end
   return nil, msg 
end

function M.loadcertificate(pem)
    return openssl.x509.read(pem,'pem')
end

return M
