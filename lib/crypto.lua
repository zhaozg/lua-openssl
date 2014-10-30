local openssl = require'openssl'
local io = require'io'

local M = {}

M["_VERSION"]       = "LuaCrypto 0.3.1"
M["_COPYRIGHT"]     = "Copyright (C) 2014 GeorgeZhao";
M["_DESCRIPTION"]   = "crypto is a high level Lua wrapper for OpenSSL based on lua-openssl";

-----------crypto------------------
function M.hex(s)
    local s = openssl.hex(s)
    return string.lower(s)
end
M.digest = openssl.digest
local dm = {}
dm.__call = function(self,alg,msg,raw) 
    raw = raw or true
--    print('MSG:',msg)
--    print('RAW:',raw)
    return M.digest.digest(alg,msg)
end
setmetatable(M.digest,dm)

M.hmac = openssl.hmac
-----------crypto encrypt/decrypt compat----------
local cipher = openssl.cipher
local C = {}

C.__index = {
    new = function(alg,key,iv)
        local c = cipher.encrypt_new(alg,key,iv)
        if c then
            local I = c:info()
            if (iv and #iv>I.iv_length) then
                error('invalid iv')
            end
            if(#key>I.key_length) then
                error('invalid key')
            end        
            local t = {}
            t.ctx = c
            setmetatable(t,C)
            return t
        end
    end,
    update = function(self,input)
        return self.ctx:update(input)
    end,
    final = function(self)
        return self.ctx:final()
    end
}

C.__call = function(self,alg,input,key,iv)
    local c = cipher.get(alg)
    local I = c:info()
    if (iv and #iv>I.iv_length) then
        error 'invalid iv'
    end
    if(#key>I.key_length) then
        error 'invalid key'
    end
    local ret, msg = cipher.encrypt(alg,input,key,iv)
    return ret,msg
end

setmetatable(C,C)
M.encrypt = C 

local D = {}

D.__index = {
    new = function(alg,key,iv)
        local c = cipher.decrypt_new(alg,key,iv)
        if c then
            local I = c:info()
            if (iv and #iv>I.iv_length) then
                error('invalid iv')
            end
            if(#key>I.key_length) then
                error('invalid key')
            end        
            local t = {}
            t.ctx = c
            setmetatable(t,D)
            return t
        end
    end,
    update = function(self,input)
        return self.ctx:update(input)
    end,
    final = function(self)
        return self.ctx:final()
    end
}

D.__call = function(self,alg,input,key,iv)
    local c = cipher.get(alg)
    local I = c:info()
    if (iv and #iv>I.iv_length) then
        error('invalid iv')
    end
    if(#key>I.key_length) then
        error('invalid key')
    end        
    local r,s =  cipher.decrypt(alg,input,key,iv)
    return r,s
end

setmetatable(D,D)
M.decrypt = D

-----------crypto random compat------------------
local R = {}
function R.load(file) 
    return openssl.rand_load(file)
end

function R.write(file) 
    return openssl.rand_write(file)
end

function R.cleanup() 
    return openssl.rand_cleanup()
end

function R.status() 
    return openssl.rand_status()
end

function R.pseudo_bytes(len)
    return openssl.random(len,false)
end

function R.bytes(len)
    return openssl.random(len,true)
end

M.rand = R

-----------crypto pkey compat------------------
local P = {}
local pkey = openssl.pkey

local PKEY_M = {}
PKEY_M.__index = {}
function PKEY_M.__index.to_pem(self,ispriv)
    local raw = ispriv and true or false
    local pem =  self.evp_pkey:export(ispriv,raw,'pem')
    return pem
end

function PKEY_M.__index.write(self,pubfile,prifile)
    local PUB,PRI = self:to_pem(false),self:to_pem(true)
    local f = io.open(pubfile,'w+')
    if f then
        f:write(PUB)
        f:close()
    end
    local f = io.open(prifile,'w+')
    if f then
        f:write(PRI)
        f:close()
    end
end

function P.read(file,ispriv)
    local f = io.open(file,'r')
    if f then
        local pem = f:read("*all")
        f:close()
        return P.from_pem(pem,ispriv)
    end
end

function P.from_pem(pem, ispriv)
    local k = pkey.read (pem, ispriv,'pem')
    if k then
        local key = {}
        key.evp_pkey = k
        setmetatable(key,PKEY_M)
        return key
    end
end

function P.generate(alg,bits)
    local k = pkey.new (alg,bits)
    if k then
        local key = {}
        key.evp_pkey = k
        setmetatable(key,PKEY_M)
        return key
    end    
end

M.pkey = P

------------------------------------------
function M.sign(alg,input,prikey)
    local pk = prikey.evp_pkey
    return pkey.sign(pk,input,alg)
end

function M.verify(alg,input,sig,pubkey)
    local pk = pubkey.evp_pkey
    return pkey.verify(pk,input,sig,alg)
end


-----------------crypto seal/open compat
local S = {}
S.__index = {
    new = function(alg,pubkey)  
        local c,key,iv = pkey.seal_init(pubkey.evp_pkey,alg)
        if c then
            local t = {}
            t.ctx = c
            t.key = key 
            t.iv = iv
            setmetatable(t,S)
            return t
        end
    end,
    update = function(self,data)
        return pkey.seal_update(self.ctx,data)
    end,
    final = function(self)
        local s =  pkey.seal_final(self.ctx)
        return s,self.key,self.iv
    end,
}
S.__call = function(self,alg,input,pubkey)
    local msg, key,iv = pkey.seal(pubkey.evp_pkey, input, alg) 
    return msg,key,iv
end
   
setmetatable(S,S)

M.seal = S

local O = {}
O.__index = {
    new = function(alg,privkey, ekey, iv)
        local c,key,iv = pkey.open_init(privkey.evp_pkey,ekey,iv,alg)
        if c then
            local t = {}
            t.ctx = c
            t.key = key 
            t.iv = iv
            setmetatable(t,O)
            return t
        end
    end,
    update = function(self,data)
        return pkey.open_update(self.ctx,data)
    end,
    final = function(self)
        local s =  pkey.open_final(self.ctx)
        return s
    end,
}
O.__call = function(self,alg,input,prikey,ek,iv)
    return pkey.open(prikey.evp_pkey,input,ek,iv,alg)
end
   
setmetatable(O,O)

M.open = O

----------------crypto pki compat------------
local X = {}
X.__index = {
    add_pem = function(self,pem)
        local ret,x = pcall(openssl.x509.read,pem)
        if ret then
            self.sk_x509:push(x)
            return x
        end
        return nil
    end,
    verify_pem = function(self,pem)
        local ret,x = pcall(openssl.x509.read,pem)
        if ret then
            local t = {}
            for i=1,#self.sk_x509 do
                table.insert(t,self.sk_x509:get(i-1))
            end
            local store = openssl.x509.store.new(t)
            return x:check(store)
        end
        return false    
    end
}

function M.x509_ca()
    local ca = openssl.x509.sk_x509_new()
    local t = {}
    t.sk_x509 = ca
    setmetatable(t,X)
    return t
end

----------------------------------------------
return M
