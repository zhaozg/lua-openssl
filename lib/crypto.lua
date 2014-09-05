local openssl = require'openssl'
local io = require'io'

local M = {}

M["_VERSION"]       = "LuaCrypto 0.3.1"
M["_COPYRIGHT"]     = "Copyright (C) 2014 GeorgeZhao";
M["_DESCRIPTION"]   = "crypto is a high level Lua wrapper for OpenSSL based on lua-openssl";

-----------crypto------------------
function M.hex(s)
    return openssl.hex(s)
end

local cipher = openssl.cipher
function M.encrypt(alg,input,key,iv)
    local c = cipher.get(alg)
    return c:encrypt(input,key,iv)
end

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

function M.sign(alg,input,prikey)
    local pk = prikey.evp_pkey
    return pkey.sign(pk,input,alg)
end

function M.verify(alg,input,sig,pubkey)
    local pk = pubkey.evp_pkey
    return pkey.verify(pk,input,sig,alg)
end

M.pkey = P
----------------------------------------------
return M
