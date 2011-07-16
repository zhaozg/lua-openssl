local openssl = require 'openssl'
--dump a table 
function dump(t,i)
        for k,v in pairs(t) do
                if(type(v)=='table') then
                        print( string.rep('\t',i),k..'={')
                                dump(v,i+1)
                        print( string.rep('\t',i),k..'=}')
                else
                        print( string.rep('\t',i),k..'='..tostring(v))
                end
        end
end

-- get sha1 digest method
local md = openssl.get_digest('sha1')
local msg = string.rep('I love lua.',1000)
local digest1 = md:digest(msg)

-- get digest method context
local mdc=md:init() 
for i=1,1000 do
        mdc:update('I love lua.')
end

local digest2 = mdc:final()
assert(digest1==digest2)
print('digest OK')
print(string.rep('-',78))

-- create a rsa private key
local pkey = openssl.pkey_new('rsa' ,1024, 0x10001)
print('is_private:',pkey:is_private())
print(string.rep('-',78))
print(pkey:export())
print(string.rep('-',78))

local t = pkey:parse()
dump(t,0)

print('pkey generate OK')
print(string.rep('-',78))

-- create a certificate
local args = {}
args.digest = 'sha1WithRSAEncryption'

local dn = {commonName='zhaozg', emailAddress='zhaozg@gmail.com'}

local csr = openssl.csr_new(pkey,dn,args)

t = csr:parse()
dump(t,0)

print('csr generate OK')
print(string.rep('-',78))

-- make a self sign certificate
args = {}
args.digest = 'sha1WithRSAEncryption'
args.serialNumber = '1234567890abcdef' --hexencode big number
args.num_days = 365		       --here need to more flexble

local x509 = csr:sign(nil,pkey,args)
local t = x509:parse()
dump(t, 0);

print('self signed certificate generate OK')
print(string.rep('-',78))

local pubkey = x509:get_public()
-- sign something.

local signed_data = openssl.sign('I love lua',  pkey , 'sha1')
print('#signed_data:', #signed_data)

print(md)
local verified = openssl.verify('I love lua', signed_data, pubkey, md)
assert(verified)

print('sign and verify OK')

-- please wait more sample
