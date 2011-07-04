local openssl = require('openssl')

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

function test_pkey(alg)
        pkey = openssl.pkey_new(alg)
        print(pkey)
        t = pkey:get_details()
        dump(t,0)
        print(pkey:is_private())
        print(string.rep('-',78))
        print(pkey:export())
        print(pkey:export(true))
end

alg = {nil, 'rsa','dsa','dh'}
for i=1,#alg do
        test_pkey(alg[i])
end