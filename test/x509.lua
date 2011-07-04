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

function test_x509()
        local x = openssl.x509_read('file://b.cer')
        print(x)
        t = x:parse()
        dump(t,0)
        t = openssl.x509_parse(x)
        print(t)
end

test_x509()
