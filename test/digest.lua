local openssl = require'openssl'

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


function test_digest()
        t = openssl.get_digest()
        dump(t,0)

        t = openssl.get_digest(false)
        dump(t,0)

        t = openssl.get_digest(true)
        dump(t,0)

        md = openssl.get_digest('md5')
        dump(md:info(),0)
        aa = md:digest('abcd')

        mdc=md:init()
        dump(mdc:info(),0)
        mdc:update('abcd')
        bb = mdc:final()
        assert(aa==bb)
end

test_digest()