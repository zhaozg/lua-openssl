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


function test_cipher()
        key = ''
        iv = ''
        t = openssl.get_cipher()
        dump(t,0)

        t = openssl.get_cipher(false)
        dump(t,0)

        t = openssl.get_cipher(true)
        dump(t,0)

        c = openssl.get_cipher('des')
        dump(c:info(),0)

        m = 'abcd'
        cc=c:init(true,key,iv)
        e1 = cc:update(m)
        bb = e1..cc:final()

        cc=c:init(false,key,iv)
        e1 = cc:update(bb)
        m1 = e1..cc:final()
        assert(m1==m)
        print(#bb,bb)


        c1=c:decrypt_init(key,iv)
        m1 = c1:decrypt_update(bb)
        m1= m1..c1:decrypt_final()
        print(#m1,m1)
        assert(m1==m)

        c1=c:encrypt_init(key,iv)
        m1 = c1:encrypt_update(m)
        m1= m1..c1:encrypt_final()
        assert(m1==bb)


end

test_cipher()