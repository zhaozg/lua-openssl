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
        --create with arg
        print(string.rep('-',18),'create',arg)
        pkey = assert(openssl.pkey_new(alg))
        --dump key
        t = pkey:parse()
        print(string.rep('-',18),'dump private key')
        dump(t,0)

        print(string.rep('-',18),'export evp format key')
        print(pkey:export())      --with evp format
        print(string.rep('-',18),'export raw format key')
        print(pkey:export(true))  --with raw format
        
        print(pkey:is_private())
        if (pkey:is_private()) then
                --dump public key
                print(string.rep('-',18),'get public from private key')
                local pub = pkey:export(
                        true,  --only public
                        false  --not raw format
                        )
                print(string.rep('-',18),"Encoded public key is:")
                print(pub)
                pub = openssl.pkey_read(pub)  
                print(string.rep('-',18),"object public key is:",pub)
                return pkey,pub
        end
end

local alg =   {
                --{nil}, --default to create rsa 1024 bits with 65537
                {'rsa',2048,3} --create rsa with give bits length and e
                --,{'dsa'},
                --{'dh'}
        }
        
for i=1,#alg do
        pri, pub = test_pkey(unpack(alg[i]))
        m = 'abcd'
        c = pri:encrypt(m)
        d = pub:decrypt(c)
        assert(m==d)
        print('test OK', unpack(alg[i]))
end