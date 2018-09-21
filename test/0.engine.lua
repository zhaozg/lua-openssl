local openssl = require'openssl'

TestEngine = {}
    function TestEngine:testAll()
        local eng = assert(openssl.engine('openssl'))
        assert(eng:id(),'openssl')
        assert(eng:set_default('RSA'))
        local _,sslv
        _, _, sslv = openssl.version(true)
        if sslv>=0x10100000 then
          assert(eng:set_default('EC'))
        else
          assert(eng:set_default('ECDSA'))
      end
    end

    function TestEngine:testLoop()
        local e = openssl.engine(true)
        while e do
            --print(e:id(), e:name())
            e = e:next()
        end
    end
