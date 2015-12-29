local openssl = require'openssl'

TestEngine = {}
    function TestEngine:testAll()
        local eng = assert(openssl.engine('openssl'))
        assert(eng:id(),'openssl')
        assert(eng:set_default('RSA'))
        assert(eng:set_default('ECDSA'))
    end

    function TestEngine:testLoop()
        local e = openssl.engine(true)
        while e do
            --print(e:id(), e:name())
            e = e:next()
        end
    end
