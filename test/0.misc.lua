local openssl = require('openssl')

local msg = 'The quick brown fox jumps over the lazy dog.'
TestLhtml = {}
    function testHex()
        local ano = openssl.hex(msg)
        assertEquals(openssl.hex(msg,true),ano)
        local raw = openssl.hex(ano,false)
        assertEquals(raw,msg)
        assertEquals(#msg*2,#ano)
    end

    function testBase64()
        local ano = openssl.base64(msg)
        --default without newline
        assert(#ano>#msg)
        assert(not string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true),ano)
        local raw = openssl.base64(ano,false)
        assertEquals(raw,msg)

        --without newline
        local ano = openssl.base64(msg,true,true)
        assert(#ano>#msg)
        assert(not string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true,true),ano)
        local raw = openssl.base64(ano,false,true)
        assertEquals(raw,msg)

        --with newline
        ano = openssl.base64(msg,true,false)
        assert(#ano>#msg)
        assert(string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true,false),ano)
        raw = openssl.base64(ano,false,false)
        assertEquals(raw,msg)

        msg = msg..msg..msg
        ano = openssl.base64(msg)
        --default without newline
        assert(#ano>#msg)
        assert(not string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true),ano)
        raw = openssl.base64(ano,false)
        assertEquals(raw,msg)

        --without newline
        ano = openssl.base64(msg,true,true)
        assert(#ano>#msg)
        assert(not string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true,true),ano)
        raw = openssl.base64(ano,false,true)
        assertEquals(raw,msg)

        --with newline
        ano = openssl.base64(msg,true,false)
        assert(#ano>#msg)
        assert(string.find(ano,'\n'))
        assertEquals(openssl.base64(msg,true,false),ano)
        raw = openssl.base64(ano,false,false)
        assertEquals(raw,msg)
    end

    function testAll()
        local f = io.open('openssl.cnf','r')
        if not f then f = io.open('test/openssl.cnf','r') end
        if f then
            local data = f:read('*a')
            f:close()

            local conf = assert(openssl.lhash_read(data))
            local t = conf:parse(false)
            assertIsTable(t)
            --print_r(t)
            t = conf:parse()
            assertIsTable(t)

            t = conf:parse(true)
            assertIsTable(t)

            assert(conf:get_string('ca','default_ca'))
            assert(conf:get_string('CA_default','default_days'))

            local c1 = openssl.lhash_load('openssl.cnf') or openssl.lhash_load('test/openssl.cnf')
            t = c1:parse()
            assertIsTable(t)

        end
    end
