local openssl = require('openssl')

TestLhtml = {}

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
            local t = conf:parse()
            assertIsTable(t)

            local t = conf:parse(true)
            assertIsTable(t)
            
            assert(conf:get_string('ca','default_ca'))
            assert(conf:get_string('CA_default','default_days'))
            
            local c1 = openssl.lhash_load('openssl.cnf') or openssl.lhash_load('test/openssl.cnf')
            t = c1:parse()
            assertIsTable(t)
        end
    end
    
