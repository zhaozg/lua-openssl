
local openssl = require('openssl')
require 'util'

function test_read_parse()
        local dat = readfile('d:\\tmp\\RCA.crl')
        print(#dat)
        local crl = assert(openssl.crl_read(dat))
        print(crl)
        local t = crl:parse()
        dump(t,0)
end


test_read_parse()

