local openssl = require'openssl'
require 'util'


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