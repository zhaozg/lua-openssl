local openssl = require'openssl'
local asn1,hex,base64 = openssl.asn1,openssl.hex,openssl.base64


local pem = "MHcCAQEEINUs3GRVhC8h1y84gcW89XB9cyjUifwO3ZEH/Redb7w8oAoGCCqBHM9VAYItoUQDQgAE"
.."9YFSq5ZO6I+YXsIpYFzCYTcgtotrg6UW5xX8+e8arpoU5SsojLjRG1PA028kbi139zZlH2Gh/JPNiMEzRClIVg=="

local s = base64(pem,false)
local d = {}
local first = true
function asn1parse(s,off,last, indent)
    off = off or 1
    last = last or #s
    indent = indent or 0
    local tab = '  '
    local tag,cls,start,stop,cons
    tag,cls,start,stop,cons = asn1.get_object(s,off,last)
    assert(tag,cls)

    if first then
    print(string.format('%sTAG=%s CLS=%s START=%s STOP=%s, %s',
        string.rep(tab,indent),
        asn1.tostring(tag,'tag'), asn1.tostring(cls,'class'),
        start, stop, cons and "CONS" or "PRIM"))
    end
    if cons then
        table.insert(d,asn1.put_object(tag,cls,stop-start+1,true))
        stop = asn1parse(s,start, stop, indent + 1)
    else
        if first then
        print(string.format('%sVAL:%s', string.rep(tab,indent+1), openssl.hex(string.sub(s,start,stop))))
        end
        table.insert(d,asn1.put_object(tag,cls,string.sub(s,start,stop)))
    end

    while stop<last do
        stop = asn1parse(s, stop+1, last, indent)
    end
    return stop
end


TestAsn1_2 = {}
function TestAsn1_2.testParse()
    d = {}
    asn1parse(s)
    local ss = table.concat(d,'')

    assertEquals(s,ss)
    first = false
end
