io.read()

local openssl = require('openssl')
asn1 = openssl.asn1

certasstring = [[-----BEGIN CERTIFICATE-----
MIIDATCCArCgAwIBAgITEgAFDVkfna1KLEIuKgAAAAUNWTAIBgYqhQMCAgMwfzEj
MCEGCSqGSIb3DQEJARYUc3VwcG9ydEBjcnlwdG9wcm8ucnUxCzAJBgNVBAYTAlJV
MQ8wDQYDVQQHEwZNb3Njb3cxFzAVBgNVBAoTDkNSWVBUTy1QUk8gTExDMSEwHwYD
VQQDExhDUllQVE8tUFJPIFRlc3QgQ2VudGVyIDIwHhcNMTUwNjEzMTczNjQ4WhcN
MTUwOTEzMTc0NjQ4WjATMREwDwYDVQQDEwhuZ2F0ZS5ydTBjMBwGBiqFAwICEzAS
BgcqhQMCAiQABgcqhQMCAh4BA0MABEBn4s6r6zCgimGfiHg4o0FpNaGv1jGzmqSD
chsnAiqcV8fQ4Y6p/o0x8CZEXAC+hzdf5w2f1VxzbJaGCTQslmNYo4IBbTCCAWkw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMB0GA1UdDgQWBBT4x4Lz
iE6QcS3Qnmz03HNroSojbzAfBgNVHSMEGDAWgBQVMXywjRreZtcVnElSlxckuQF6
gzBZBgNVHR8EUjBQME6gTKBKhkhodHRwOi8vdGVzdGNhLmNyeXB0b3Byby5ydS9D
ZXJ0RW5yb2xsL0NSWVBUTy1QUk8lMjBUZXN0JTIwQ2VudGVyJTIwMi5jcmwwgakG
CCsGAQUFBwEBBIGcMIGZMGEGCCsGAQUFBzAChlVodHRwOi8vdGVzdGNhLmNyeXB0
b3Byby5ydS9DZXJ0RW5yb2xsL3Rlc3QtY2EtMjAxNF9DUllQVE8tUFJPJTIwVGVz
dCUyMENlbnRlciUyMDIuY3J0MDQGCCsGAQUFBzABhihodHRwOi8vdGVzdGNhLmNy
eXB0b3Byby5ydS9vY3NwL29jc3Auc3JmMAgGBiqFAwICAwNBAA+nkIdgmqgVr/2J
FlwzT6GFy4Cv0skv+KuUyfrd7kX4jcY/oGwxpxBv5WfNYDnHrVK90bNsXTqlon2M
veFd3yM=
-----END CERTIFICATE-----
]]

function dump_x509ext(ext)

    i = 3
    t = ext.info(ext)

    for k,v in pairs(t) do
        if(type(v)=='table') then
            print( string.rep('\t',i),k..'={')
            dump_x509ext(v,i+1)
            print( string.rep('\t',i),k..'=}')
        else
            if(type(v)=='userdata') then
                local _, stype = v:type()
                print( string.rep('\t',i),k..'='..openssl.hex(tostring(v)))
                print( string.rep('\t',i),string.format('TYPE:%s',stype))
            else
                print( string.rep('\t',i),k..'='..tostring(v))
            end
        end
    end
end

function dump(t,i)
    for k,v in pairs(t) do
        if(type(v)=='table') then
            print( string.rep('\t',i),k..'={')
            dump(v,i+1)
            print( string.rep('\t',i),k..'=}')
        else
            print( string.rep('\t',i),k..'='..tostring(v))
            if k == "extensions" then
                n = #v
                for q=1, n do
                    x = v:get(q)
                    print (x)
                    dump_x509ext(x)
                    --openssl.x509.extension q =
                    --v.object()
                end
            end
        end
    end
end

function test_x509()
    local x = openssl.x509.read(certasstring)
    t = x:parse()
    dump(t,0)

end

test_x509()
