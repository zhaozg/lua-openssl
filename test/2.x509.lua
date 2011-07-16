local openssl = require('openssl')
require 'util'

local raw_data = [[
-----BEGIN CERTIFICATE-----
MIIBoTCCAQqgAwIBAgIMA/016215epG+OPNOMA0GCSqGSIb3DQEBBQUAMBExDzAN
BgNVBAMTBnpoYW96ZzAeFw0xMTA3MDYwNTI3MDlaFw0xMjA3MDUwNTI3MDlaMBEx
DzANBgNVBAMTBnpoYW96ZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAy48u
FWSdZmSET1gdJqczdL6jxxssCCq/lEthPj9SRr1iZl/lkZ95VhwA/llJHVLpOA4m
DjIJd8jFW+g/Bo2XyqHa2unSHtYW7xT6iUMAQOGlvkF81NtXzmEffFNAj4Ud/T2r
pKdFY/5YZI+CFCi6m1hT/xbwR84bASL/dBXoOOUCAwEAATANBgkqhkiG9w0BAQUF
AAOBgQA8LAd0UXbzPN6v1lIM4KcR88mH/SKeRvNXJqv8JEF4qosXr6wN0XT4bIqN
fv/5OBot6ECcEm8aeGR08gBmjtsQAYtGc07ksvzYtytKsGWdcTLAf/+K2bKg6VGy
pM4KW8DPKCZ16zylyzRbVKbQJ/sjcCPqd55M3THg2gRnxywalw==
-----END CERTIFICATE----- 
]]

function test_x509()
        local x = openssl.x509_read(raw_data)
        print(x)
        t = x:parse()
        dump(t,0)
end

test_x509()
