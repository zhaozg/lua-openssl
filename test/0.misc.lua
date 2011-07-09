local openssl = require('openssl')

length = 64
print('伪随机数生成', string.rep('-',40))
print(openssl.random_bytes(length))

print('强随机数生成', string.rep('-',40))
print(openssl.random_bytes(length, true))

