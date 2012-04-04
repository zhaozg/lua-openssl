local openssl = require('openssl')

length = 64
print('伪随机数生成', string.rep('-',40))
print(openssl.random_bytes(length))

print('强随机数生成', string.rep('-',40))
print(openssl.random_bytes(length, true))


secret_key = "secret"
cipher = openssl.get_cipher("RC4")

num = 10
i = 1
while i <= num do
        i = i+1

        id = "something"

        encrypted = cipher:encrypt(id, secret_key);
end
