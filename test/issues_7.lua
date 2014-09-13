local openssl = require('openssl')

secret_key = "secret"
cipher = openssl.cipher.get("RC4")

num = 10000000
i = 1
while i <= num do
        i = i+1
        id = "something"
        encrypted = cipher:encrypt(id, secret_key);
end
print('DONE')
