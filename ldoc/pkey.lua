------------
-- Provide Public/Private key module.
-- @module pkey
-- @usage
--  pkey = require'openssl'.pkey

do --define module function

--- generate a new ec keypair
-- @tparam string alg, alg must be 'ec'
-- @tparam string|number curvename this can be integer as curvename NID
-- @tparam[opt] integer flags when alg is ec need this.
-- @treturn evp_pkey object with mapping to EVP_PKEY in openssl
function new() end

--- generate a new keypair
-- @tparam[opt='rsa'] string alg, accept 'rsa','dsa','dh'
-- @tparam[opt=1024|512] integer bits, rsa with 1024,dh with 512
-- @tparam[opt]  when alg is rsa give e value default is 0x10001
-- @treturn evp_pkey object with mapping to EVP_PKEY in openssl
function new() end

--- create a new keypair by factors of keypair or get public key only
-- @tparam table factors to create private/public key, key alg only accept accept 'rsa','dsa','dh','ec' and must exist</br>
--  when arg is rsa, table may with key n,e,d,p,q,dmp1,dmq1,iqmp, both are binary string or openssl.bn<br>
--  when arg is dsa, table may with key p,q,g,priv_key,pub_key, both are binary string or openssl.bn<br>
--  when arg is dh, table may with key p,g,priv_key,pub_key, both are binary string or openssl.bn<br>
--  when arg is ec, table may with D,X,Y,Z,both are binary string or openssl.bn<br>
-- @treturn evp_pkey object with mapping to EVP_PKEY in openssl
-- @usage
--  --create rsa public key
--    pubkey = new({alg='rsa',n=...,e=...}
--  --create new rsa
--    rsa = new({alg='rsa',n=...,q=...,e=...,...}
function new() end

--- get public key from private key object
-- @tparam evp_pkey priv_key
-- @treturn evp_pkey pub_key
-- @see evp_pkey
function get_public() end

--- read public/private key from data
-- @tparam string|openssl.bio input string data or bio object
-- @tparam[opt=false] boolean priv prikey set true when input is private key
-- @tparam[opt='auto'] format format or encoding of input, support 'auto','pem','der'
-- @tparam[opt] string passhprase when input is private key, or key types 'ec','rsa','dsa','dh'
-- @treturn evp_pkey public key
-- @see evp_pkey
function read() end

--- sign message with private key
-- @tparam evp_pkey key key used to sign message
-- @tparam string data data be signed
-- @tparam[opt='SHA1'] string|env_digest md_alg default use sha-1
-- @treturn string signed message
function sign() end

--- verify signed message with public key
-- @tparam evp_pkey key key used to verify message
-- @tparam string data data be signed
-- @tparam string signature signed result
-- @tparam[opt='SHA1'] string|env_digest md_alg default use sha-1
-- @tparam boolean true for pass verify
function verify() end

--- encrypt message with public key
-- encrypt length of message must not longer than key size, if shorter will do padding,currently supports 6 padding modes.
-- They are: pkcs1, sslv23, no, oaep, x931, pss.
-- @tparam evp_pkey key key used to encrypted message
-- @tparam string data data to be encrypted
-- @tparam string[opt='pkcs1'] string padding padding mode
-- @treturn string encrypted message
function encrypt() end

--- decrypt message with private key
-- pair with encrypt
-- @tparam evp_pkey key key used to decrypted message
-- @tparam string data data to be decrypted
-- @tparam string[opt='pkcs1'] string padding padding mode
-- @treturn[1] string result
-- @treturn[2] nil
function decrypt() end

--- seal  and encrypt  message with one public key
-- data be encrypt with secret key, secret key be encrypt with public key
-- encrypts data using pubkeys in table, so that only owners of the respective private keys and ekeys can decrypt and read the data.
-- @tparam table pubkeys public keys to encrypt secret key
-- @tparam string data data to be encrypted
-- @tparam[opt='RC4'] cipher|string alg
-- @treturn string data encrypted
-- @treturn table ekey secret key encrypted by public key
-- @treturn stringiv
function seal() end

--- seal and encrypt message with one public key
-- data be encrypt with secret key, secret key be encrypt with public key
-- @tparam evp_pkey pubkey public keys to encrypt secret key
-- @tparam string data data to be encrypted
-- @tparam[opt='RC4'] cipher|string alg
-- @treturn string data encrypted
-- @treturn string skey secret key encrypted by public key
-- @treturn string iv
function seal() end

--- open and ecrypted seal data with private key
-- @tparam evp_pkey pkey private key used to open encrypted secret key
-- @tparam string ekey encrypted secret key
-- @tparam string string iv
-- @tparam[opt='RC4'] evp_cipher|string md_alg
-- @treturn string data decrypted message or nil on failure
function open() end

end  -- define module


do  -- define class

--- openssl.evp_pkey object
-- @type evp_pkey
--

do  -- define evp_pkey

--- export evp_pkey as pem/der string
-- @tparam[opt=true] boolean pem default export as pem format, false export as der string
-- @tparam[opt=false] boolean raw_key true for export low layer key just rsa,dsa,ec, and public key only support RSA
-- @tparam[opt] string passphrase if given, export key will encrypt with des-cbc-ede,
--    only need when export private key
-- @treturn string
function export() end

--- get key details as table
-- @treturn table infos with key bits,pkey,type, pkey may be rsa,dh,dsa, show as table with factor hex encoded bignum
function parse() end

--- return key is private or public
-- @treturn boolean ture is private or public key
function is_private() end

--- compute dh key, check whether then supplied key is a private key
-- by checking then prime factors whether set
-- @tparam string remote_public_key
-- @treturn string
-- @todo: more check
function compute_key() end

--- sign message with private key
-- @tparam string data data be signed
-- @tparam[opt='SHA1'] string|env_digest md_alg default use sha-1
-- @treturn string signed message
function sign() end

--- verify signed message with public key
-- @tparam string data data be signed
-- @tparam string signature signed result
-- @tparam[opt='SHA1'] string|env_digest md_alg default use sha-1
-- @treturn boolean true for pass verify
function verify() end

--- encrypt message with public key
-- encrypt length of message must not longer than key size, if shorter will do padding,currently supports 6 padding modes.
-- They are: pkcs1, sslv23, no, oaep, x931, pss.
-- @tparam string data data to be encrypted
-- @tparam string[opt='pkcs1'] string padding padding mode
-- @treturn string encrypted message
function encrypt() end

--- decrypt message with private key
-- pair with encrypt
-- @tparam string data data to be decrypted
-- @tparam string[opt='pkcs1'] string padding padding mode
-- @treturn[1] string result
-- @treturn[2] nil
function decrypt() end

--- seal and encrypt message with one public key
-- data be encrypt with secret key, secret key be encrypt with public key
-- @tparam string data data to be encrypted
-- @tparam[opt='RC4'] cipher|string alg
-- @treturn string data encrypted
-- @treturn string skey secret key encrypted by public key
-- @treturn string iv
function seal() end

--- open and ecrypted seal data with private key
-- @tparam string ekey encrypted secret key
-- @tparam string string iv
-- @tparam[opt='RC4'] evp_cipher|string md_alg
-- @treturn string data decrypted message or nil on failure
function open() end

end --define class
