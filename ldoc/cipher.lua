--- 
-- Provide cipher function in lua.
--
-- @module cipher
-- @usage
--  cipher = require('openssl').cipher
--

do  -- define module function

--- list all support cipher algs
--
-- @tparam[opt] boolean alias include alias names for cipher alg, default true
-- @treturn[table] all cipher methods
--
function list() end


--- get evp_cipher object
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @treturn evp_cipher cipher object mapping EVP_MD in openssl
--
-- @see evp_cipher
function get() end

--- get evp_cipher_ctx object for encrypt or decrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx cipher object mapping EVP_CIPHER_CTX in openssl
--
-- @see evp_cipher_ctx
function new() end

--- get evp_cipher_ctx object for encrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx cipher object mapping EVP_CIPHER_CTX in openssl
--
-- @see evp_cipher_ctx
function encrypt_new() end

--- get evp_cipher_ctx object for decrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx cipher object mapping EVP_CIPHER_CTX in openssl
--
-- @see evp_cipher_ctx
function decrypt_new() end

--- quick encrypt or decrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string input data to encrypt or decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result
function cipher() end

--- quick encrypt or decrypt,alias to cipher
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string input data to encrypt or decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result
function openssl.cipher() end

--- quick encrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string input data to encrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result encrypt data
function encrypt() end

--- quick decrypt
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string input data to decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result decrypt data
function decrypt() end
 
end

do  -- define class

--- openssl.evp_cipher object
-- @type evp_cipher
--
do  -- define evp_cipher


--- get infomation of evp_cipher object
--
-- @treturn table info keys include name,block_size,key_length,iv_length,flags,mode
function info() end

--- derive key
--
-- @tparam string data derive data
-- @tparam string[opt] string salt salt will get strong security
-- @tparam ev_digest|string md digest method used to diver key, default with 'sha1'
-- @treturn string key
-- @treturn string iv
function BytesToKey() end

--- do encrypt or decrypt
--
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string input data to encrypt or decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result
function cipher() end

--- do encrypt
--
-- @tparam string input data to encrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result
function encrypt() end

--- do decrypt
--
-- @tparam string input data to decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn string result
function decrypt() end

--- get evp_cipher_ctx to encrypt or decrypt 
--
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx evp_cipher_ctx object
--
-- @see evp_cipher_ctx
function new() end

--- get evp_cipher_ctx to encrypt 
--
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx evp_cipher_ctx object
--
-- @see evp_cipher_ctx
function encrypt_new() end

--- get evp_cipher_ctx to decrypt 
--
-- @tparam boolean encrypt true for encrypt,false for decrypt
-- @tparam string key secret key
-- @tparam[opt] string iv
-- @tparam[opt] boolean pad true for padding default
-- @tparam[opt] engine engine custom crypto engine
-- @treturn evp_cipher_ctx evp_cipher_ctx object
--
-- @see evp_cipher_ctx
function decrypt_new() end

end

do  -- define evp_cipher_ctx

--- openssl.evp_cipher_ctx object
-- @type evp_cipher_ctx
--
 
--- get infomation of evp_cipher_ctx object
--
-- @treturn table info keys include block_size,key_length,iv_length,flags,mode,nid,type, evp_cipher
function info() end
  
--- feed data to do cipher
--
-- @tparam string msg data
-- @treturn string result parture result
function update() end

--- get result of cipher
--
-- @treturn string result last result
function final() end

end

end



