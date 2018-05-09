--- 
-- Provide sm2 function in lua.
--
-- @module sm2
-- @usage
--  sm2 = require('openssl').sm2
--
-- OpenSSL support SM2/SM3/SM4 from version version 1.1.1

do  -- define module function

--- compute SM2 digest with userid
--
-- @tparam ec_key SM2 key or SM2 public key
-- @tparam[opt='1234567812345678'] string userId default is `1234567812345678`
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity
-- @treturn string result binary string
--
function compute_userid_digest() end

--- do SM2 sign, input message will be do digest
--
-- @tparam ec_key sm2key
-- @tparam string msg data to be sign
-- @tparam[opt='1234567812345678'] string userId default is `1234567812345678`
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default use sm3
-- @treturn string result binary signature string
--
function do_sign() end

--- do SM2 verify
--
-- @tparam ec_key sm2key
-- @tparam string msg data to be signed
-- @tparam string signature
-- @tparam[opt='1234567812345678'] string userId default is `1234567812345678`
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default use sm3
-- @treturn boolean true for verified, false for invalid signature, or nil floow error message
--
function do_verify() end

--- do SM2 sign, input is SM3 digest result
--
-- @tparam ec_key sm2key
-- @tparam string digest result of SM3 digest to be signed
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn string signature
--
function sign() end

--- do SM2 verify, input msg is sm3 digest result
--
-- @tparam ec_key sm2key
-- @tparam string digest result of SM3 digest to be signed
-- @tparam string signature
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn boolean true for verified, false for invalid signature, or nil floow error message
--
function verify() end

--- get SM2 encrypt result size
--
-- @tparam ec_key sm2key
-- @tparam number size of data to be encrypted
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn number size or nil followed by error message
--
function ciphersize()

--- get SM2 decrypt result size
--
-- @tparam ec_key sm2key
-- @tparam number size of data to be decrypted
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn number size or nil followed by error message
--
function plainsize()

--- do SM2 encrypt
--
-- @tparam ec_key sm2key
-- @tparam string data_to_encrypt
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn string cipherdata or nil followed by error message
-- 
function encrypt()

--- do SM2 decrypt
--
-- @tparam ec_key sm2key
-- @tparam string data_to_decrypt
-- @tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
-- @treturn string plaindata or nil followed by error message
-- 
function decrypt()

end
