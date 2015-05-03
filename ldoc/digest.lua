--- 
-- Provide digest function in lua.
--
-- @module digest
-- @usage
--  digest = require('openssl').digest
--

do  -- define module function

--- list all support digest algs
--
-- @tparam[opt] boolean alias include alias names for digest alg, default true
-- @treturn[table] all methods
--
function list() end

--- get evp_digest object
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @treturn evp_digest digest object mapping EVP_MD in openssl
--
-- @see evp_digest
function get() end

--- get evp_digest_ctx object
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @treturn evp_digest_ctx digest object mapping EVP_MD_CTX in openssl
--
-- @see evp_digest_ctx
function new() end

--- quick method to generate digest result
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string msg to compute digest 
-- @tparam[opt] boolean raw binary result return if set true, or hex encoded string default
-- @treturn string digest result value
function digest() end
 
--- create digest object for sign
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam[opt=nil] engine object
-- @treturn evp_digest_ctx
function signInit() end

--- create digest object for verify
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam[opt=nil] engine object
-- @treturn evp_digest_ctx
function verifyInit() end

end

do  -- define class

--- openssl.evp_digest object
-- @type evp_digest
--
do  -- define evp_digest

--- create new evp_digest_ctx
--
-- @tparam[opt] engine, nothing will use default engine
-- @treturn evp_digest_ctx ctx
-- @see evp_digest_ctx
function new() end

--- get infomation of evp_digest object
--
-- @treturn table info keys include nid,name size,block_size,pkey_type,flags
function info() end

--- compute msg digest result
--
-- @tparam string msg data to digest
-- @tparam[opt] engine, eng
-- @treturn string result a binary hash value for msg
function digest() end

--- create digest object for sign
--
-- @tparam[opt=nil] engine object
-- @treturn evp_digest_ctx
function signInit() end

--- create digest object for verify
--
-- @tparam[opt=nil] engine object
-- @treturn evp_digest_ctx
function verifyInit() end

end

do  -- define evp_digest_ctx

--- openssl.evp_digest_ctx object
-- @type evp_digest_ctx
--
 
--- get infomation of evp_digest_ctx object
--
-- @treturn table info keys include size,block_size,digest
function info() end

--- feed data to do digest
--
-- @tparam string msg data
-- @treturn boolean result true for success
function update() end

--- get result of digest
--
-- @tparam[opt] string last last part of data
-- @tparam[opt] boolean raw binary or hex encoded result, default true for binary result
-- @treturn string val hash result 
function final() end


--- reset evp_diget_ctx to reuse
--
function reset() end

--- feed data for sign to get signature
--
-- @tparam string data to be signed
-- @treturn boolean result
function signUpdate() end

--- feed data for verify with signature
--
-- @tparam string data to be verified
-- @treturn boolean result
function verifyUpdate() end

--- get result of sign
--
-- @tparam evp_pkey private key to do sign
-- @treturn string singed result
function signFinal() end

--- get verify result
--
-- @tparam string signature
-- @treturn boolean result, true for verify pass
function verifyFinal() end

end

end



