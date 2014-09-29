--- 
-- Provide hmac function in lua.
--
-- @module hmac
-- @usage
--  hamc = require('openssl').hmac
--

do  -- define module function

--- compute hmac one step, in module openssl
--
-- @tparam evp_digest|string|nid digest digest alg identity
-- @tparam string key
-- @tparam[opt] engine engine, nothing with default engine
-- @treturn string result binary string
--
function openssl.hmac() end

--- compute hmac one step, in module openssl.hamc
--
-- @tparam evp_digest|string|nid digest digest alg identity
-- @tparam string key
-- @tparam boolean raw, return binary or hex encoded string, true false binary or hex
-- @tparam[opt] engine engine, nothing with default engine
-- @treturn string result binary or hex string
function hmac() end

--- alias for hmac
--
-- @tparam evp_digest|string|nid digest digest alg identity
-- @tparam string key
-- @tparam boolean raw, return binary or hex encoded string, true false binary or hex
-- @tparam[opt] engine engine, nothing with default engine
-- @treturn string result binary or hex string
function digest() end

--- get hamc_ctx object
--
-- @tparam string|integer|asn1_object alg name, nid or object identity
-- @tparam string key secret key
-- @tparam[opt] engine engine, nothing with default engine
-- @treturn hamc_ctx hmac object mapping HMAC_CTX in openssl
--
-- @see hmac_ctx
function new() end
 
end

do  -- define class

--- openssl.hmac_ctx object
-- @type hmac_ctx
--

do  -- define hmac_ctx

--- feed data to do digest
--
-- @tparam string msg data
function update() end

--- get result of hmac
--
-- @tparam[opt] string last last part of data
-- @tparam[opt] boolean raw binary or hex encoded result, default true for binary result
-- @treturn string val hash result 
function final() end


--- reset hmac_ctx to reuse
--
function reset() end

end

end
