--- 
-- Provide openssl base function in lua.
--
-- @module openssl
-- @usage
--  openssl = require('openssl')
--

do  -- define module function

--- hex encode or decode string
-- @tparam string str
-- @tparam[opt=true] boolean encode true to encoed, false to decode
-- @treturn string
function hex() end

--- get method names
-- @tparam string type support 'cipher','digests','pkeys','comps'
-- @treturn table as array
function list() end

--- get last error infomation
-- @tparam[opt=false] boolean verbose 
-- @treturn number errcode
-- @treturn string errmsg
-- @treturn string verbose message
function error() end

--- get randome bytes
-- @tparam number length
-- @tparam[opt=false] boolean strong true to generate strong randome bytes
-- @treturn string 
function randome() end

--- add new object
-- @tparam string oid
-- @tparam string name 
-- @tparam[opt=nil] string alias
function object() end

--- get object according object nid or name
-- @tparam number|string nid_or_name
-- @treturn asn1_object
function object() end

--- get openssl engine object
-- @tparam string engine_id
-- @treturn engine 
function engine() end

end
