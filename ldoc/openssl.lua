---
-- Provide openssl base function in lua.
--
-- @module openssl
-- @usage
--  openssl = require('openssl')
--

do  -- define module function

-- Most lua-openssl function or methods return nil or false when error or
-- failed, followed by string type error _reason_ and number type error _code_,
-- _code_ can pass to openssl.error() to get more error information.

--- hex encode or decode string
-- @tparam string str
-- @tparam[opt=true] boolean encode true to encoed, false to decode
-- @treturn string
function hex() end

--- base64 encode or decode
-- @tparam string|bio input
-- @tparam[opt=true] boolean encode true to encoed, false to decode
-- @tparam[opt=true] boolean NO_NL true with newline, false without newline
-- @treturn string
function base64() end

--- get method names
-- @tparam string type support 'cipher','digests','pkeys','comps'
-- @treturn table as array
function list() end

--- get last or given error infomation
-- @tparam[opt] number error, default use ERR_get_error() return value
-- @tparam[opt=false] boolean clear the current thread's error queue.
-- @treturn number errcode
-- @treturn string reason
-- @treturn string library name
-- @treturn string function name
-- @treturn boolean is this is fatal error
function error() end

--- get random bytes
-- @tparam number length
-- @tparam[opt=false] boolean strong true to generate strong randome bytes
-- @treturn string
function random() end

--- get random generator state
-- @tparam boolean result true for sucess
function rand_status() end

--- load rand seed from file
-- @tparam[opt=nil] string file path to laod seed, default opensl management
-- @treturn boolean result
function rand_load() end

--- save rand seed to file
-- @tparam[opt=nil] string file path to save seed, default openssl management
-- @treturn bool result
function rand_write() end

--- cleanup random genrator
function rand_cleanup() end

--- get openssl engine object
-- @tparam string engine_id
-- @treturn engine
function engine() end

-- get lua-openssl version
-- @tparam[opt] boolean format result will be number when set true, or string
-- @treturn lua-openssl version, lua version, openssl version
function version() end

end
