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

--- base64 encode or decode
-- @tparam string|bio input
-- @tparam[opt=true] boolean encode true to encoed, false to decode
-- @treturn string
function base64() end

--- get method names
-- @tparam string type support 'cipher','digests','pkeys','comps'
-- @treturn table as array
function list() end

--- get last error infomation
-- @tparam[opt] number error, default use ERR_get_error() return value
-- @tparam[opt=false] boolean verbose error message print on stderr. 
-- @treturn number errcode
-- @treturn string errmsg
--  The string will have the following format:
-- error:[error code]:[library name]:[function name]:[reason string]
-- `error code` is an 8 digit hexadecimal number, 
-- `library name`, `function name` and `reason string` are ASCII text.
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
