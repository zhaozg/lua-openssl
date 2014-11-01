------------
-- Provide bio module.
-- bio object mapping to BIO in openssl
-- openssl.bio is a help object, it is useful, but rarely use.
-- @module bio
-- @usage
--  bio = require'openssl'.bio

do --define module function

--- make string as bio object
-- same with bio.mem, implication by metatable '__call'
-- @tparam[opt=nil] string data
-- @treturn bio
function openssl.bio() end

--- make string as bio object
-- @tparam[opt=nil] string data, it will be memory buffer data
-- @treturn bio it can be input or output object
function mem() end

--- make tcp bio from socket fd
-- @tparam number fd
-- @tparam[opt='noclose'] flag support 'close' or 'noclose' when close or gc
-- @treturn bio
function socket() end

--- make dgram bio from socket fd
-- @tparam number fd
-- @tparam[opt='noclose'] flag support 'close' or 'noclose' when close or gc
-- @treturn bio
function dgram() end

--- make socket or file bio with fd
-- @tparam number fd
-- @tparam[opt='noclose'] flag support 'close' or 'noclose' when close or gc
-- @treturn bio
function fd() end

--- make file object with file name or path
-- @tparam string file
-- @tparam[opt='r'] string mode
-- @treturn bio
function file() end

--- make tcp client socket
-- @tparam string host_addr addrees like 'host:port'
-- @tparam[opt=true] boolean connect default connect immediately
-- @treturn bio
function connect() end

--- make tcp listen socket 
-- @tparam string host_port address like 'host:port'
-- @treturn bio 
function accept() end

--- Create base64 or buffer bio, which can append to an io BIO object
-- @tparam string mode support 'base64' or 'buffer'
-- @treturn bio
function filter() end

--- Create digest bio, which can append to an io BIO object
-- @tparam string mode must be 'digest'
-- @tparam evp_md|string md_alg
-- @treturn bio
function filter() end

--- Create ssl bio
-- @tparam string mode must be 'ssl'
-- @tparam ssl s
-- @tparam[opt='noclose'] flag support 'close' or 'noclose' when close or gc
-- @treturn bio
function filter() end

--- create cipher filter bio object
-- @tparam string mode must be 'cipher'
-- @tparam string key
-- @tparam string iv
-- @tparam[opt=true] boolean encrypt
-- @treturn bio
function filter() end

end  -- define module


do  -- define class

--- openssl.bio object
-- @type bio
--

do  -- define bio

--- setup ready and accept client connect
-- @tparam[opt=false] boolean setup true for setup accept bio, false or none will accept client connect
-- @treturn[1] boolean result only when setup is true
-- @treturn[2] bio accpeted bio object
function accept() end 

--- read data from bio object
-- @tparam number len
-- @treturn string string length may be less than param len
function read() end

--- get line from bio object
-- @tparam[opt=256] number max line len
-- @treturn string string length may be less than param len
function gets() end

--- write data to bio object
-- @tparam string data
-- @treturn number length success write
function write() end

--- put line to bio object
-- @tparam string data
-- @treturn number length success write
function puts() end

--- get mem data, only support mem bio object
-- @treturn string
function get_mem() end

--- push bio append to chain of bio, if want to free a chain use free_all()
-- @tparam bio append
-- @treturn bio 
function push() end

--- remove bio from chain
-- @tparam bio toremove
function pop() end

--- free a chain
function free_all() end

--- close bio
function close() end

--- get type of bio
-- @treturn string
function type() end

-- reset bio
-- @TODO string
function reset() end

end --define class
