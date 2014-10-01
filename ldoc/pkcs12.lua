--- 
-- Provide pkcs12 function in lua.
--
-- @module pkcs12
-- @usage
--  pkcs12 = require('openssl').pkcs12
--

do  -- define module function

--- parse pkcs12 data as lua table
--
-- @tparam string|bio input pkcs12 content
-- @tparam string password for pkcs12
-- @treturn table result contain 'cert', 'pkey', 'extracerts' keys
function read() end

--- create and export pkcs12 data
-- @tparam x509 cert
-- @tparam evp_pkey pkey
-- @tparam string password
-- @tparam[opt] string friendlyname
-- @tparam[opt] table|stak_of_x509 extracerts
-- @treturn string data
function export() end

end

