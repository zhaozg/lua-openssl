---
-- Provide pkcs7 function in lua.
--
-- @module pkcs7
-- @usage
--  pkcs7 = require('openssl').pkcs7
--

do  -- define module function

--- read pkcs7
-- read string or bio object, which include pkcs7 content
-- @tparam bio|string input
-- @tparam[opt='auto'] format allow 'auto','der','pem','smime'
--  auto will only try 'der' or 'pem'
-- @tparam string password for pkcs12
-- @treturn pkcs7 object or nil
-- @treturn string content exist only smime format
function read() end

--- sign message with signcert and signpkey to create pkcs7 object
-- @tparam string|bio msg
-- @tparam x509 sigcert
-- @tparam evp_pkey signkey
-- @tparam[opt] stack_of_x509 cacerts
-- @tparam[opt=0] number flags
-- @treturn pkcs7 object
function sign() end

--- verify pkcs7 object, and return msg content, follow by singers
-- @tparam pkcs7 in
-- @tparam[opt] stack_of_x509 signercerts
-- @tparam[opt] x509_store cacerts
-- @tparam[opt] string|bio msg
-- @tparam[opt=0] number flags
-- @treturn[1] string content
-- @treturn[1] boolean result
function verify() end

--- encrypt message with recipcerts certificates return encrypted pkcs7 object
-- @tparam string|bio msg
-- @tparam stack_of_x509 recipcerts
-- @tparam[opt='rc4'] string|evp_cipher cipher
-- @tparam[opt] number flags
function encrypt() end

--- decrypt encrypted pkcs7 message
-- @tparam pkcs7 input
-- @tparam x509 recipcert
-- @tparam evp_pkey recipkey
-- @treturn string decrypt message
function decrypt() end

end


do  -- define class

--- openssl.pkcs7 object
-- @type pkcs7
--

do  -- define pkcs7

--- export pkcs7 as string
-- @tparam[opt=true] boolean pem default export as pem format, false export as der string
-- @treturn string
function export() end

--- export pkcs7 as a string
-- @treturn table  a table has pkcs7 infomation, include type,and other things relate to types
function parse() end

--- verify pkcs7 object, and return msg content, follow by singers
-- @tparam[opt] stack_of_x509 signercerts
-- @tparam[opt] x509_store cacerts
-- @tparam[opt] string|bio msg
-- @tparam[opt=0] number flags
-- @treturn string content
-- @treturn stack_of_x509 signers
function verify() end

--- decrypt encrypted pkcs7 message
-- @tparam x509 recipcert
-- @tparam evp_pkey recipkey
-- @treturn string decrypt message
function decrypt() end

end

end
