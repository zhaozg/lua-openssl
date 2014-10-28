--- 
-- Provide x509_extension as lua object.
-- Sometime when you make CSR,TS or X509, you maybe need to use this.
--
-- @module x509.extension
-- @usage
--  extension = require('openssl').x509.extension
--

do  -- define module function

--- Create x509_extension object
--
-- @tparam table extension with object, value and critical
-- @treturn x509_extension mapping to X509_EXTENSION in openssl
--
-- @see x509_extension_param_table
function new_extension() end

--- read der encoded x509_extension
-- @tparam string data der encoded
-- @treturn x509_extension mappling to X509_EXTENSION in openssl
function read_extension() end

--- Create stack_of_x509_extension object, which mapping to STACK_OF(X509_EXTENSION)
--
-- @tparam table node_array, each node is a x509_extension node
-- @treturn[1] sk_x509_extension mapping to STACK_OF(X509_EXTENSION) in openssl
--
-- @see new_extension, sk
function new_sk_extension() end

--- get all x509 certificate supported extensions
-- @treturn table contain all support extension nid
-- @treturn table contain all support extension info as table node {lname=..., sname=..., nid=...}
function support() end

--- ask x509_extension object support or not 
-- @tparam x509_extension extension 
-- @tparam boolean true for supported, false or not 
function support() end

--- ask nid or name support or not 
-- @tparam number|string nid_or_name for extension 
-- @tparam boolean true for supported, false or not 
function support() end

end

do -- define module table

--- x509_extension contrust param table.
--
-- @table x509_extension_param_table
-- @tfield boolean critical true set critical
-- @tfield asn1_string value of x509_extension
-- @tfield string|asn1_object object, object of extension
--
-- @usage
-- xattr = x509.attr.new_extension {
--   object = asn1_object,
--   critical = false,
--   value = string or asn1_string value
-- }
function new_extension() end

--- x509_extension infomation table
-- other field is number type, and value table is alter name.(I not understand clearly)
-- @table x509_extension_info_table
-- @tfield asn1_object|object object of x509_extension
-- @tfield boolean|critical true for critical value
-- @tfield string|value as octet string


end

do  -- define class

--- openssl.x509_extension object
-- @type x509_extension
--
do  -- defint x509_extension

--- get infomation table of x509_extension.
--
-- @tparam[opt] boolean|utf8 true for utf8 default 
-- @treturn[1] table info,  x509_extension infomation as table
-- @see x509_extension_info_table
function info() end

--- clone then x509_extension
--
-- @treturn x509_extension attr clone of x509_extension
function dup() end

--- get critical of x509_extension.
--
-- @treturn boolean true if extension set critical or false
function critical() end

--- set critical of x509_extension.
--
-- @tparam boolean critical set to self
-- @treturn[1] boolean set critical success return true
-- @treturn[2] nil nil, fail return nothing
-- @treturn[2] string errmsg reason of fail
function critical() end

--- get asn1_object of x509_extension.
--
-- @treturn[1] asn1_object object of x509_extension
function object() end

--- set asn1_object for x509_extension.
--
-- @tparam asn1_object obj
-- @treturn[1] boolean true for success
-- @treturn[2] nil nil when occure error
-- @treturn[2] string errmsg error message
function object() end

--- get data of x509_extension
--
-- @treturn asn1_string
function data() end

--- set type of x509_extension
--
-- @tparam asn1_string data set to self
-- @treturn[1] boolean true for success
-- @treturn[2] nil nil when occure error
-- @treturn[2] string errmsg error message
function data() end

--- export x509_extenion to der encoded string
-- @treturn string 
function export() end

end

end

