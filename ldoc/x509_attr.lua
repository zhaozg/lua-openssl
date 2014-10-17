--- 
-- Provide x509_attribute as lua object.
-- Sometime when you make CSR,TS or X509, you maybe need to use this.
--
-- @module x509.attr
-- @usage
--  attr = require('openssl').x509.attr
--

do  -- define module function

--- Create x509_attribute object
--
-- @tparam table attribute with object, type and value
-- @treturn[1] x509_attribute mapping to X509_ATTRIBUTE in openssl
--
-- @see x509_attribute_param_table
function new_attribute() end

--- Create stack_of_x509_attribute object, which mapping to STACK_OF(X509_ATTRIBUTE)
--
-- @tparam table node_array, each node is a x509_attribute node
-- @treturn sk_x509_attribute mapping to STACK_OF(X509_ATTRIBUTE) in openssl
--
-- @see new_attribute, sk
function new_sk_attribute() end

end

do -- define module table

--- x509_attribute contrust param table.
--
-- @table x509_attribute_param_table
-- @tfield string|integer|asn1_object object, identify a asn1_object
-- @tfield string|integer type, same with type in asn1.new_string
-- @tfield string|asn1_object value, value of attribute
--
-- @usage
-- xattr = x509.attr.new_attribute {
--   object = asn1_object,
--   type = Nid_or_String,
--   value = string or asn1_string value
-- }
-- 
function new_attribute() end

--- x509_attribute infomation table
--
-- @table x509_attribute_info_table
-- @tfield asn1_object|object object of asn1_object
-- @tfield boolean single  true for single value
-- @tfield table value  if single, value is asn1_type or array have asn1_type node table  

--- asn1_type object as table
--
-- @table asn1_type_table
-- @tfield string value, value data
-- @tfield string type, type of value
-- @tfield string format, value is 'der', only exist when type is not in 'bit','bmp','octet'
-- 
end

do  -- define class

--- openssl.x509_attribute object
-- @type x509_attribute
--
do  -- defint x509_attribute

--- get infomation table of x509_attribute.
--
-- @treturn[1] table info,  x509_attribute infomation as table
-- @see x509_attribute_info_table
function info() end

--- clone then asn1_attribute
--
-- @treturn x509_attribute attr clone of x509_attribute
function dup() end

--- get type of x509_attribute.
--
-- @tparam[opt] integer location which location to get type, default is 0
-- @treturn[1] table asn1_type, asn1_type as table info
-- @treturn[2] nil nil, fail return nothing
--
-- @see asn1_type_table
function type() end

--- get asn1_object of x509_attribute.
--
-- @treturn[1] asn1_object object of x509_attribute
function object() end

--- set asn1_object for x509_attribute.
--
-- @tparam asn1_object obj
-- @treturn[1] boolean true for success
-- @treturn[2] nil nil when occure error
-- @treturn[2] string errmsg error message
function object() end

--- get type of x509_attribute
--
-- @tparam integer idx location want to get type
-- @tparam string attrtype attribute type
-- @treturn asn1_string
function data() end

--- set type of x509_attribute
--
-- @tparam string attrtype attribute type
-- @tparam string data set to asn1_attr
-- @string data to set
function data() end

end

end

