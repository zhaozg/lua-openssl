--- 
-- Provide x509_name as lua object.
-- Sometime when you make CSR,TS or X509, you maybe need to use this.
--
-- @module x509.name
-- @usage
--  name = require('openssl').x509.name
--


do  -- define module function

--- Create x509_name object
--
-- @tparam table array include name node
-- @tparam[opt] boolean utf8 encode will be use default
-- @treturn x509_name mapping to X509_EXTENSION in openssl
-- @usage
--  name = require'openssl'.x509.name
--  subject = name.new{
--    {C='CN'},
--    {O='kkhub.com'},
--    {CN='zhaozg'}
--  }
--

function new() end

--- Create x509_name from der string
--
-- @tparam string content DER encoded string
-- @treturn x509_name mapping to X509_NAME in openssl
--
function d2i() end

end

do -- define module table
--
--- x509_name infomation table
-- other field is number type, and value table is alter name.(I not understand clearly)
-- @table x509_extension_info_table
-- @tfield asn1_object|object object of x509_name
-- @tfield boolean|critical true for critical value
-- @tfield string|value as octet string


end

do  -- define class

--- openssl.x509_name object
-- @type x509_name
--
do  -- define x509_name

--- as oneline of x509_name.
--
-- @treturn string line, name as oneline text 
function oneline() end

--- get hash code of x509_name
--
-- @treturn integer hash hash code of x509_name
function hash() end

--- get digest of x509_name
--
-- @tparam string|nid|openssl.evp_md md method of digest
-- @treturn string digest digest value by given alg of x509_name
function digest() end

--- print x509_name to bio object
--
-- @tparam openssl.bio out output bio object
-- @tparam[opt] integer indent for output
-- @tparam[opt] integer flags for output
-- @treturn boolean result, follow by error message
function print() end

--- return x509_name as table
--
-- @tparam boolean utf8 true for utf8 encoded string, default
-- @treturn table names
-- @see new
function info() end

--- compare two x509_name
--
-- @tparam x509_name another to compare with 
-- @treturn boolean result true for equal or false
-- @usage
--
--  name1 = name.new({...})
--  name2 = name1:dup()
--  assert(name1:cmp(name2)==(name1==name2))
--
function cmp() end

--- get DER encoded string of x509_name.
--
-- @treturn string der
function i2d() end

--- get count in x509_name.
--
-- @treturn integer count of x509_name
function entry_count() end

--- get text by given asn1_object or nid
--
-- @tparam string|integer|asn1_object identid for asn1_object
-- @tparam[opt=-1] number lastpos retrieve the next index after lastpos
-- @treturn string
-- @treturn lastpos
function get_text() end

--- get x509 name entry by index
-- @tparam integer index start from 0, and less than xn:entry_count()
-- @tparam[opt=true] boolean utf8
-- @treturn x509 name entry table
function get_entry() end

--- add name entry 
--
-- @tparam string|integer|asn1_object identid for asn1_object
-- @tparam string data to add
-- @tparam[opt] boolean utf8 true for use utf8 default
-- @treturn boolean result true for success or follow by error message
function add_entry() end

--- get index by give asn1_object or nid
--
-- @tparam integer location which name entry to delete
-- @treturn[1] asn1_object object that delete name entry
-- @treturn[1] asn1_string value that delete name entry
-- @treturn[2] nil delete nothing 
function delete_entry() end


end

end

