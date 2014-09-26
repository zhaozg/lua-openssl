--- 
-- Provide asn1_object, asn1_string, asn1_object as lua object.
-- Sometime when you want to custome x509, you maybe need to use this.
--
-- @module asn1
-- @usage
--  asn1 = require('openssl').asn1
--

do  -- define module function

--- Create asn1_object object
--
-- @tparam string name_or_oid  short name,long name or oid string
-- @tparam[opt] boolean no_name  true for only oid string, default is false
-- @treturn[1] asn1_object mapping to ASN1_OBJECT in openssl
--
-- @see asn1_object
function new_object() end

--- Create asn1_object object
--
-- @tparam integer nid ident to asn1_object
-- @treturn[1] asn1_object mapping to ASN1_OBJECT in openssl
--
-- @see asn1_object
function new_object() end

--- Create asn1_object object
--
-- @tparam table options have sn, ln, oid keys to create asn1_object
-- @treturn[1] asn1_object mapping to ASN1_OBJECT in openssl
--
-- @see asn1_object
function new_object() end

--- Create asn1_string object
--
-- <br/><p> asn1_string object support types:   "integer", "enumerated", "bit", "octet", "utf8",
-- "numeric", "printable", "t61", "teletex", "videotex", "ia5", "graphics", "iso64",
-- "visible", "general", "unversal", "bmp", "utctime" </p>
--
-- @tparam string data to create new asn1_string
-- @tparam[opt] string type asn1 string type, defult with 'utf8'
-- @see asn1_string
function new_string() end
 
end

do  -- define class

--- openssl.asn1_object object
-- @type asn1_object
--
do  -- defint asn1_object

--- get nid of asn1_object.
--
-- @treturn[1] integer nid of asn1_object
--
function nid() end

--- get name of asn1_object.
--
-- @treturn[1] string short name of asn1_object
-- @treturn[2] string long name of asn1_object
--
function name() end

--- get short name of asn1_object.
--
-- @treturn[1] string short name of asn1_object
--
function sn() end

--- get long name of asn1_object.
--
-- @treturn[1] string long name of asn1_object
--
function ln() end

--- get text of asn1_object.
--
-- @tparam[opt] boolean no_name true for only oid or name, default with false
-- @treturn[1] string name or oid of asn1_object
--
function txt() end

--- compare two asn1_objects, if equals return true
--
-- @tparam asn1_object another to compre
-- @treturn[1] boolean true if equals
--
function __eq(another) end

end


--- openssl.asn1_string object
-- @type asn1_string

do

--- get length of asn1_string
--
-- @treturn[1] integer length of asn1_string
--
function length() end

--- get type of asn1_string
--
-- @treturn[1] string type of asn1_string
-- @see new_string
function type() end

--- get data of asn1_string
--
-- @treturn[1] string raw data of asn1_string
function data() end

--- set data of asn1_string
--
-- @tparam string data set to asn1_string
-- @treturn[1] boolean success if value set true, or follow by errmsg
-- @treturn[2] string fail error message
function data() end

--- get data as utf8 encode string
--
-- @treturn[1] string utf8 encoded string
function toutf8() end

--- get data as printable encode string
--
-- @treturn[1] string printable encoded string
function print() end

--- duplicate a new asn1_string
--
-- @treturn[1] asn1_string clone for self
function dup() end

--- get length two asn1_string
--
-- @treturn[1] integer length of asn1_string
-- @usage
--  local astr = asn1.new_string('ABCD')
--  print('length:',#astr)
--  print('length:',astr:length())
--  assert(#astr==astr:length,"must equals")
function length() end

--- compare two asn1_string, if equals return true
--
-- @tparam asn1_string another to compre
-- @treturn[1] boolean true if equals
-- @usage
--  local obj = astr:dup()
--  assert(obj==astr, "must equals")
function __eq(another) end

--- convert asn1_string to lua string
--
-- @treturn[1] string result format match with type:data
function __tostring() end

end

end
