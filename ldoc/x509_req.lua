---
-- Provide x509_req as lua object.
-- create and manage x509 certificate sign request
-- @module x509.req
-- @usage
--  req = require'openssl'.x509.req
--

do --define module function

--- create or generate a new x509_req object.
-- Note if not give evp_pkey, will create a new x509_req object,or will generate a signed x509_req object.
-- @tparam[opt] x509_name subject subject name set to x509_req
-- @tparam[opt] stack_of_x509_extension extensions add to x509_req
-- @tparam[opt] stack_of_x509_attribute attributes add to x509_req
-- @tparam[opt] evp_pkey pkey private key sign the x509_req, and set as public key
-- @tparam[opt='sha1WithRSAEncryption'] evp_digest|string md_alg,  only used when pkey exist, and should fellow pkey
-- @treturn x509_req certificate sign request object
-- @see x509_req
function new () end

--- read x509_req from string or bio input
-- @tparam bio|string input input data
-- @tparam[opt='auto'] string format support 'auto','pem','der'
-- @treturn x509_req certificate sign request object
function read() end

end  -- define module

do  -- define class

--- openssl.x509_req object
-- @type x509_req
--

do  -- define x509_req

--- export x509_req to string
-- @tparam[opt='pem'] string format
-- @tparam[opt='true'] boolean noext not export extension
-- @treturn string
function export () end

--- get public key
-- @treturn evp_pkey public key
function public() end

--- set public key
-- @tparam evp_pkey pubkey public key set to x509_req
-- @treturn boolean result
function public() end

--- get version key
-- @treturn integer
function version() end

--- set version key
-- @tparam integer version
-- @treturn boolean result
function version() end

--- get subject x509_name object
-- @treturn x509_name
function subject() end

--- set subject x509_name object
-- @tparam x509_name subject
-- @treturn boolean result
function subject() end

--- remove attribute object from location
-- @tparam integer location
-- @tparam nil nil, nil not none
-- @treturn x509_attribute attribute removed
function attribute() end

--- get attribute object from location
-- @tparam integer location
-- @treturn x509_attribute attribute
function attribute() end

--- add attribute to x509_req object
-- @tparam x509_attribute attribute attribute to add
-- @treturn boolean result
function attribute() end

--- get total attribute count in x509_req object
-- @treturn integer
function attr_count() end

--- convert x509_req to x509 object
-- @treturn x509 object not signed
-- @fixme memleaks
function to_x509()

--- clone x509_req object
-- @treturn x509_req object
function dup()

--- check x509_req with evp_pkey
-- @tparam evp_pkey pkey
-- @treturn boolean result true for check pass
function check() end

--- verify x509_req signature
-- @treturn boolean result true for verify pass
function verify() end

--- get digest of x509_req
-- @tparam[opt='SHA1'] evp_md|string md_alg default use sha1
-- @treturn string digest result
function digest() end

--- parse x509_req object as table
-- @tparam[opt=true] shortname default will use short object name
-- @treturn table result
function parse() end

end --define class
