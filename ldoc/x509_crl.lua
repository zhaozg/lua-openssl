---
-- Provide x509_crl as lua object.
-- create and manage x509 certificate sign request
-- @module x509.crl
-- @usage
--  crl = require'openssl'.x509.crl
--

do --define module function

--- create or generate a new x509_crl object.
-- Note if not give evp_pkey, will create a new x509_crl object,if give will generate a signed x509_crl object.
-- @tparam[opt] table revoked_list 
-- @tparam[opt] x509 cacert ca cert to sign x509_crl
-- @tparam[opt] evp_pkey capkey private key to sign x509_crl
-- @tparam[opt] string|evp_md md_alg
-- @tparam[opt=7*24*3600] number period to generate new crl
-- @treturn x509_crl object
-- @see x509_crl
function new() end

--- read x509_crl from string or bio input
-- @tparam bio|string input input data
-- @tparam[opt='auto'] string format support 'auto','pem','der'
-- @treturn x509_crl certificate sign request object
-- @see x509_crl
function read() end

--- list all support reason info
-- @treturn table contain support reason node like {lname=...,sname=...,bitnum=...}
function reason() end

end  -- define module

do  -- define class

--- openssl.x509_crl object
-- @type x509_crl
--

do  -- define x509_crl

--- export x509_crl to string
-- @tparam[opt='pem'] string format
-- @tparam[opt='true'] boolean noext not export extension
-- @treturn string
function export () end

--- sign x509_crl
-- @tparam evp_pkey pkey private key to sign x509
-- @tparam x509|x509_name cacert or cacert x509_name
-- @tparam[opt='sha1WithRSAEncryption'] string|md_digest md_alg
-- @treturn boolean result true for check pass
function sign() end

--- get digest of x509_crl
-- @tparam[opt='SHA1'] evp_md|string md_alg default use sha1
-- @treturn string digest result
function digest() end

--- compare with other x509_crl object
-- @tparam x509_crl other
-- @treturn boolean result true for equals or false
-- @usage
--  x:cmp(y) == (x==y)
function cmp() end

--- make a delta x509_crl object
-- @tparam x509_crl newer
-- @tparam evp_pkey pkey
-- @tparam[opt='sha1'] evp_md|string md_alg
-- @tparam[opt=0] integer flags
-- @treturn x509_crl delta result x509_crl object 
function diff() end

--- check x509_crl with evp_pkey
-- @tparam evp_pkey pkey
-- @tparam[opt=0] integer flags 
-- @treturn boolean result true for pass
function check() end

--- parse x509_crl object as table
-- @tparam[opt=true] shortname default will use short object name
-- @treturn table result
function parse() end

--- get count of revoked entry
-- @treturn number count
-- @usage
--  assert(#crl==crl:count())
function count() end

--- get revoekd entry
-- @tparam number index
-- @treturn table revoekd 
function get() end

--- set version key
-- @tparam integer version
-- @treturn boolean result
function version() end

--- get issuer x509_name object
-- @treturn x509_name
function issuer() end

--- set issuer x509_name object
-- @tparam x509_name|x509 issuer
-- @treturn boolean result
function issuer() end

--- get lastUpdate time
-- @treturn string lastUpdate
function lastUpdate() end

--- set lastUpdate time
-- @tparam number lastUpdate
-- @treturn boolean result
function lastUpdate() end

--- get nextUpdate time
-- @treturn string nextUpdate
function nextUpdate() end

--- set nextUpdate time
-- @tparam number nextUpdate
-- @treturn boolean result
function nextUpdate() end

--- get updateTime time
-- @treturn string lastUpdate
-- @treturn string nextUpdate
function updateTime() end

--- set updateTime time
-- @tparam[opt=os.time()] lastUpdate, default use current time
-- @tparam number periord periord how long time(seconds)
-- @treturn boolean result
function updateTime() end

--- get extensions of x509_crl
-- @treturn stack_of_x509_extension extensions
function extensions() end

--- set extensions to x509_crl object
-- @tparam stack_of_x509_extension extensions add to x509_crl
-- @treturn boolean result
function extensions() end

--- add revoked entry to x509_crl object
-- @tparam string|number|bn serial
-- @tparam number revokedtime
-- @tparam[opt=0] number|string reason
-- @treturn boolean result true for add success
function add() end

end --define class
