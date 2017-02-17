---
-- Provide X509_ALGOR as lua object.
-- Sometime when you make CSR,TS or X509, you maybe need to use this.
--
-- @module x509.algor
-- @usage
--  algor = require('openssl').x509.algor
--

do  -- define module function

--- Create x509_algor object
--
-- @treturn x509_algor mapping to X509_ALGOR in openssl
function new() end

end

do  -- define class

--- openssl.x509_algor object
-- @type x509_algor
--
do

--- clone the x509_algor
--
-- @treturn x509_algor clone of x509_algor
function dup() end

--- set x509_algor properties
--
-- @tparam asn1_object obj ident algorithm in openssl
-- @tparam[opt] asn1_string val attached paramater value
-- @treturn boolean result true for success, others for fail
function set() end

--- get x509_algor properties
--
-- @tparam asn1_object ident algorithm, nil for fail
-- @tparam asn1_string attached paramater value
function get() end

--- convert x509_algor to txt string of asn1_object
--
-- @tparam string txt of asn1_object
function tostring() end

--- check with other x509_algor whether equals, alias with == operator
--- only when OPENSSL_VERSION_NUMBER >= 0x10002000L
--
-- @tparam x509_algor other to compare
function equals() end

--- check with other x509_algor whether equals, alias with == operator
--- only when OPENSSL_VERSION_NUMBER >= 0x10002000L
--
-- @tparam x509_algor other to compare
function equals() end

--- set digest algorithm, alias of set()
--- only when OPENSSL_VERSION_NUMBER >= 0x10001000
--
-- @tparam string|evp_digest digest algorithm

end

end

