---
-- Provide x509 module.
-- create and manage x509 certificate
-- @module x509
-- @usage
--  x509 = require'openssl'.x509
--

do --define module function

--- create or generate a new x509 object.
-- @tparam[opt] openssl.bn serial serial number
-- @tparam[opt] x509_req csr,copy x509_name, pubkey and extension to new object
-- @tparam[opt] x509_name subject subject name set to x509_req
-- @tparam[opt] stack_of_x509_extension extensions add to x509
-- @tparam[opt] stack_of_x509_attribute attributes add to x509
-- @treturn x509 certificate object
function new() end

--- read x509 from string or bio input
-- @tparam bio|string input input data
-- @tparam[opt='auto'] string format support 'auto','pem','der'
-- @treturn x509 certificate object
function read() end

--- return all supported purpose as table
-- @treturn table
function purpose() end

--- get special purpose info as table
-- @tparam number|string purpose id or short name
-- @treturn table
function purpose() end

--- get support certtypes
-- @tparam[opt='standard'] string type support 'standard','netscape','extend'
-- @treturn table if type is 'standard' or 'netscape', contains node with {lname=...,sname=...,bitname=...},
--                if type is 'extend', contains node with {lname=...,sname=...,nid=...}
function certtypes() end

--- get certificate verify result string message
-- @tparam number verify_result
-- @treturn string result message
function verify_cert_error_string() end

end --define module

do  -- define class

--- openssl.x509 object
-- @type x509
--

do  -- define x509

--- export x509_req to string
-- @tparam[opt='pem'] string format, 'der' or 'pem' default
-- @tparam[opt='true'] boolean noext not export extension
-- @treturn string
function export() end

--- parse x509 object as table
-- @tparam[opt=true] shortname default will use short object name
-- @treturn table result which all x509 information
function parse() end

--- sign x509
-- @tparam evp_pkey pkey private key to sign x509
-- @tparam x509|x509_name cacert or cacert x509_name
-- @tparam[opt='sha1WithRSAEncryption'] string|md_digest md_alg
-- @treturn boolean result true for check pass
function sign() end

--- check x509 with evp_pkey
-- @tparam evp_pkey pkey private key witch match with x509 pubkey
-- @treturn boolean result true for check pass
function check() end

--- check x509 for host (only for openssl 1.0.2 or greater)
-- @tparam string host hostname to check for match match with x509 subject
-- @treturn boolean result true if host is present and matches the certificate
function check_host() end

--- check x509 for email address (only for openssl 1.0.2 or greater)
-- @tparam string email to check for match match with x509 subject
-- @treturn boolean result true if host is present and matches the certificate
function check_email() end

--- check x509 for ip address (ipv4 or ipv6, only for openssl 1.0.2 or greater)
-- @tparam string ip to check for match match with x509 subject
-- @treturn boolean result true if host is present and matches the certificate
function check_ip_asc() end

--- check x509 with ca certchian and option purpose
-- purpose can be one of: ssl_client, ssl_server, ns_ssl_server, smime_sign, smime_encrypt, crl_sign, any, ocsp_helper, timestamp_sign
-- @tparam x509_store cacerts 
-- @tparam x509_store untrusted certs  containing a bunch of certs that are not trusted but may be useful in validating the certificate.
-- @tparam[opt] string purpose to check supported
-- @treturn boolean result true for check pass
-- @treturn integer verify result
-- @see verify_cert_error_string
function check() end

--- get digest of x509 object
-- @tparam[opt='sha1'] evp_digest|string md_alg, default use 'sha1'
-- @treturn string digest result
function digest() end

--- get public key of x509
-- @treturn evp_pkey public key
function pubkey() end

--- set public key of x509
-- @tparam evp_pkey pubkey public key set to x509
-- @treturn boolean result, true for success
function pubkey() end

--- get extensions of x509 object
-- @tparam[opt=false] boolean asobject, true for return as stack_of_x509_extension or as table
-- @treturn[1] stack_of_x509_extension object when param set true
-- @treturn[2] table contain all x509_extension when param set false or nothing
function extensions() end

--- set extension of x509 object
-- @tparam stack_of_x509_extension extensions
-- @treturn boolean result true for success
function extensions() end

--- get issuer name of x509
-- @tparam[opt=false] boolean asobject, true for return as x509_name object, or as table
-- @treturn[1] x509_name issuer
-- @treturn[1] table issuer name as table
function issuer() end

--- set issuer name of x509
-- @tparam x509_name name
-- @treturn boolean result true for success
function issuer() end

--- get subject name of x509
-- @tparam[opt=false] boolean asobject, true for return as x509_name object, or as table
-- @treturn[1] x509_name subject name
-- @treturn[1] table subject name as table
function subject() end

--- set subject name of x509
-- @tparam x509_name subject
-- @treturn boolean result true for success
function subject() end

--- get serial number of x509
-- @tparam[opt=true] boolean asobject
-- @treturn[1] bn object
-- @treturn[2] string result
function serial() end

--- set serial number of x509
-- @tparam string|number|bn serail
-- @treturn boolean result true for success
function serial() end

--- get version number of x509
-- @treturn number version of x509
function version() end

--- set version number of x509
-- @tparam number version
-- @treturn boolean result true for result
function version() end

--- get notbefore valid time of x509
-- @treturn string notbefore time string
function notbefore() end

--- set notbefore valid time of x509
-- @tparam string|number notbefore
function notbefore() end

--- get notafter valid time of x509
-- @treturn string notafter time string
function notafter() end

--- set notafter valid time of x509
-- @tparam string|number notafter
function notafter() end

--- check x509 valid
-- @tparam[opt] number time, default will use now time
-- @treturn boolean result true for valid, or for invalid
-- @treturn string notbefore
-- @treturn string notafter
function validat()

--- set valid time, notbefore and notafter
-- @tparam number notbefore
-- @tparam number notafter
-- @treturn boolean result, true for success
function validat() end

end --define x509

end --define class
