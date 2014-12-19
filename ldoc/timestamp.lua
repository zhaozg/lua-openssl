---
-- Provide timestamp module.
-- create and manage x509 certificate sign request
-- @module ts
-- @usage
--  ts = require'openssl'.ts
--

do --define module function

--- create a new ts_req object.
-- @tparam[opt=1] integer version
-- @treturn ts_req timestamp sign request object
-- @see ts_req
function req_new () end

--- read ts_req object from string or bio data
-- @tparam string|bio input
-- @treturn ts_req timestamp sign request object
-- @see ts_req
function req_read() end

--- read ts_resp object from string or bio input
-- @tparam string|bio input
-- @treturn ts_resp object
function resp_read() end

--- create ts_resp_ctx object
-- @tparam[opt] x509 signer timestamp certificate
-- @tparam[opt] evp_pkey pkey private key to sign ts_req
-- @tparam[opt] asn1_object|string|nid identity for default policy object
-- @treturn ts_resp_ctx object

function resp_ctx_new() end

--- create ts_verify_ctx object
-- @tparam[opt=nil] string|ts_req reqdata
-- @treturn ts_verify_ctx object
function verify_ctx_new() end

end  -- define module

do  -- define class

-------------------------------------------------------------------------------------------
--- openssl.ts_req object
-- @type ts_req

do  -- define ts_req

--- export ts_req to string
-- @treturn string
function export () end

--- get info as table 
-- @treturn table
function info() end

--- create ts_verify_ctx from ts_req object
-- @treturn ts_verify_ctx object
function to_verify_ctx() end

--- make a clone of ts_req object
-- @treturn ts_req
function dup() end

--- get version
-- @treturn integer
function version() end

--- set version
-- @tparam integer version
-- @treturn boolean result
function version() end

--- get cert_req
-- @treturn boolean true for set or not
function cert_req() end

--- set cert_req
-- @tparam boolean cert_req 
-- @treturn boolean result
function cert_req() end

--- get nonce
-- @treturn bn openssl.bn object
function nonce() end

--- set nonce
-- @tparam string|bn nonce
-- @treturn boolean result
function nonce() end

--- get policy_id
-- @treturn asn1_object
function policy_id() end

--- set policy_id
-- @tparam asn1_object|number id  identity for asn1_object
-- @treturn boolean result
function policy_id() end

--- get msg_imprint
-- @treturn string octet octet string
-- @treturn table with algorithm and paramater
function msg_imprint() end

--- set msg_imprint
-- @tparam string data digest value of message 
-- @tparam[opt='sha'] string|evp_md md_alg
-- @treturn boolean result
function msg_imprint() end

end --define class


--- openssl.ts_resp object
-- @type ts_resp

do  -- define ts_resp

--- export ts_resp to string
-- @treturn string
function export () end

--- duplicate ts_resp object
-- @treturn ts_resp object
function dup () end

--- get info as table
-- @treturn table 
function info() end

--- get info as table
-- @treturn table 
function tst_info() end

end

--- openssl.ts_verify_ctx object
-- @type ts_verify_ctx
do
--- verify ts_resp object, pkcs7 token or ts_resp data
-- @tparam ts_resp|pkcs7|string data
-- @treturn boolean result
function verify() end

--- get x509_store cacerts
-- @treturn stack_of_x509
function store() end

--- set x509_store cacerts
-- @tparam x509_store cacerts
-- @treturn boolean result
function store() end

--- get flags 
-- @treturn integer flags
function flags() end

--- set flags
-- @tparam integer flags
-- @treturn boolean result
function flags() end

--- get untrust certs
-- @treturn stack_of_x509 untrust
function certs() end

--- set untrust certs
-- @tparam stack_of_x509 untrust
-- @treturn boolean result
function certs() end

--- get data
-- @treturn bio data object
function data() end

--- set data
-- @tparam bio data object
-- @treturn boolean result
function data() end

--- get imprint
-- @treturn string imprint
function imprint() end

--- set imprint
-- @tparam string imprint
-- @treturn boolean result
function imprint() end

end

--- openssl.ts_resp_ctx object
-- @type ts_resp_ctx

do

--- get signer cert and pkey
-- @treturn x509 cert object or nil
-- @treturn evp_pkey pkey object or nil
function signer() end

--- set signer cert and pkey
-- @tparam x509 cert signer cert
-- @tparam evp_pkey pkey signer pkey
-- @treturn boolean result
function signer() end

--- get additional certs 
-- @treturn stack_of_x509 certs object or nil
function certs() end

--- set additional certs 
-- @tparam stack_of_x509 certs
-- @treturn boolean result
function certs() end

--- get flags
-- @treturn integer flags
function flags() end

--- set flags
-- @tparam integer flags
-- @treturn boolean result
function flags() end

--- get policies
-- @treturn stack_of_asn1_object 
function policies() end

--- set policies
-- @tparam asn1_object|integer|string|stack_of_asn1_object|table policies
-- @treturn boolean result
function policies() end

--- get accuracy
-- @treturn integer seconds
-- @treturn integer millis
-- @treturn integer micros
function accuracy() end

--- set accuracy
-- @tparam integer seconds
-- @tparam integer millis
-- @tparam integer micros
-- @treturn boolean result
function accuracy() end

--- get clock_precision_digits
-- @treturn integer clock_precision_digits
function clock_precision_digits() end

--- set clock_precision_digits
-- @tparam integer clock_precision_digits
-- @treturn boolean result
function clock_precision_digits() end

--- set status info
-- @tparam integer status
-- @tparam string text
-- @treturn boolean result
function set_status_info() end

--- set status info cond
-- @tparam integer status
-- @tparam string text
-- @treturn boolean result
function set_status_info_cond() end

--- add failure info 
-- @tparam integer failure
-- @treturn result
function add_failure_info() end

--- get all digest method 
-- @treturn table contains all support digest method
function md() end

--- set support digest method
-- @tparam table mds support digest method
-- @treturn boolean result
function md() end

--- add digest
-- @tparam string|evp_digest md_alg
-- @treturn boolean result
function md() end

--- get tst_info as table
-- @treturn table tst_info
function tst_info() end

--- get ts_req object
-- @treturn rs_req
function request() end

--- set serial generate callback function
-- @tparam function serial_cb serial_cb with proto funciont(ts_resp_ctx, arg) return openssl.bn end
-- @usage
--  function serial_cb(tsa,arg)
--    local bn = ...
--    return bn
--  end
--  local arg = {}
--- ts_resp_ctx:set_serial_cb(serial_cb, arg)
function set_serial_cb() end

--- set time callback function
-- @tparam function time_cb serial_cb with proto funciont(ts_resp_ctx, arg) return sec, usec end
-- @usage
--  function time_cb(tsa,arg)
--    local time = os.time()
--    local utime = nil
--    return time,utime
--  end
--  local arg = {}
--- ts_resp_ctx:set_time_cb(time_cb, arg)
function set_serial_cb() end

--- create response for ts_req
-- @tparam string|bio|ts_req data support string,bio ts_req content or ts_req object
-- @treturn ts_resp result
function create_response() end

--- sign ts_req and get ts_resp, alias of create_response
-- @tparam string|bio|ts_req data support string,bio ts_req content or ts_req object
-- @treturn ts_resp result
function sign() end

end

end
