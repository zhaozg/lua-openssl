--- 
-- Provide ssl function in lua.
--
-- @module ssl
-- @usage
--  hamc = require('openssl').ssl
--

do  -- define module function

--- create ssl_ctx object, which mapping to SSL_CTX in openssl.
-- @tparam string protocol support 'SSLv3', 'SSLv23', 'SSLv2', 'TSLv1', 'DTLSv1', and can be follow by '-server' or '-client'
-- @tparam[opt] string support_ciphers, if not given, default of openssl will be used
-- @treturn ssl_ctx
function ctx_new() end

--- get alert_string for ssl state
-- @tparam number alert 
-- @tparam[opt=false] boolean long 
-- @treturn string alert type
-- @treturn string desc string, if long set true will return long info
function alert_string() end
 
end

do  -- define class

--- openssl.ssl_ctx object
-- @type ssl_ctx
--

do  -- define ssl_ctx

--- tell ssl_ctx use private key and certificate, and check private key
-- @tparam evp_pkey pkey
-- @tparam x509 cert
-- @treturn boolean result return true for ok, or nil follow by errmsg and errval
-- @treturn string errmsg
-- @treturn number errval
function used() end

--- add client ca cert and option extra chain cert
-- @tparam x509 clientca 
-- @tparam table extra_chain_cert_array
-- @treturn boolean result
function add() end

--- set temp callback 
-- @tparam string keytype, 'dh','ecdh',or 'rsa'
-- @tparam function tmp_cb
-- @param[opt] vararg
function set_tmp() end

--- set tmp key content pem format
-- @tparam string keytype, 'dh','ecdh',or 'rsa'
-- @tparam string key_pem
function set_tmp() end

--- set ecdh with given curvename as tmp key
-- @tparam string keytype, must be 'ecdh'
-- @tparam string curvename
function set_tmp() emd

--- clean given mode
-- mode support 'enable_partial_write','accept_moving_write_buffer','auto_retry','no_auto_chain','release_buffers'
-- @tparam boolean clear must be true
-- @tparam string mode 
-- @param[opt] ...
-- @treturn string
-- @treturn ...
-- @usage
--  modes = { ssl_ctx:mode('enable_partial_write','accept_moving_write_buffer','auto_retry') },
--   
--   for  i, v in ipairs(modes)
--     print(v)
--  end
--  --output 'enable_partial_write','accept_moving_write_buffer','auto_retry'
function mode() end

--- set options 
-- @tparam string option, support "microsoft_sess_id_bug", "netscape_challenge_bug", "netscape_reuse_cipher_change_bug",
-- "sslref2_reuse_cert_type_bug", "microsoft_big_sslv3_buffer", "msie_sslv3_rsa_padding","ssleay_080_client_dh_bug",
-- "tls_d5_bug","tls_block_padding_bug","dont_insert_empty_fragments","all",
-- @tparam string new options list
function options() end

--- clear options
-- @tparam boolean clear set true to clear options 
-- @tparam string option, support "microsoft_sess_id_bug", "netscape_challenge_bug", "netscape_reuse_cipher_change_bug",
-- "sslref2_reuse_cert_type_bug", "microsoft_big_sslv3_buffer", "msie_sslv3_rsa_padding","ssleay_080_client_dh_bug",
-- "tls_d5_bug","tls_block_padding_bug","dont_insert_empty_fragments","all",
-- @tparam string new options list
function options() end

--- get timeout
-- @return number 
function timeout() end

--- set timeout
-- @tparam number timeout
-- @treturn number previous timeout
function timeout() end

--- get verify mode
-- @treturn string 'none','peer','fail' or 'once'
function verify_mode() end

--- set verify mode
-- @tparam string mode must be in "none", "peer", "fail", "once"
-- you can pass more than one mode at same time

 --- get quit_shutdown is set or not
-- Normally when a SSL connection is finished, the parties must send out
-- "close notify" alert messages using ***SSL:shutdown"*** for a clean shutdown.
-- @treturn boolean result
function quiet_shutdown() end

--- set quiet_shutdown 
-- @tparam boolean quiet 
-- When setting the "quiet shutdown" flag to 1, ***SSL:shutdown*** will set the internal flags
-- to SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN. ***SSL:shutdown*** then behaves like
-- ***SSL:set_shutdown*** called with SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN.
-- The session is thus considered to be shutdown, but no "close notify" alert
-- is sent to the peer. This behaviour violates the TLS standard.
-- The default is normal shutdown behaviour as described by the TLS standard.
-- @treturn boolean result
function quiet_shutdown() end

--- set verify locations with cafile and capath
-- ssl_ctx:verify_locations specifies the locations for *ctx*, at
-- which CA certificates for verification purposes are located. The certificates
-- available via *CAfile* and *CApath* are trusted.
-- @tparam string cafile
-- @tparam string capath
-- @treturn boolean result
function verify_locations() end

--- get certificate verification store of ssl_ctx
--@treturn x509_store store
function cert_store() end

--- set or replaces then certificate verification store of ssl_ctx
-- @tparam x509_store store
--@treturn x509_store store
function cert_store() end

--- get verify depth when cert chain veirition
-- @treturn number depth 
function verify_depth() end

--- set verify depth when cert chain veirition
-- @tparam number depth
-- @treturn number depth 
function verify_depth() end

--- get verify_mode
-- @treturn number mode_code
-- @treturn string mode_string
--  none: not verify client cert
--  peer: verify client cert
--  fail: if client not have cert, will failure
--  once: verify client only once.
function verify_mode() end

--- set verify call back
-- @tparam string mode, must be 'none' or 'peer'
-- @tparam[opt=nil] function verifycb if mode is 'none', not need this
-- verifycb should like int function(int preverify_ok,X509_STORE_CTX ctx) return 0 to end,1 to continue
-- @treturn boolean result
function set_verify() end

--- create bio and ssl object
-- @tparam string host_addr format like 'host:port'
-- @tparam[opt=true] boolean server, true listen at host_addr,false connect to host_addr
-- @tparam[opt=true] boolean autoretry 
-- @treturn bio bio object
-- @treturn ssl ssl object
function bio() end

end

do  --define ssl object

--- openssl.ssl object
-- @type ssl

--- get want to do 
-- @treturn string 'nothing', 'reading', 'writing', 'x509_lookup'
-- @treturn number state want
function want() end

--- get cipher info of current session
-- @treturn table has key include name, version,id,bits,description 
function cipher() end

--- get number of bytes available inside SSL fro immediate read
-- treturn number 
function pending() end

--- get ssl_ctx object
-- @treturn ssl_ctx 
function ctx() end

--- set new ssl_ctx object
-- @tparam ssl_ctx ctx 
-- @treturn ssl_ctx orgine ssl_ctx object
function ctx() end

--- shutdown SSL connection
function shutdown() end

--- shutdown ssl connect with special mode, disable read or write, 
-- enable or disable quite shutdown
-- @tparam string mode support 'read','write', 'quite', 'noquite'
function shutdown() end

--- shutdown ssl connection with quite or noquite mode 
-- @tparam boolean mode
-- @treturn[1] boolean if mode is true, return true or false for quite 
-- @treturn[2] string if mode is false, return 'read' or 'write' for shutdown direction
function shutdown() end

--- get value according to what, arg can be list, arg must be in below list 
-- @tparam string arg
--  certificate:  return SSL certificates
--  fd: return file or network connect fd
--  rfd:
--  wfd:
--  client_CA_list
--  read_ahead: -> boolean
--  shared_ciphers: string
--  cipher_list -> string
--  verify_mode: number
--  verify_depth
--  state_string
--  state_string_long
--  rstate_string
--  rstate_string_long
--  iversion
--  version
--  default_timeout,
--  certificates
--  verify_result
--  state
--  state_string
-- @return according to arg
function get() end

--- set value according to what, arg can be list, arg must be in below list 
-- @tparam string arg
--  certificate:  return SSL certificates
--  fd: return file or network connect fd
--  rfd:
--  wfd:
--  client_CA:
--  read_ahead
--  cipher_list
--  verify_depth
--  purpose:
--  trust:
--  verify_result
--  state
-- @param value val type accroding to arg 
-- @return value
function set() end

end

end
