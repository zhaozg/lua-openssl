---
-- Provide ssl function in lua.
--
-- @module ssl
-- @usage
--  hamc = require('openssl').ssl
--

do  -- define module function

--- create ssl_ctx object, which mapping to SSL_CTX in openssl.
-- @tparam string protocol support 'SSLv3', 'SSLv23', 'SSLv2', 'TSLv1', 'TSLv1_1','TSLv1_2','DTLSv1', and can be follow by '_server' or '_client'
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
-- @treturn boolean result return true for ok, or nil followed by errmsg and errval
function use() end

--- add client ca cert and option extra chain cert
-- @tparam x509 clientca
-- @tparam[opt] table extra_chain_cert_array
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

--- get options
-- @treturn table string list of current options
function options() end

--- set options
-- @tparam string option, support "microsoft_sess_id_bug", "netscape_challenge_bug", "netscape_reuse_cipher_change_bug",
-- "sslref2_reuse_cert_type_bug", "microsoft_big_sslv3_buffer", "msie_sslv3_rsa_padding","ssleay_080_client_dh_bug",
-- "tls_d5_bug","tls_block_padding_bug","dont_insert_empty_fragments","all", please to see ssl_options.h
-- @treturn table string list of current options after set new option
function options() end

--- clear options
-- @tparam boolean clear set true to clear options
-- @tparam string option, support "microsoft_sess_id_bug", "netscape_challenge_bug", "netscape_reuse_cipher_change_bug",
-- "sslref2_reuse_cert_type_bug", "microsoft_big_sslv3_buffer", "msie_sslv3_rsa_padding","ssleay_080_client_dh_bug",
-- "tls_d5_bug","tls_block_padding_bug","dont_insert_empty_fragments","all",  please to see ssl_options.h
-- @treturn table string list of current options after clear some option
function options() end

--- get timeout
-- @return number
function timeout() end

--- set timeout
-- @tparam number timeout
-- @treturn number previous timeout
function timeout() end

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

--- get verify_mode, return number mode and all string modes list
-- @treturn number mode_code
-- @return ...
 --  none: not verify client cert
 --  peer: verify client cert
 --  fail: if client not have cert, will failure
 --  once: verify client only once.
-- @usage
--  mode = {ctx:verify_mode()}
--  print('integer mode',mode[1])
--  for i=2, #mode then
--    print('string mode:'..mode[i])
--  end
function verify_mode() end

--- set ssl verify mode and callback
-- @tparam number mode, mode set to ctx, must be ssl.none or ssl.peer, and ssl.peer support combine with ssl.fail or ssl.once
-- @tparam[opt=nil] function ssl verify callback in lua function, not give will use default openssl callback, when mode is 'none', will be ignore this
-- verify_cb must be boolean function(verifyarg) prototype, return true to continue or false to end ssl handshake
-- verifyarg has field 'error', 'error_string','error_depth','current_cert', and 'preverify_ok'
-- @treturn boolean result
function verify_mode() end

--- set certificate verify callback function
-- @tparam[opt] function cert_verify_cb with boolean function(verifyargs) prototype, if nil or none will use openssl default callback
-- verifyargs has field 'error', 'error_string','error_depth','current_cert'
function set_cert_verify() end

--- set certificate verify options
-- @tparam table verify_cb_flag support field always_continue with boolean value and verify_depth with number value.
function set_cert_verify() end

--- get current session cache mode
-- @ table modes as array, mode is 'no_auto_clear','server','client','both','off'
function session_cache_mode()

--- set session cache mode,and return old mode
-- @param mode string support 'no_auto_clear','server','client','both','off',
-- 'no_auto_clear' can be combine with others, so accept one or two param.
function session_cache_mode(...)

--- create bio object
-- @tparam string host_addr format like 'host:port'
-- @tparam[opt=false] boolean server, true listen at host_addr,false connect to host_addr
-- @tparam[opt=true] boolean autoretry ssl operation autoretry mode
-- @treturn bio bio object
function bio() end

--- create ssl object
-- @tparam bio bio
-- @tparam[opt=false] boolean server, true will make ssl server
-- @treturn ssl
function ssl() end

--- create ssl object
-- @tparam bio input
-- @tparam bio ouput
-- @tparam[opt=false] boolean server, true will make ssl server
-- @treturn ssl
function ssl() end

end

do  --define ssl object

--- openssl.ssl object
--  All SSL object IO operation methods(connect, accept, handshake, read,
--  peek or write) return nil or false when fail or error.
--  When nil returned, it followed by 'ssl' or 'syscall', means SSL layer or
--  system layer error. When false returned, it followed by number 0,
--  'want_read','want_write','want_x509_lookup','want_connect','want_accept'.
--  Numnber 0 means SSL connection closed, others means you should do some
--  SSL operation.
-- @type ssl

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

--- tell ssl use private key and certificate, and check private key
-- @tparam evp_pkey pkey
-- @tparam[opt] x509 cert
-- @treturn boolean result return true for ok, or nil followed by errmsg and errval
function use() end

--- get peer certificate and certificate chains
-- @treturn x509 certificate
-- @treturn sk_of_x509 chains of peer
function peer() end

--- get socket fd of ssl
-- @treturn number fd
function getfd() end

--- get current cipher info
-- @treturn table include name,version,id,bits,algbits and description
function current_cipher() end

--- get current compression name
-- @treturn string
function current_compression() end

--- get peer certificate verify result
-- @treturn boolean true for success
-- @treturn table all certificate in chains verify result
--  preverify_ok as boolean verify result
--  error as number error code
--  error_string as string error message
--  error_depth as number verify depth
--  current_cert as x509 certificate to verified
function getpeerverification() end

--- get ssl session
-- @treturn ssl_session session object
function session() end

--- set ssl session
-- @tparam string|ssl_session sesion
--  reuse session would speed up ssl handshake
-- @treturn boolean result
function session() end

--- duplicate ssl object
-- @treturn ssl
function dup() end

--- get ssl_ctx associate with current ssl
-- @treturn ssl_ctx
function ctx() end

--- set ssl_ctx associate to current ssl
-- @tparam ssl_ctx ctx
-- @treturn ssl_ctx orgine ssl_ctx object
function ctx() end

--- reset ssl object to allow another connection
-- @treturn boolean result true for success
function clear() end

--- get want to do
-- @treturn string 'nothing', 'reading', 'writing', 'x509_lookup'
-- @treturn number state want
function want() end

--- get number of bytes available inside SSL fro immediate read
-- treturn number
function pending() end

--- do ssl server accept
-- @treturn boolean true for success
-- @treturn string fail reason
function accept() end

--- do ssl client connect
-- @treturn boolean true for success
-- @treturn string fail reasion
function connect() end

--- do ssl read
-- @tparam[opt=4096] number length to read
-- @treturn string data, nil or false for fail
-- @treturn string fail reason
function read() end

--- do ssl peak, data can be read again
-- @tparam[opt=4096] number length to read
-- @treturn string data, nil or false for fail
-- @treturn string fail reason
function peek() end

--- do ssl write
-- @tparam string data
-- @treturn number count of bytes write successfully
-- @treturn string fail reason
function write() end

--- do ssl renegotiate
-- @treturn boolean true for success
-- @treturn string fail reasion
function renegotiate() end

--- do ssl handshake, support both server and client side
-- @treturn boolean true for success
-- @treturn string fail reasion
function handshake() end

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

--- do ssl renegotiate_pending
-- @treturn boolean true for success
-- @treturn string fail reasion
function renegotiate_pending() end

--- do ssl renegotiate_pending
-- @treturn boolean true for success
-- @treturn string fail reasion
function renegotiate_pending() end

--- make ssl to client mode
function set_connect_state() end

--- make ssl to server mode
function set_accept_state() end

end

end
