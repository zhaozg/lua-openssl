--- Provide cms function in lua.
-- cms are based on apps/cms.c from the OpenSSL dist, so for more information, see the documentation for OpenSSL.
-- cms api need flags, not support "detached", "nodetached", "text", "nointern", "noverify", "nochain", "nocerts",
-- "noattr", "binary", "nosigs"
--
-- Decrypts the S/MIME message in the BIO object and output the results to BIO object. 
-- recipcert is a CERT for one of the recipients. recipkey specifies the private key matching recipcert.
-- Headers is an array of headers to prepend to the message, they will not be included in the encoded section.
--
-- @module cms
-- @usage
--  cms = require('openssl').cms
--

do  -- define module function

--- create cms object
-- @treturn cms
function create() end

--- read cms object
-- @tparam bio input
-- @tparam[opt=0] number flags
-- @treturn cms
function create() end

--- create digest cms object
-- @tparam bio input
-- @tparam evp_digest|string md_alg
-- @tparam[opt=0] number flags
-- @treturn cms
function create() end

--- encrypt with recipt certs
-- @tparam stack_of_x509 recipt certs
-- @tparam bio input
-- @tparam string|evp_cipher cipher_alg
-- @tparam[opt=0] number flags
-- @tparam[opt=nil] table options, may have key,keyid, password field which must be string type 
-- @treturn cms
function encrypt() end

--- decrypt cms message
-- @tparam cms message
-- @tparam evp_pkey pkey
-- @tparam x509 recipt
-- @tparam bio dcount output object
-- @tparam bio out output object
-- @tparam[opt=0] number flags
-- @tparam[opt=nil] table options may have key, keyid, password field, which must be string type
-- @treturn boolean
function decrypt() end

--- make signed cms object
-- @tparam x509 signer cert
-- @tparam evp_pkey pkey
-- @tparam stack_of_x509 certs include in the CMS
-- @tparam bio input_data
-- @tparam[opt=0] number flags 
-- @treturn cms object
function sign() end

--- verfiy signed cms object
-- @tparam cms signed
-- @tparam string verify_mode, must be 'verify'
-- @tparam stack_of_x509 others 
-- @tparam x509_store castore
-- @tparam bio message
-- @tparam bio out
-- @tparam[opt=0] number flags
-- @treturn boolean result
function verify() end

--- verify digest cms object
-- @tparam cms digested
-- @tparam string verify_mode, must be 'digest'
-- @tparam bio input message
-- @tparam bio out content
-- @tparam[opt=0] number flags
-- @treturn boolean result
function verify() end

--- verify receipt cms object
-- @tparam cms cms
-- @tparam string verify_mode must be 'receipt'
-- @tparam cms source
-- @tparam stack_of_x509 certs
-- @tparam x509_store store
-- @tparam[opt=0] number flags
-- @treturn boolean result
function verify() end

--- read cms object from input bio or string
-- @tparam bio|string input 
-- @tparam[opt='auto'] string format, support 'auto','smime','der','pem'
--  auto will only try 'der' or 'pem'
-- @tparam[opt=nil] bio content, only used when format is 'smime'
-- @treturn cms
function read() end

--- write cms object to bio object
-- @tparam cms cms
-- @tparam bio out
-- @tparam bio in 
-- @tparam[opt=0] number flags 
-- @tparam[opt='smime'] string format
-- @treturn boolean 
function write() end

--- create compress cms object
-- @tparam bio input 
-- @tparam string alg, zlib or rle 
-- @tparam[opt=0] number flags
-- @treturn cms
function compress() end

--- uncompress cms object
-- @tparam cms cms
-- @tparam bio input 
-- @tparam bio out 
-- @tparam[opt=0] number flags
-- @treturn boolean
function uncompress() end

--- create enryptdata cms
-- @tparam bio input 
-- @tparam cipher|string cipher_alg
-- @tparam strig key 
-- @tparam[opt=0] number flags
-- @treturn cms object
function EncryptedData_encrypt() end

--- decrypt encryptdata cms
-- @tparam cms encrypted
-- @tparam string key
-- @tparam bio out 
-- @tparam[opt=0] number flags
-- @treturn boolean result 
function EncryptedData_decrypt() end

end

