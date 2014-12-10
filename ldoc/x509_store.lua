---
-- Provide x509_store as lua object.
-- create and manage x509 store object
-- @module x509.store
-- @usage
--  store = require'openssl'.x509.store
--

do --define module function

--- create or generate a new x509_store object.
-- @tparam table certs array of x509 objects, all x509 object will add to store, certs can be empty but not nil
-- @tparam[opt] table crls array of x509_crl objects, all crl object will add to store
-- @treturn x509_store object
-- @see x509_store
function new() end

end  -- define module

do  -- define class

--- openssl.x509_store object
-- @type x509_store
--

do  -- define x509_store

function export () end

--- set verify depth of certificate chains
-- @tparam number depth
-- @treturn boolean result 
function depth() end

--- set verify flags of certificate chains
-- @tparam number flags
-- @treturn boolean result 
function flags() end

--- set as trust x509 store
-- @tparam boolean trust
-- @treturn boolean result 
function trust() end

--- set prupose of x509 store
-- @tparam integer purpose
-- @treturn boolean result
function purpose() end

--- load certificate from file or dir,not given any paramater will load from defaults path
-- @tparam[opt] string filepath
-- @tparam[opt] string dirpath
-- @treturn boolean result
function load() end

--- add x509 certificate or crl to store
-- paramater support x509 object,x509_crl object or array contains x509,x509_crl object
-- @treturn boolean result
function add(...) end

--- add lookup path for store
-- @tparam string path file or dir path to add
-- @tparam[opt='file'] mode only 'file' or 'dir'
-- @tparam[opt='default'] format only 'pem', 'der' or 'default'
-- @treturn boolean result
function add_lookup() end

end --define class

