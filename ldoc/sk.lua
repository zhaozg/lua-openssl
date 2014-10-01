--- 
-- Provide hmac function in lua.

--
-- @module hmac
-- @usage
--  hamc = require('openssl').hmac
--

do  -- define module function

--- read stack_of_x509 from string data or bio input
-- @tparam string|bio input 
-- @treturn stack_of_x509
-- @see stack_of_object
function openssl.sk_x509_read() end

--- contrust stack_of_x509 from table
-- @tparam table certs x509 object certs
-- @treturn stack_of_x509
-- @see stack_of_object
function openssl.sk_x509_new() end

end

do  -- define class

--- openssl.stack_of_object object
-- stack_of_x509_extension, stack_of_x509, stack_of_x509_attribute object has same interface.
-- stack_of_x509 is an important object in lua-openssl, it can be used as a certchain, trusted CA files or unstrust certs.
-- object not support x509, x509_extension or x509_attribute
-- @type stack_of_object
--

do  -- define stack_of_object

--- push an object into stack
-- @tparam object obj
-- @treturn stack_of_object self
function push() end

--- pop an object from stack
-- @treturn object
function pop() end

--- set object at given location
-- @tparam integer location
-- @tparam object object
-- @treturn stack_of_object self
function set() end

--- get object at given location
-- @tparam integer location
-- @treturn object obj
function get() end

--- insert object at given location
-- @tparam object obj
-- @tparam integer location
-- @treturn stack_of_x509 self
function insert() end

--- delete object at geiven location
-- @tparam integer location
-- @treturn object deleted object
function delete() end

--- convert stack_of_object to table
-- @@treturn table contain object index start from 1
function totable() end

end

end
