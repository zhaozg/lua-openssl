local openssl = require'openssl'
local ca = require'utils.ca'

local M = {}

M.luaopensslv, M.luav, M.opensslv = openssl.version()
M.libressl = M.opensslv:find('^LibreSSL')

function M.sslProtocol(srv, protocol)
  local _,_,opensslv = openssl.version(true)
  if M.libressl or opensslv < 0x10100000 then
    protocol = protocol or 'SSLv23'
  else
    protocol = protocol or 'TLS'
  end
  if srv==true then
    return protocol.."_server"
  elseif srv==false then
    return protocol.."_client"
  elseif srv==nil then
    return protocol
  end
  assert(nil)
end

function M.get_ca()
  if not M.ca then
    M.ca = ca:new()
  end
  return M.ca
end

function M.new_req(subject)
  local pkey = openssl.pkey.new()
  if type(subject)=='table' then
    subject = openssl.x509.name.new(subject)
  end
  local req = assert(openssl.x509.req.new(subject, pkey))
  return req, pkey
end

function M.sign(subject, extensions)
  local CA = M.get_ca()
  if not type(subject):match("x509.req") then
    local req, pkey = M.new_req(subject)
    local cert = CA:sign(req, extensions)
    return cert, pkey
  end
  return CA:sign(subject, extensions)
end

return M

