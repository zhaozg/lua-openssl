local openssl = require'openssl'
local ext = openssl.x509.extension

local M = {}

local default_caexts = {
  {
     object='basicConstraints',
     value='CA:true',
     critical = true
  },
  {
    object='keyUsage',
    value='keyCertSign'
  }
}

function M.to_extensions(exts)
  exts = exts or default_caexts
  local ret = {}
  for i=1, #exts do
    ret[i] = ext.new_extension(exts[i])
  end
  return ret
end

function M.new_ca(subject)
  --cacert, self sign
  local pkey = assert(openssl.pkey.new())
  local req = assert(openssl.x509.req.new(subject, pkey))
  local cacert = openssl.x509.new(
    1,      --serialNumber
    req     --copy name and extensions
  )
  cacert:extensions(M.to_extensions())
  cacert:notbefore(os.time())
  cacert:notafter(os.time() + 3600*24*365)
  assert(cacert:sign(pkey, cacert))  --self sign
  return pkey, cacert
end

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

return M

