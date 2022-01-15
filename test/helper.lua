local openssl = require("openssl")
local ca = require("utils.ca")

local M = {}

M.luaopensslv, M.luav, M.opensslv = openssl.version()
M.libressl = M.opensslv:find("^LibreSSL")
M.openssl3 = M.opensslv:find("^OpenSSL 3")

function M.sslProtocol(srv, protocol)
  protocol = protocol or openssl.ssl.default
  if srv == true then
    return protocol .. "_server"
  elseif srv == false then
    return protocol .. "_client"
  elseif srv == nil then
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
  if type(subject) == "table" then
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

function M.spawn(cmd, args, pattern, after_start, after_close, env)
  local uv = require("luv")
  env = env or {}
  env['DYLD_INSERT_LIBRARIES'] = os.getenv('ASAN_LIB')
  env['LUA_CPATH'] = package.cpath
  env['LUA_PATH'] = package.path

  local function stderr_read(err, chunk)
    assert(not err, err)
    if (chunk) then
      io.write(chunk)
      io.flush()
    end
  end

  local resutls = ''
  local function stdout_read(err, chunk)
    assert(not err, err)
    if (chunk) then
      io.write(chunk)
      io.flush()
      resutls = resutls .. chunk
      if pattern and resutls:match(pattern) then
        print('matched.ing')
        if after_start then
          after_start()
        end
        resutls=''
      end
    end
  end

  local stdin = uv.new_pipe(false)
  local stdout = uv.new_pipe(false)
  local stderr = uv.new_pipe(false)

  local handle, pid
  handle, pid = uv.spawn(
    cmd,
    {
      args = args,
      env = env,
      stdio = { stdin, stdout, stderr },
    },
    function(code, signal)
      uv.close(handle)
      if after_close then
        after_close(code, signal)
      end
    end
  )
  uv.read_start(stdout, stdout_read)
  uv.read_start(stderr, stderr_read)
  return handle, pid
end

return M
