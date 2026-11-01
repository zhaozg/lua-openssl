local openssl = require("openssl")
local ca = require("utils.ca")

local M = {}

M.luaopensslv, M.luav, M.opensslv, M.info = openssl.version()
M._luaopensslv, M._luav, M._opensslv = openssl.version(true)

--[[
Version checks always go through numbers, never through version strings.

This used to be `M.opensslv:match("1.0.2")` and `:find("^OpenSSL 3")`:
  - string matching pins the tests to one exact version number and breaks as
    soon as OpenSSL words it differently ("OpenSSL 3.0.2 15 Mar 2022" contains
    "1.0.2" as well, and "OpenSSL 4.0" does not match "^OpenSSL 3");
  - more importantly, M.opensslv describes the **runtime** library while the
    #if branches inside the tests are fixed at **compile time**; when the two
    disagree, inferring behaviour from a string only yields wrong conclusions.

M.info is the 4th return value of openssl.version(), its fields are described
in the "Version" section of README.md.
]]
M.libressl = M.info.libressl
M.openssl3 = M.info.num >= 0x30000000 and not M.info.libressl
-- 1.0.2 and earlier: the DTLS method of SSL_CTX/SSL is DTLSv1_2, not DTLS.
M.before_1_1_0 = M.info.num < 0x10100000

--- Semantic version comparison, the C side equivalent is openssl.version_ge
---@param major integer
---@param minor? integer
---@param patch? integer
function M.version_ge(major, minor, patch)
  return openssl.version_ge(major, minor or 0, patch or 0)
end

function M.sslProtocol(srv, protocol)
  protocol = protocol or openssl.ssl.default
  if M.before_1_1_0 then
    protocol = protocol:gsub("DTLS", "DTLSv1_2")
  end
  if srv == true then
    return protocol .. "_server"
  elseif srv == false then
    return protocol .. "_client"
  elseif srv == nil then
    return protocol
  end
  assert(nil)
end

function M.supportTLSv1_3()
  -- TLS 1.3 arrived in 1.1.1; the old `> 0x10100000` counted 1.1.0 as well.
  return M.version_ge(1, 1, 1) or M.libressl
end

function M.get_ca()
  if not M.ca then
    M.ca = ca:new()
  end
  return M.ca
end

function M.new_req(subject, exts, attrs)
  local pkey = openssl.pkey.new()
  if type(subject) == "table" then
    subject = openssl.x509.name.new(subject)
  end
  local req = assert(openssl.x509.req.new(subject))
  if exts then
    req:extensions(exts)
  end
  if attrs then
    req:attributes(attrs)
  end
  assert(req:sign(pkey))
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
  if os.getenv("ASAN_LIB") then
    env[#env + 1] = "DYLD_INSERT_LIBRARIES=" .. os.getenv("ASAN_LIB")
  end
  env[#env + 1] = "LUA_CPATH=" .. package.cpath
  env[#env + 1] = "LUA_PATH=" .. package.path

  -- Passing env hands the child a fresh environment, which drops PATH entirely.
  -- Callers usually pass a bare name ("luajit"), and without PATH it cannot be
  -- spawned: uv.spawn reports ENOENT, which looks like an OpenSSL failure but
  -- is really the launcher's. This entry used to be missing and kept seven
  -- SSL/TCP cases red.
  local has_path = false
  for _, kv in ipairs(env) do
    if kv:match("^PATH=") then has_path = true break end
  end
  if not has_path then
    env[#env + 1] = "PATH=" .. (os.getenv("PATH") or "/usr/local/bin:/usr/bin:/bin")
  end

  local function stderr_read(err, chunk)
    assert(not err, err)
    if chunk then
      io.write(chunk)
      io.flush()
    end
  end

  local resutls = ""
  local function stdout_read(err, chunk)
    assert(not err, err)
    if chunk then
      io.write(chunk)
      io.flush()
      resutls = resutls .. chunk
      if pattern and resutls:match(pattern) then
        print("matched.ing")
        if after_start then
          after_start()
        end
        resutls = ""
      end
    end
  end

  local stdin = uv.new_pipe(false)
  local stdout = uv.new_pipe(false)
  local stderr = uv.new_pipe(false)

  local handle, pid
  handle, pid = assert(uv.spawn(cmd, {
    args = args,
    env = env,
    cwd = uv.cwd(),
    stdio = { stdin, stdout, stderr },
  }, function(code, signal)
    uv.close(handle)
    if after_close then
      after_close(code, signal)
    end
  end))
  uv.read_start(stdout, stdout_read)
  uv.read_start(stderr, stderr_read)
  return handle, pid
end

return M
