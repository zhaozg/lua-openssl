local lu = require 'luaunit'
local ok, uv = pcall(require, 'luv')
local math = require'math'
if not ok then
  uv = nil
  print('skip SSL, bacause luv not avalible')
end

TestSSL = {}
local LUA = arg and arg[-1] or nil
assert(LUA)

if uv then
  math.randomseed(os.time())
  local function set_timeout(timeout, callback)
    local timer = uv.new_timer()
    local function ontimeout()
      uv.timer_stop(timer)
      uv.close(timer)
      callback(timer)
    end
    uv.timer_start(timer, timeout, 0, ontimeout)
    return timer
  end

  function TestSSL:testUVSSL()
    local lcode
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then print(chunk) end
    end

    local port = math.random(8000, 9000)
    local child, pid
    child, pid = uv.spawn(LUA, {
      args = {"8.ssl_s.lua",  '127.0.0.1',  port},
      stdio = {nil,  stdout1,  stderr1}
    }, function(code, signal)
      lu.assertEquals(code, 0)
      lu.assertEquals(signal, 0)
      uv.close(child)
      lcode = code
    end)

    if pid then
      uv.read_start(stdout1, onread)
      uv.read_start(stderr1, onread)
      set_timeout(2000, function()
        local _child
        _child = uv.spawn(LUA, {
          args = {"8.ssl_c.lua",  '127.0.0.1',  port},
          stdio = {nil,  stdout2,  stderr2}
        }, function(code, signal)
          lu.assertEquals(code, 0)
          lu.assertEquals(signal, 0)
          uv.close(_child)
          lcode = code
        end)
        uv.read_start(stdout2, onread)
        uv.read_start(stderr2, onread)
      end)
    end

    uv.run()
    lu.assertEquals(lcode, 0)
  end

  function TestSSL:testUVBio()
    local lcode
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then print(chunk) end
    end

    local port = math.random(8000, 9000)
    local child
    child = uv.spawn(LUA, {
      args = {"8.bio_s.lua",  '127.0.0.1',  port},
      stdio = {nil,  stdout1,  stderr1}
    }, function(code, signal)
      lu.assertEquals(code, 0)
        lu.assertEquals(signal, 0)
      uv.close(child)
      lcode = code
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)

    set_timeout(2000, function()
      local _child
      _child = uv.spawn(LUA, {
        args = {"8.bio_c.lua",  '127.0.0.1',  port},
        stdio = {nil,  stdout2,  stderr2}
      }, function(code, signal)
        lu.assertEquals(code, 0)
        lu.assertEquals(signal, 0)
        uv.close(_child)
        lcode = 0
      end)
      uv.read_start(stdout2, onread)
      uv.read_start(stderr2, onread)
    end)

    uv.run()
    lu.assertEquals(lcode, 0)
  end

  function TestSSL:testUVsslconnectbio()
    local lcode
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then print(chunk) end
    end
    local port = math.random(8000, 9000)
    local child
    child = uv.spawn(LUA, {
      args = {"8.bio_s.lua",  '127.0.0.1',  port},
      stdio = {nil,  stdout1,  stderr1}
    }, function(code, signal)
      lu.assertEquals(code, 0)
      uv.close(child)
      lcode = code
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)

    set_timeout(2000, function()
      local _child
      _child = uv.spawn(LUA, {
        args = {"8.ssl_c.lua",  '127.0.0.1',  port, "serveraa.br"},
        stdio = {nil,  stdout2,  stderr2}
      }, function(code, signal)
        lu.assertEquals(code, 0)
        uv.close(_child)
        lcode = code
      end)
      uv.read_start(stdout2, onread)
      uv.read_start(stderr2, onread)
    end)

    uv.run()
    lu.assertEquals(lcode, 0)
  end

  function TestSSL:testUVbioconnectssl()
    local lcode = nil
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then print(chunk) end
    end
    local port = math.random(8000, 9000)
    local child
    child = uv.spawn(LUA, {
      args = {"8.ssl_s.lua",  '127.0.0.1',  port},
      stdio = {nil,  stdout1,  stderr1}
    }, function(code, signal)
      lu.assertEquals(code, 0)
      uv.close(child)
      lcode = code
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)

    set_timeout(2000, function()
      local _child
      _child = uv.spawn(LUA, {
        args = {"8.bio_c.lua",  '127.0.0.1',  port},
        stdio = {nil,  stdout2,  stderr2}
      }, function(code, signal)
        lu.assertEquals(code, 0)
        uv.close(_child)
        lcode = code
      end)
      uv.read_start(stdout2, onread)
      uv.read_start(stderr2, onread)
    end)

    uv.run()
    lu.assertEquals(lcode, 0)
  end
end

local luv
ok, luv = pcall(require, 'lluv')
if not ok then luv = nil end

local lua_spawn
do
  local function P(pipe, read)
    return {
      stream = pipe,
      flags = luv.CREATE_PIPE +
        (read and luv.READABLE_PIPE or luv.WRITABLE_PIPE)
    }
  end

  lua_spawn = function(f, o, e, c)
    return luv.spawn({
      file = LUA,
      args = {f},
      stdio = {{},  P(o, false),  P(e, false)}
    }, c)
  end
end

local function onread(pipe, err, chunk)
  if err then
    if err:name() ~= 'EOF' then assert(not err, tostring(err)) end
    pipe:close()
  end

  if chunk then
    print(chunk)
  else
    print("end")
  end
end

local function onclose(child, err, status)
  if err then return print("Error spawn:", err) end
  lu.assertEquals(status, 0)
  child:close()
end

if luv then
  function TestSSL:testLUVSSL()
    local stdout1 = luv.pipe()
    local stderr1 = luv.pipe()
    local stdout2 = luv.pipe()
    local stderr2 = luv.pipe()

    lua_spawn("8.ssl_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.ssl_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    luv.run()
    luv.close()
  end

  function TestSSL:testLUVBio()
    local stdout1 = luv.pipe()
    local stderr1 = luv.pipe()
    local stdout2 = luv.pipe()
    local stderr2 = luv.pipe()

    lua_spawn("8.bio_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.bio_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    luv.run()
    luv.close()
  end

  function TestSSL:testLUVsslconnectbio()
    local stdout1 = luv.pipe()
    local stderr1 = luv.pipe()
    local stdout2 = luv.pipe()
    local stderr2 = luv.pipe()

    lua_spawn("8.bio_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.ssl_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    luv.run()
    luv.close()
  end

  function TestSSL:testLUVbioconnectssl()
    local stdout1 = luv.pipe()
    local stderr1 = luv.pipe()
    local stdout2 = luv.pipe()
    local stderr2 = luv.pipe()

    lua_spawn("8.ssl_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.bio_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    luv.run()
    luv.close()
  end
end
