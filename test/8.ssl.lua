local ok, uv = pcall(require, 'lluv')
if not ok then uv = nil end

local lua_spawn do
local LUA = arg[-1]

local function P(pipe, read)
  return {
    stream = pipe,
    flags = uv.CREATE_PIPE + 
            (read and uv.READABLE_PIPE or uv.WRITABLE_PIPE)
  }
end

lua_spawn = function(f, o, e, c)
    return uv.spawn({
        file = LUA, args = {f},
      stdio = {{}, P(o, false), P(e, false)}
    }, c)
end
end

local function onread(pipe, err, chunk)
    if err then
        if err:name() ~= 'EOF' then
            assert(not err, tostring(err))
        end
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
    assertEquals(status, 0)
    child:close()
end

TestSSL = {}
if uv then
function TestSSL:testSSL()
    local stdout1 = uv.pipe()
    local stderr1 = uv.pipe()
    local stdout2 = uv.pipe()
    local stderr2 = uv.pipe()

    lua_spawn("8.ssl_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.ssl_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    uv.run()
    uv.close()
end

function TestSSL:testBio()
    local stdout1 = uv.pipe()
    local stderr1 = uv.pipe()
    local stdout2 = uv.pipe()
    local stderr2 = uv.pipe()

    lua_spawn("8.bio_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.bio_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    uv.run()
    uv.close()
end

function TestSSL:testsslconnectbio()
    local stdout1 = uv.pipe()
    local stderr1 = uv.pipe()
    local stdout2 = uv.pipe()
    local stderr2 = uv.pipe()

    lua_spawn("8.bio_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.ssl_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    uv.run()
    uv.close()
end

function TestSSL:testbioconnectssl()
    local stdout1 = uv.pipe()
    local stderr1 = uv.pipe()
    local stdout2 = uv.pipe()
    local stderr2 = uv.pipe()

    lua_spawn("8.ssl_s.lua", stdout1, stderr1, onclose)
    os.execute('ping -n 3 127.0.0.1')
    lua_spawn("8.bio_c.lua", stdout2, stderr2, onclose)

    stdout1:start_read(onread)
    stderr1:start_read(onread)
    stdout2:start_read(onread)
    stderr2:start_read(onread)

    uv.run()
    uv.close()
end
end
