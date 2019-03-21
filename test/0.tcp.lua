local ok, uv  = pcall(require,'luv')
if not ok then uv = nil end

local LUA = arg[-1]
TestTCP = {}

if uv then
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

    function TestTCP:testUVTcp()
        local lcode = 1
        local stdout1 = uv.new_pipe(false)
        local stderr1 = uv.new_pipe(false)
        local stdout2 = uv.new_pipe(false)
        local stderr2 = uv.new_pipe(false)

        local function onread(err, chunk)
          assert(not err, err)
          if (chunk) then
            print(chunk)
          end
        end

        local child, pid
        child, pid = uv.spawn(LUA, {
          args = {"0.tcp_s.lua",'127.0.0.1',8081},
          stdio = {nil, stdout1, stderr1}
        }, function (code, signal)
            assertEquals(code,0)
            uv.close(child)
            lcode = 0
        end)
        if pid then
            uv.read_start(stdout1, onread)
            uv.read_start(stderr1, onread)
            set_timeout(2000,function()
                local child, pid
                child, pid = uv.spawn(LUA, {
                  args = {"0.tcp_c.lua",'127.0.0.1',8081},
                  stdio = {nil, stdout2, stderr2}
                }, function (code, signal)
                    assertEquals(code,0)
                    uv.close(child)
                    lcode = 0
                end)
                if pid then
                    uv.read_start(stdout2, onread)
                    uv.read_start(stderr2, onread)
                end
            end)
        end

        uv.run()
        uv.loop_close()
        assertEquals(lcode,0)
    end
end


local ok, luv = pcall(require, 'lluv')
if not ok then luv = nil end

if luv then

    local function P(pipe, read)
      return {
        stream = pipe,
        flags = luv.CREATE_PIPE +
                (read and luv.READABLE_PIPE or luv.WRITABLE_PIPE)
      }
    end

    lua_spawn = function(f, o, e, c)
        return luv.spawn({
            file = LUA, args = {f},
          stdio = {{}, P(o, false), P(e, false)}
        }, c)
    end

    function TestTCP:testLUVTCP()
        local function onread(pipe, err, chunk)
            if err then
                if err:name() ~= 'EOF' then
                    assert(not err, tostring(err))
                end
            end
            if chunk then
                print(chunk)
            end
        end

        local function onclose(child, err, status)
            if err then return print("Error spawn:", err) end
            assertEquals(status, 0)
            child:close()
        end

        local stdout1 = luv.pipe()
        local stderr1 = luv.pipe()
        local stdout2 = luv.pipe()
        local stderr2 = luv.pipe()

        lua_spawn("0.tcp_s.lua", stdout1, stderr1, onclose)
        lua_spawn("0.tcp_c.lua", stdout2, stderr2, onclose)

        stdout1:start_read(onread)
        stderr1:start_read(onread)
        stdout2:start_read(onread)
        stderr2:start_read(onread)

        luv.run()
        luv.close()
    end
end
