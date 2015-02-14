local uv = pcall(require,'luv')

TestSSL = {}
if uv then
function TestSSL:testSSL()
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then
        print(chunk)
      else
        print("end")
      end
    end

    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.ssl_s.lua"},
      stdio = {nil, stdout1, stderr1}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)

    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.ssl_c.lua"},
      stdio = {nil, stdout2, stderr2}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)
    uv.read_start(stdout2, onread)
    uv.read_start(stderr2, onread)
    
    uv.run()
    uv.loop_close()
end


function TestSSL:testBio()
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then
        print(chunk)
      else
        print("end")
      end
    end
    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.bio_s.lua"},
      stdio = {nil, stdout1, stderr1}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)

    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.bio_c.lua"},
      stdio = {nil, stdout2, stderr2}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)
    uv.read_start(stdout2, onread)
    uv.read_start(stderr2, onread)
    
    uv.run()
    uv.loop_close()
end


function TestSSL:testsslconnectbio()
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then
        print(chunk)
      else
        print("end")
      end
    end
    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.bio_s.lua"},
      stdio = {nil, stdout1, stderr1}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)

    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.ssl_c.lua"},
      stdio = {nil, stdout2, stderr2}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)
    uv.read_start(stdout2, onread)
    uv.read_start(stderr2, onread)
    
    uv.run()
    uv.loop_close()
end

function TestSSL:testbioconnectssl()
    local stdout1 = uv.new_pipe(false)
    local stderr1 = uv.new_pipe(false)
    local stdout2 = uv.new_pipe(false)
    local stderr2 = uv.new_pipe(false)
    local function onread(err, chunk)
      assert(not err, err)
      if (chunk) then
        print(chunk)
      else
        print("end")
      end
    end
    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.ssl_s.lua"},
      stdio = {nil, stdout1, stderr1}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)

    local child, pid child, pid = uv.spawn(arg[-1], {
      args = {"8.bio_c.lua"},
      stdio = {nil, stdout2, stderr2}
    }, function (code, signal)
        assertEquals(code,1)
        uv.close(child)
    end)
    uv.read_start(stdout1, onread)
    uv.read_start(stderr1, onread)
    uv.read_start(stdout2, onread)
    uv.read_start(stderr2, onread)
    
    uv.run()
    uv.loop_close()
end
end
