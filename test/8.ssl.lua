local lu = require 'luaunit'
local ok, uv = pcall(require, 'luv')
local math = require 'math'
local openssl = require "openssl"
local helper = require 'helper'
local bio, ssl = openssl.bio, openssl.ssl

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

  function TestSSL:testMisc()
    assert(ssl.alert_type(1) == 'W')
    assert(ssl.alert_type(1, true) == 'warning')
    assert(ssl.alert_type(2) == 'F')
    assert(ssl.alert_type(2, true) == 'fatal')
    assert(ssl.alert_type(3) == 'U')
    assert(ssl.alert_type(3, true) == 'unknown')

    local list = {10,  20,  21,  22,  30,  40,  50,  60,  70,  80,  90,  100}
    for _, i in pairs(list) do
      assert(ssl.alert_desc(i) ~= 'U', i)
      assert(ssl.alert_desc(i, true) ~= 'unknown', i)
    end
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

    set_timeout(5000, function()
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
        args = {"8.ssl_c.lua",  '127.0.0.1',  port,  "serveraa.br"}, 
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

function TestSSL:testSNI()
  local ca = helper.get_ca()
  local store = ca:get_store()
  assert(store:trust(true))
  store:add(ca.cacert)
  store:add(ca.crl)

  local certs = {}

  local function create_ctx(dn, mode)
    mode = mode or '_server'
    local ctx = ssl.ctx_new(ssl.default .. mode)
    if dn then
      local cert, pkey = helper.sign(dn)
      assert(ctx:use(pkey, cert))
      certs[#certs + 1] = cert
    end
    return ctx
  end

  local function create_srv_ctx()
    local ctx = create_ctx({{CN = "server"},  {C = "CN"}})

    ctx:set_servername_callback({
      ["serverA"] = create_ctx {{CN = "serverA"},  {C = "CN"}}, 
      ["serverB"] = create_ctx {{CN = "serverB"},  {C = "CN"}}
    })
    if store then ctx:cert_store(store) end

    ctx:set_cert_verify()
    ctx:set_cert_verify({always_continue = true,  verify_depth = 4})
    return ctx
  end

  local function create_cli_ctx()
    local ctx = create_ctx(nil, '_client')
    if store then ctx:cert_store(store) end
    ctx:set_cert_verify({always_continue = true,  verify_depth = 4})
    return ctx
  end

  local bs, bc = bio.pair()

  local rs, cs, es, ec, i, o, sess

  local srv_ctx = create_srv_ctx()
  local cli_ctx = create_cli_ctx()
  local srv = assert(srv_ctx:ssl(bs, bs, true))
  local cli = assert(cli_ctx:ssl(bc, bc, false))
  srv_ctx:add(ca.cacert, certs)
  srv_ctx:set_engine(openssl.engine('openssl'))
  srv_ctx:timeout(500)
  assert(srv_ctx:timeout() == 500)
  local t = assert(srv_ctx:session_cache_mode())
  srv_ctx:mode(true, "enable_partial_write", "accept_moving_write_buffer",
               "auto_retry", "no_auto_chain")
  srv_ctx:mode(false, "enable_partial_write", "accept_moving_write_buffer",
               "auto_retry", "no_auto_chain")

  srv_ctx:set_session_callback(function(...)
    -- add
    print('set session')
    print(...)
  end, function(...)
    -- get
    print('get session')
    print(...)
  end, function(...)
    -- del
    print('del session')
    print(...)
  end)
  srv_ctx:flush_sessions(10000)

  repeat
    cs, ec = cli:handshake()
    rs, es = srv:handshake()
  until (rs and cs) or (rs == nil or cs == nil)
  assert(rs and cs)
  i, o = cli:pending()
  local msg = openssl.random(20)
  cli:write(msg)
  srv:write(srv:read())
  local got = cli:read()
  assert(got == msg)
  local peer = cli:peer()
  assert(peer:subject():oneline() == "/CN=server/C=CN")
  sess = cli:session()
  cli:shutdown()
  srv:shutdown()
  bs:close()
  bc:close()

  bs, bc = bio.pair()
  srv = assert(srv_ctx:ssl(bs, true))
  cli = assert(cli_ctx:ssl(bc, false))
  cli:set('hostname', 'serverB')
  cli:session(sess)
  repeat
    cs, ec = cli:handshake()
    rs, es = srv:handshake()
  until (rs and cs) or (rs == nil or cs == nil)
  assert(rs and cs)
  assert(peer:subject():oneline() == "/CN=server/C=CN")
  rc, ec = cli:renegotiate()
  rs, es = srv:renegotiate_abbreviated()
  print(cli:renegotiate_pending())
  assert(cli:read() == false)
  assert(srv:read() == false)
  repeat
    cs, ec = cli:handshake()
    rs, es = srv:handshake()
  until (rs and cs) or (rs == nil or cs == nil)
  assert(rs and cs)
  cli:write(msg)
  srv:write(srv:read())
  got = cli:read()
  assert(got == msg)
  peer = cli:peer()
  cli:shutdown('read')
  cli:shutdown('write')
  cli:shutdown('quiet')
  cli:shutdown('noquiet')
  cli:shutdown(true)
  cli:shutdown(false)
  assert(peer:subject():oneline() == "/CN=server/C=CN")
  bs:close()
  bc:close()

  local cert, pkey = helper.sign({{CN = "server"},  {C = "CN"}})

  bs, bc = bio.pair()
  srv = assert(srv_ctx:ssl(bs))
  srv:set_accept_state()
  cli = assert(cli_ctx:ssl(bc))
  cli:use(cert, pkey)
  cli:set_connect_state()
  cli:set('hostname', 'serverB')
  repeat
    cs, ec = cli:handshake()
    rs, es = srv:handshake()
    srv:want()
  until (rs and cs) or (rs == nil or cs == nil)
  assert(rs and cs)
  cli:write(msg)
  srv:write(srv:read())
  got = cli:peek()
  assert(got == msg)
  got = cli:read()
  assert(got == msg)
  peer = cli:peer()
  cli:current_compression()
  assert(peer:subject():oneline() == "/CN=serverB/C=CN")
  assert(cli:get('hostname') == 'serverB')
  sess = cli:session()
  local S = sess:export()
  S = ssl.session_read(S)
  assert(S)
  if sess.has_ticket then assert(type(sess:has_ticket()) == 'boolean') end
  if sess.is_resumable then assert(sess:is_resumable()) end
  assert(sess:peer())
  assert(sess:compress_id())
  assert(sess:timeout())
  assert(sess:timeout(500))
  assert(sess:time())
  assert(sess:time(50))
  assert(sess:id())
  local id = assert(sess:id())
  sess:id(id)
  cli:getpeerverification()
  cli:get('version')
  cli:get('certificate')
  cli:get('client_CA_list')
  cli:get('fd')
  cli:get('rfd')
  cli:get('wfd')
  cli:get('read_ahead')
  cli:get('shared_ciphers')
  cli:get('cipher_list')
  cli:get('verify_mode')
  cli:get('verify_depth')
  cli:get('state_string')
  cli:get('state_string_long')
  cli:get('rstate_string')
  cli:get('rstate_string_long')
  cli:get('iversion')
  cli:get('version')
  cli:get('default_timeout')
  cli:get('verify_result')
  cli:get('state')
  cli:get('state_string')
  cli:get('side')

  cli:cache_hit()
  cli:session_reused()

  local D = cli:dup()
  assert(D)

  local ctx = cli:ctx()
  assert(ctx)
  -- FIXME:
  -- cli:ctx(ctx)
  -- FIXME:
  srv_ctx:session(sess, true)
  srv_ctx:session(sess, false)
  srv_ctx:session(sess:id(), false)

  cli:clear()
  cli:shutdown()

  bs:close()
  bc:close()

  sess = ssl.session_new()
  sess:id(id)
end
