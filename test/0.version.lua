--[[
Version interface: openssl.version() / openssl.version_ge()

What is checked here is not "the version number equals X" -- the exact number
varies per environment and hardcoding it would pin the tests to one OpenSSL
release, which is precisely the habit these tests exist to get rid of.

Three criteria:
  1. the numeric version and the textual version describe the same thing;
  2. the fields of the structured form agree with the text and the number;
  3. version_ge agrees with the ordering of version numbers (reflexive,
     monotonic, consistent across major bumps).
]]
local lu = require("luaunit")
local openssl = require("openssl")

-- Decode 0xMNNFFPPS / 0xMNN00PP0 into major/minor/patch.
-- patch is "the third number a human sees"; its position differs between the
-- two layouts:
--   3.x     0xMNN00PP0 -> bit4    (3.6.5 -> 5)
--   legacy  0xMNNFFPPS -> bit12   (1.0.2u -> 2)
-- LibreSSL keeps the legacy layout even when its major reaches 3.
local function unpack_version(num, libressl)
  local major = math.floor(num / 2 ^ 28) % 256
  local minor = math.floor(num / 2 ^ 20) % 256
  local patch
  if major >= 3 and not libressl then
    patch = math.floor(num / 2 ^ 4) % 256
  else
    patch = math.floor(num / 2 ^ 12) % 256
  end
  return major, minor, patch
end

TestVersion = {}

function TestVersion:testThreeReturnsUnchanged()
  local a, b, c = openssl.version()
  lu.assertIsString(a, "lua-openssl version should be a string")
  lu.assertIsString(b, "lua version should be a string")
  lu.assertIsString(c, "openssl version should be a string")
  lu.assertStrContains(b, "Lua")
  lu.assertNotNil(c:match("OpenSSL") or c:match("LibreSSL"),
    "version text is neither OpenSSL nor LibreSSL: " .. tostring(c))
end

function TestVersion:testNumericForm()
  local a, b, c = openssl.version(true)
  lu.assertIsNumber(a)
  lu.assertIsNumber(b)
  lu.assertIsNumber(c)
  lu.assertTrue(c > 0x10000000, "numeric version looks wrong: " .. tostring(c))
end

--- Key criterion: the text says 3.6.5, the number must say 3.6.5 as well
function TestVersion:testTextAndNumAgree()
  local _, _, text, info = openssl.version()
  local major, minor, patch = unpack_version(info.num, info.libressl)

  lu.assertEquals(info.text, text, "info.text should equal the 3rd return value")
  lu.assertEquals(info.major, major)
  lu.assertEquals(info.minor, minor)
  lu.assertEquals(info.patch, patch)

  -- the same three numbers must appear in the text
  local tmajor, tminor, tpatch = text:match("(%d+)%.(%d+)%.(%d+)")
  lu.assertNotNil(tmajor, "no x.y.z found in the version text: " .. text)
  lu.assertEquals(tonumber(tmajor), major, "major differs between text and number: " .. text)
  lu.assertEquals(tonumber(tminor), minor, "minor differs between text and number: " .. text)
  lu.assertEquals(tonumber(tpatch), patch, "patch differs between text and number: " .. text)
end

--- patch is the third semantic version field, not the legacy patch level
function TestVersion:testPatchIsSemantic()
  local _, _, text, info = openssl.version()
  local _, _, tpatch = text:match("(%d+)%.(%d+)%.(%d+)")
  lu.assertEquals(info.patch, tonumber(tpatch),
    "patch should equal the 3rd field of the text: " .. text .. " vs " .. tostring(info.patch))
  -- 3.x has no notion of patchlevel/status, both must be 0 there
  if info.major >= 3 and not info.libressl then
    lu.assertEquals(info.patchlevel, 0)
    lu.assertEquals(info.status, 0)
  end
end

function TestVersion:testInfoFields()
  local _, _, _, info = openssl.version()
  lu.assertIsNumber(info.num)
  lu.assertIsNumber(info.build_num)
  lu.assertIsString(info.text)
  lu.assertIsString(info.kind)
  lu.assertIsString(info.build_kind)
  lu.assertIsBoolean(info.libressl)
  lu.assertIsBoolean(info.matches_build)
  lu.assertIsBoolean(info.is_3_plus)

  lu.assertEquals(info.is_3_plus, info.num >= 0x30000000 and not info.libressl,
    "is_3_plus should be major >= 3 and not LibreSSL")
  lu.assertEquals(info.libressl, info.kind == "LibreSSL")
end

--- build_num of the structured form must agree with the 2nd calling convention
function TestVersion:testBuildNumConsistent()
  local _, _, num = openssl.version(true)
  local _, _, _, info = openssl.version()
  lu.assertEquals(info.num, num, "version() and version(true) should report the same number")

  -- matches_build() intentionally compares major.minor only for LibreSSL:
  -- its header constant and the runtime version text do not have to share the
  -- patch/status bytes, which would otherwise produce false mismatch alarms.
  local same_build
  if info.libressl then
    same_build = math.floor(info.num / 2 ^ 20) == math.floor(info.build_num / 2 ^ 20)
  else
    same_build = info.num == info.build_num
  end
  lu.assertEquals(info.matches_build, same_build,
    "matches_build should follow the documented build comparison")
end

function TestVersion:testGeSelf()
  local _, _, _, info = openssl.version()
  local major, minor, patch = unpack_version(info.num, info.libressl)
  lu.assertTrue(openssl.version_ge(major, minor, patch),
    "self >= self should hold: " .. info.text)
end

function TestVersion:testGeIsMonotonic()
  local _, _, _, info = openssl.version()
  local major, minor, patch = unpack_version(info.num, info.libressl)

  lu.assertTrue(openssl.version_ge(major, minor, math.max(0, patch - 1)),
    "a lower version should hold")
  lu.assertFalse(openssl.version_ge(major, minor, patch + 1),
    "a higher patch should not hold")
  lu.assertFalse(openssl.version_ge(major + 1, 0, 0),
    "a higher major should not hold")
  if major > 0 then
    lu.assertTrue(openssl.version_ge(major - 1, 99, 0),
      "a lower major should hold")
  end
end

function TestVersion:testGeAcceptsString()
  lu.assertTrue(openssl.version_ge("1.0.0"), "every version is >= 1.0.0")
  lu.assertTrue(openssl.version_ge("0.9.8"))
  lu.assertFalse(openssl.version_ge("99.0.0"), "99.0.0 cannot exist")
  lu.assertEquals(openssl.version_ge("1.0.0"), openssl.version_ge(1, 0, 0),
    "the string form and the numeric form should be equivalent")
  lu.assertErrorMsgContains("bad version string", openssl.version_ge, "abc")
end

function TestVersion:testGeBasicTiers()
  -- these thresholds are historical facts, any OpenSSL/LibreSSL in use meets them
  lu.assertTrue(openssl.version_ge(1, 0, 0), "1.0.0 at the very least")
  lu.assertTrue(openssl.version_ge("1.0.1"))
end
