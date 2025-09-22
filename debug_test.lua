#!/usr/bin/env lua5.4

local lpeg = require("lpeg")

-- LPEG pattern utilities
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Cc, Ct, Cs = lpeg.C, lpeg.Cc, lpeg.Ct, lpeg.Cs

-- Define basic LPEG patterns
local nl = P("\n") + P("\r\n") + P("\r")
local alpha = R("az", "AZ")
local digit = R("09")
local alnum = alpha + digit
local ws = lpeg.S(" \t")^0
local identifier = (lpeg.R("az", "AZ") + lpeg.P("_")) * (lpeg.R("az", "AZ", "09") + lpeg.P("_"))^0

-- LPEG pattern for any @tag
local at_tag = P("@") * C(identifier) * ws * C((1 - nl - P("@"))^0)

-- String trim function
function string:trim()
    return self:match("^%s*(.-)%s*$")
end

-- Parse LDoc comment for tags using LPEG
local function parse_ldoc_comment(comment_text)
    local tags = {}
    local description = ""
    local lines = {}

    -- Split into lines and clean them
    for line in comment_text:gmatch("[^\r\n]+") do
        -- Remove leading * and whitespace using LPEG pattern
        local clean_line_pattern = ws * P("*")^-1 * ws * C((1 - P(-1))^0)
        local cleaned = clean_line_pattern:match(line)
        if cleaned then
            table.insert(lines, cleaned:trim())
        else
            table.insert(lines, line:trim())
        end
    end

    local in_description = true
    local current_tag = nil
    local current_content = {}

    for _, line in ipairs(lines) do
        -- Use LPEG to match @tag patterns
        local tag_name, tag_content = at_tag:match(line)
        if tag_name then
            -- Save previous tag if any
            if current_tag then
                if not tags[current_tag] then
                    tags[current_tag] = {}
                end
                table.insert(tags[current_tag], table.concat(current_content, " "):trim())
                current_content = {}
            end

            in_description = false
            current_tag = tag_name
            if tag_content and tag_content:trim() ~= "" then
                table.insert(current_content, tag_content:trim())
            end
        elseif current_tag then
            -- Continue collecting content for current tag
            if line ~= "" and not line:match("^[-=]+$") then
                table.insert(current_content, line)
            end
        elseif in_description and line ~= "" and not line:match("^[-=]+$") then
            if description ~= "" then
                description = description .. " "
            end
            description = description .. line
        end
    end

    -- Don't forget the last tag
    if current_tag then
        if not tags[current_tag] then
            tags[current_tag] = {}
        end
        table.insert(tags[current_tag], table.concat(current_content, " "):trim())
    end

    return {
        description = description,
        tags = tags,
        raw_lines = lines
    }
end

-- Test with the actual comment from mac.c line 280
local test_comment = [[
compute mac 
@function mac
@tparam evp_digest|string|nid digest digest alg identity
@tparam string message
@tparam string key
@treturn string result binary string
]]

print("Testing comment parsing...")
local parsed = parse_ldoc_comment(test_comment)

print("Description:", parsed.description)
print("Has function tag:", parsed.tags["function"] and "YES" or "NO")
print("Has treturn tag:", parsed.tags.treturn and "YES" or "NO")
print("Has return tag:", parsed.tags["return"] and "YES" or "NO")

if parsed.tags.treturn then
    print("Treturn content:", table.concat(parsed.tags.treturn, " "))
end

-- Test the validation logic
local has_return = parsed.tags.treturn or parsed.tags["return"]
print("Has return validation result:", has_return and "YES" or "NO")