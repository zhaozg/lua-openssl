#!/usr/bin/env lua5.4

local lpeg = require("lpeg")
local lfs = require("lfs")

-- Copy the exact same patterns and functions from the analyze tool
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Cc, Ct, Cs = lpeg.C, lpeg.Cc, lpeg.Ct, lpeg.Cs

local nl = P("\n") + P("\r\n") + P("\r")
local alpha = R("az", "AZ")
local digit = R("09")
local alnum = alpha + digit
local ws = lpeg.S(" \t")^0
local identifier = (lpeg.R("az", "AZ") + lpeg.P("_")) * (lpeg.R("az", "AZ", "09") + lpeg.P("_"))^0
local at_tag = P("@") * C(identifier) * ws * C((1 - nl - P("@"))^0)

function string:trim()
    return self:match("^%s*(.-)%s*$")
end

local function parse_ldoc_comment(comment_text)
    local tags = {}
    local description = ""
    local lines = {}

    for line in comment_text:gmatch("[^\r\n]+") do
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
        local tag_name, tag_content = at_tag:match(line)
        if tag_name then
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

-- Test with mac.c
local file = io.open("src/mac.c", "r")
local content = file:read("*a")
file:close()

print("=== Debugging mac.c comment parsing ===")

-- Find all LDoc comments
local comments = {}
local pos = 1
while pos <= #content do
    local start_pos = content:find("/***", pos)
    if not start_pos then break end
    
    -- Find the corresponding */ for this comment
    local end_pos = content:find("*/", start_pos + 4)
    if not end_pos then break end
    
    local comment_text = content:sub(start_pos + 4, end_pos - 1) -- Remove /*** and */
    table.insert(comments, {
        text = comment_text,
        start_pos = start_pos,
        end_pos = end_pos + 1,
        line_num = select(2, content:sub(1, start_pos):gsub('\n', '\n')) + 1
    })

    pos = end_pos + 2
end

print("Found", #comments, "comments")

-- Check each comment that has @function tag
for i, comment in ipairs(comments) do
    local parsed = parse_ldoc_comment(comment.text)
    
    if parsed.tags["function"] then
        print("\n--- Comment #" .. i .. " at line " .. comment.line_num .. " ---")
        print("Function name:", parsed.tags["function"][1] or "unnamed")
        print("Has treturn:", parsed.tags.treturn and "YES" or "NO")
        print("Has return:", parsed.tags["return"] and "YES" or "NO")
        
        -- Show first few lines of actual comment text to identify it
        local preview_lines = {}
        for line in comment.text:gmatch("[^\r\n]+") do
            table.insert(preview_lines, line)
            if #preview_lines >= 3 then break end
        end
        print("First 3 lines of comment:")
        for _, line in ipairs(preview_lines) do
            print("  " .. line)
        end
        
        local has_return = parsed.tags.treturn or parsed.tags["return"]
        if not has_return then
            print("*** MISSING @treturn/@return ***")
        else
            print("Return docs:", table.concat(parsed.tags.treturn or parsed.tags["return"] or {}, " "))
        end
    end
end