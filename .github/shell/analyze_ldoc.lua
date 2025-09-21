#!/usr/bin/env luajit

--[[
analyze_ldoc.lua - LDoc Comment Analyzer for lua-openssl

This script analyzes LDoc comments in C source files to check their validity
and provide feedback for documentation improvement.

Usage: luajit .github/shell/analyze_ldoc.lua src

Dependencies: lpeg, lfs
Author: GitHub Copilot Assistant
]]

local lpeg = require("lpeg")
local lfs = require("lfs")

-- ANSI color codes for better output
local colors = {
    reset = "\27[0m",
    red = "\27[31m",
    green = "\27[32m",
    yellow = "\27[33m",
    blue = "\27[34m",
    magenta = "\27[35m",
    cyan = "\27[36m",
    bold = "\27[1m"
}

local function printf(fmt, ...)
    print(string.format(fmt, ...))
end

local function colored(color, text)
    return colors[color] .. text .. colors.reset
end

-- Statistics tracking
local stats = {
    total_files = 0,
    analyzed_files = 0,
    total_functions = 0,
    documented_functions = 0,
    total_comments = 0,
    valid_comments = 0,
    issues = {}
}

-- LDoc comment patterns using LPEG
local P, R, S, C, Ct, Cf, Cc = lpeg.P, lpeg.R, lpeg.S, lpeg.C, lpeg.Ct, lpeg.Cf, lpeg.Cc

-- Define basic patterns
local ws = S(" \t")^0
local nl = P("\n") + P("\r\n") + P("\r")
local comment_start = P("/***")
local comment_end = P("*/")
local non_star = (1 - P("*"))
local comment_line = P("*") * (1 - nl)^0 * nl^-1

-- LDoc tag patterns
local function tag_pattern(tagname)
    return P("@" .. tagname) * ws * (1 - nl - P("@"))^0
end

local ldoc_tags = {
    "module", "function", "tparam", "param", "treturn", "return", 
    "usage", "see", "author", "since", "deprecated", "local"
}

-- Pattern to match LDoc comment blocks
local ldoc_comment = comment_start * (comment_line + non_star)^0 * comment_end

-- Pattern to match function definitions
local function_pattern = P("static")^-1 * ws * 
                        (P("int") + P("void") + P("char") + P("const") + R("az", "AZ") * (R("az", "AZ", "09") + P("_"))^0) * ws *
                        (P("*"))^0 * ws *
                        C((R("az", "AZ") + P("_")) * (R("az", "AZ", "09") + P("_"))^0) * ws * P("(")

-- Parse LDoc comment for tags
local function parse_ldoc_comment(comment_text)
    local tags = {}
    local description = ""
    local lines = {}
    
    for line in comment_text:gmatch("[^\r\n]+") do
        line = line:gsub("^%s*%*%s?", "") -- Remove leading * and whitespace
        table.insert(lines, line)
    end
    
    local in_description = true
    for _, line in ipairs(lines) do
        if line:match("^@") then
            in_description = false
            local tag, content = line:match("^@(%w+)%s*(.*)")
            if tag then
                if not tags[tag] then
                    tags[tag] = {}
                end
                table.insert(tags[tag], content or "")
            end
        elseif in_description and line:trim() ~= "" then
            if description ~= "" then
                description = description .. " "
            end
            description = description .. line
        end
    end
    
    return {
        description = description,
        tags = tags,
        raw_lines = lines
    }
end

-- String trim function
function string:trim()
    return self:match("^%s*(.-)%s*$")
end

-- Analyze a single C file
local function analyze_file(filepath)
    local file = io.open(filepath, "r")
    if not file then
        printf(colored("red", "Error: Cannot open file %s"), filepath)
        return
    end
    
    local content = file:read("*a")
    file:close()
    
    stats.total_files = stats.total_files + 1
    stats.analyzed_files = stats.analyzed_files + 1
    
    printf(colored("cyan", "\n=== Analyzing %s ==="), filepath)
    
    local file_issues = {}
    local comment_count = 0
    local function_count = 0
    local documented_function_count = 0
    
    -- Find all LDoc comments
    local comments = {}
    local pos = 1
    while pos <= #content do
        local start_pos, end_pos = content:find("/***.-*/", pos)
        if not start_pos then break end
        
        local comment_text = content:sub(start_pos + 4, end_pos - 2) -- Remove /*** and */
        table.insert(comments, {
            text = comment_text,
            start_pos = start_pos,
            end_pos = end_pos,
            line_num = select(2, content:sub(1, start_pos):gsub('\n', '\n')) + 1
        })
        
        comment_count = comment_count + 1
        pos = end_pos + 1
    end
    
    printf("Found %d LDoc comment blocks", comment_count)
    stats.total_comments = stats.total_comments + comment_count
    
    -- Find all function definitions
    local functions = {}
    pos = 1
    
    -- Pattern to match C function definitions more accurately
    local function is_function_definition(line_text, func_name)
        -- Skip preprocessor directives, comments, and function calls
        if line_text:match("^%s*#") or 
           line_text:match("^%s*//") or 
           line_text:match("^%s*%*") or
           line_text:match("^%s*/") then
            return false
        end
        
        -- Must look like a function definition with return type
        return line_text:match("^%s*[%w_*%s]+%s+" .. func_name .. "%s*%(") or
               line_text:match("^%s*static%s+[%w_*%s]+%s+" .. func_name .. "%s*%(")
    end
    
    while pos <= #content do
        local func_start, func_end, func_name = content:find("([%w_]+)%s*%(", pos)
        if not func_start then break end
        
        -- Get the line containing this function
        local line_start = 1
        for i = func_start, 1, -1 do
            if content:sub(i, i) == '\n' then
                line_start = i + 1
                break
            end
        end
        local line_text = content:sub(line_start, func_end)
        
        if is_function_definition(line_text, func_name) then
            table.insert(functions, {
                name = func_name,
                start_pos = func_start,
                line_num = select(2, content:sub(1, func_start):gsub('\n', '\n')) + 1
            })
            function_count = function_count + 1
        end
        
        pos = func_end + 1
    end
    
    printf("Found %d function definitions", function_count)
    stats.total_functions = stats.total_functions + function_count
    
    -- Analyze each comment
    for i, comment in ipairs(comments) do
        local parsed = parse_ldoc_comment(comment.text)
        local valid = true
        local comment_issues = {}
        
        -- Check for required elements
        if not parsed.description or parsed.description:trim() == "" then
            table.insert(comment_issues, "Missing or empty description")
            valid = false
        end
        
        -- Check for function documentation
        if parsed.tags.module then
            -- Module documentation
            if not parsed.tags.usage then
                table.insert(comment_issues, "Module missing @usage example")
            end
        elseif parsed.tags["function"] then
            -- Function documentation
            documented_function_count = documented_function_count + 1
            
            -- Check parameters and return values
            local has_params = parsed.tags.tparam or parsed.tags.param
            local has_return = parsed.tags.treturn or parsed.tags["return"]
            
            -- Find corresponding function
            local next_func = nil
            for _, func in ipairs(functions) do
                if func.start_pos > comment.end_pos then
                    next_func = func
                    break
                end
            end
            
            if next_func then
                -- Basic validation for function documentation
                if not has_return then
                    table.insert(comment_issues, string.format("Function '%s' missing @treturn/@return documentation", next_func.name))
                end
            end
        end
        
        -- Check for common LDoc tag issues
        for tag, values in pairs(parsed.tags) do
            for _, value in ipairs(values) do
                if value:trim() == "" then
                    table.insert(comment_issues, string.format("Empty @%s tag", tag))
                    valid = false
                end
            end
        end
        
        if valid and #comment_issues == 0 then
            stats.valid_comments = stats.valid_comments + 1
            printf(colored("green", "✓ Comment at line %d: Valid"), comment.line_num)
        else
            printf(colored("yellow", "⚠ Comment at line %d: Issues found"), comment.line_num)
            for _, issue in ipairs(comment_issues) do
                printf(colored("yellow", "  - %s"), issue)
                table.insert(file_issues, string.format("Line %d: %s", comment.line_num, issue))
            end
        end
    end
    
    stats.documented_functions = stats.documented_functions + documented_function_count
    
    -- Report undocumented functions
    local undocumented = function_count - documented_function_count
    if undocumented > 0 then
        printf(colored("red", "⚠ %d functions are undocumented"), undocumented)
        table.insert(file_issues, string.format("%d undocumented functions", undocumented))
    end
    
    -- Store file issues
    if #file_issues > 0 then
        stats.issues[filepath] = file_issues
    end
    
    -- Summary for this file
    local doc_percentage = function_count > 0 and (documented_function_count / function_count * 100) or 0
    printf("Documentation coverage: %.1f%% (%d/%d functions)", doc_percentage, documented_function_count, function_count)
end

-- Main function to analyze directory
local function analyze_directory(dir_path)
    printf(colored("bold", "LDoc Comment Analyzer for lua-openssl"))
    printf("Analyzing directory: %s\n", dir_path)
    
    -- Check if directory exists
    local attr = lfs.attributes(dir_path)
    if not attr or attr.mode ~= "directory" then
        printf(colored("red", "Error: Directory %s does not exist"), dir_path)
        os.exit(1)
    end
    
    -- Scan for C files
    local c_files = {}
    for file in lfs.dir(dir_path) do
        if file:match("%.c$") then
            local filepath = dir_path .. "/" .. file
            table.insert(c_files, filepath)
        end
    end
    
    table.sort(c_files)
    
    if #c_files == 0 then
        printf(colored("yellow", "No C files found in directory %s"), dir_path)
        return
    end
    
    printf("Found %d C files to analyze\n", #c_files)
    
    -- Analyze each file
    for _, filepath in ipairs(c_files) do
        analyze_file(filepath)
    end
    
    -- Print overall summary
    printf(colored("bold", "\n" .. string.rep("=", 60)))
    printf(colored("bold", "ANALYSIS SUMMARY"))
    printf(colored("bold", string.rep("=", 60)))
    
    printf("Files analyzed: %d", stats.analyzed_files)
    printf("Total functions: %d", stats.total_functions)
    printf("Documented functions: %d", stats.documented_functions)
    printf("Total LDoc comments: %d", stats.total_comments)
    printf("Valid LDoc comments: %d", stats.valid_comments)
    
    local overall_doc_coverage = stats.total_functions > 0 and (stats.documented_functions / stats.total_functions * 100) or 0
    local comment_validity = stats.total_comments > 0 and (stats.valid_comments / stats.total_comments * 100) or 0
    
    printf(colored("cyan", "Overall documentation coverage: %.1f%%"), overall_doc_coverage)
    printf(colored("cyan", "Comment validity rate: %.1f%%"), comment_validity)
    
    -- Report issues by priority
    if next(stats.issues) then
        printf(colored("yellow", "\nISSUES FOUND:"))
        for filepath, issues in pairs(stats.issues) do
            printf(colored("yellow", "\n%s:"), filepath)
            for _, issue in ipairs(issues) do
                printf(colored("yellow", "  • %s"), issue)
            end
        end
    end
    
    -- Recommendations
    printf(colored("bold", "\nRECOMMENDATIONS:"))
    
    if overall_doc_coverage < 80 then
        printf(colored("red", "• Low documentation coverage (%.1f%%). Target: 80%%+"), overall_doc_coverage)
    end
    
    if comment_validity < 90 then
        printf(colored("red", "• Improve LDoc comment quality (%.1f%% valid). Target: 90%%+"), comment_validity)
    end
    
    -- Identify files mentioned in TODO.md as needing attention
    local priority_files = {"cipher.c", "digest.c", "kdf.c", "crl.c"}
    for _, file in ipairs(priority_files) do
        local filepath = dir_path .. "/" .. file
        if stats.issues[filepath] then
            printf(colored("red", "• High priority: Fix documentation in %s (mentioned in TODO.md)"), file)
        end
    end
    
    printf(colored("green", "• Use consistent LDoc tags: @module, @function, @tparam, @treturn"))
    printf(colored("green", "• Add @usage examples for all modules"))
    printf(colored("green", "• Ensure all public functions have complete documentation"))
    
    -- Exit with appropriate code
    if overall_doc_coverage < 50 or comment_validity < 70 then
        printf(colored("red", "\nDocumentation quality needs significant improvement!"))
        os.exit(1)
    elseif overall_doc_coverage < 80 or comment_validity < 90 then
        printf(colored("yellow", "\nDocumentation quality could be improved."))
        os.exit(0)
    else
        printf(colored("green", "\nDocumentation quality is good!"))
        os.exit(0)
    end
end

-- Command line argument handling
if #arg < 1 then
    print("Usage: luajit analyze_ldoc.lua <source_directory>")
    print("Example: luajit .github/shell/analyze_ldoc.lua src")
    os.exit(1)
end

local source_dir = arg[1]
analyze_directory(source_dir)