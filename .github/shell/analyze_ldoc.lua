#!/usr/bin/env luajit

--[[
analyze_ldoc.lua - LDoc Comment Analyzer for lua-openssl

This script analyzes LDoc comments in C source files to check their validity
and provide feedback for documentation improvement.

Usage: luajit .github/shell/analyze_ldoc.lua [OPTIONS] [PATH]

Dependencies: lpeg, lfs
Author: GitHub Copilot Assistant
]]

local lpeg = require("lpeg")
local lfs = require("lfs")

-- LPEG pattern utilities  
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Cc, Ct, Cs = lpeg.C, lpeg.Cc, lpeg.Ct, lpeg.Cs

-- Configuration options
local config = {
    verbose = false,
    max_issues_per_file = 50,
    show_undocumented_list = true,
    show_issues = true
}

-- Show help information
local function show_help()
    print("LDoc Documentation Analyzer")
    print("Usage: analyze_ldoc.lua [OPTIONS] [PATH]")
    print("")
    print("Options:")
    print("  -h, --help           Show this help message")
    print("  -v, --verbose        Enable verbose output")
    print("  --max-issues=N       Set maximum issues to show per file (default: 50)")
    print("  --no-issues          Don't show individual issues")
    print("  --no-undocumented    Don't show undocumented function lists")
    print("")
    print("PATH can be a directory (will analyze all .c files) or a specific .c file")
    print("If no PATH is provided, defaults to 'src' directory")
    print("")
    print("Examples:")
    print("  luajit analyze_ldoc.lua                    # Analyze src directory")
    print("  luajit analyze_ldoc.lua src/cipher.c       # Analyze single file")
    print("  luajit analyze_ldoc.lua -v src            # Verbose analysis")
    print("  luajit analyze_ldoc.lua --max-issues=10 src # Limit issues shown")
end

-- Parse command line arguments
local function parse_args(args)
    local path = "src"  -- Default path
    local i = 1

    while i <= #args do
        local arg = args[i]
        if arg == "-h" or arg == "--help" then
            show_help()
            os.exit(0)
        elseif arg == "-v" or arg == "--verbose" then
            config.verbose = true
        elseif arg == "--no-issues" then
            config.show_issues = false
        elseif arg == "--no-undocumented" then
            config.show_undocumented_list = false
        elseif arg:match("^--max%-issues=(%d+)$") then
            config.max_issues_per_file = tonumber(arg:match("^--max%-issues=(%d+)$"))
        elseif not arg:match("^%-") then
            -- This is the path argument
            path = arg
        else
            print("Unknown option: " .. arg)
            show_help()
            os.exit(1)
        end
        i = i + 1
    end

    return path
end

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
    local current_tag = nil
    local current_content = {}
    
    for _, line in ipairs(lines) do
        line = line:trim()
        if line:match("^@") then
            -- Save previous tag if any
            if current_tag then
                if not tags[current_tag] then
                    tags[current_tag] = {}
                end
                table.insert(tags[current_tag], table.concat(current_content, " "):trim())
                current_content = {}
            end
            
            in_description = false
            local tag, content = line:match("^@(%w+)%s*(.*)")
            if tag then
                current_tag = tag
                if content and content:trim() ~= "" then
                    table.insert(current_content, content)
                end
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
    
    if config.verbose then
        printf("File size: %d bytes", #content)
    end
    
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
           line_text:match("^%s*/") or
           line_text:match("^%s*return") or
           line_text:match("^%s*if%s*%(") or
           line_text:match("^%s*while%s*%(") or
           line_text:match("^%s*for%s*%(") then
            return false
        end
        
        -- Skip common non-function patterns
        if func_name:match("^[A-Z_]+$") or -- All caps constants
           func_name:match("^%d") or -- Starts with number
           func_name == "return" or
           func_name == "if" or
           func_name == "while" or
           func_name == "for" or
           func_name == "switch" then
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
        local line_end = func_start
        for i = func_start, #content do
            if content:sub(i, i) == '\n' then
                line_end = i - 1
                break
            end
        end
        local line_text = content:sub(line_start, line_end)
        
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
    
    if config.verbose then
        printf("Starting comment validation...")
    end
    
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
            -- Module documentation - should have usage
            if not parsed.tags.usage or (parsed.tags.usage and #parsed.tags.usage > 0 and parsed.tags.usage[1]:trim() == "") then
                table.insert(comment_issues, "Module missing @usage example")
                valid = false
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
                    valid = false
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
            if config.verbose then
                printf(colored("green", "✓ Comment at line %d: Valid"), comment.line_num)
            end
        else
            if config.verbose then
                printf(colored("yellow", "⚠ Comment at line %d: Issues found"), comment.line_num)
                for _, issue in ipairs(comment_issues) do
                    printf(colored("yellow", "  - %s"), issue)
                end
            end
            for _, issue in ipairs(comment_issues) do
                table.insert(file_issues, string.format("Line %d: %s", comment.line_num, issue))
            end
        end
    end
    
    stats.documented_functions = stats.documented_functions + documented_function_count
    
    -- Report undocumented functions
    local undocumented = function_count - documented_function_count
    if undocumented > 0 then
        if config.show_undocumented_list then
            printf(colored("red", "⚠ %d functions are undocumented"), undocumented)
        end
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
-- Main function to analyze path (file or directory)
local function analyze_path(path)
    printf(colored("bold", "LDoc Comment Analyzer for lua-openssl"))
    
    -- Check if path exists
    local attr = lfs.attributes(path)
    if not attr then
        printf(colored("red", "Error: Path %s does not exist"), path)
        os.exit(1)
    end
    
    local c_files = {}
    
    if attr.mode == "directory" then
        printf("Analyzing directory: %s\n", path)
        
        -- Scan for C files in directory
        for file in lfs.dir(path) do
            if file:match("%.c$") then
                local filepath = path .. "/" .. file
                table.insert(c_files, filepath)
            end
        end
        
        table.sort(c_files)
        
        if #c_files == 0 then
            printf(colored("yellow", "No C files found in directory %s"), path)
            return
        end
        
    elseif attr.mode == "file" then
        if not path:match("%.c$") then
            printf(colored("red", "Error: %s is not a C source file"), path)
            os.exit(1)
        end
        
        printf("Analyzing file: %s\n", path)
        table.insert(c_files, path)
    else
        printf(colored("red", "Error: %s is neither a file nor a directory"), path)
        os.exit(1)
    end
    
    printf("Found %d C file%s to analyze\n", #c_files, #c_files == 1 and "" or "s")
    
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
    if config.show_issues and next(stats.issues) then
        printf(colored("yellow", "\nISSUES FOUND:"))
        for filepath, issues in pairs(stats.issues) do
            printf(colored("yellow", "\n%s:"), filepath)
            local issue_count = 0
            for _, issue in ipairs(issues) do
                if issue_count < config.max_issues_per_file then
                    printf(colored("yellow", "  • %s"), issue)
                    issue_count = issue_count + 1
                else
                    local remaining = #issues - issue_count
                    if remaining > 0 then
                        printf(colored("yellow", "  • ... and %d more issues"), remaining)
                    end
                    break
                end
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
        -- Check if any analyzed file contains this priority file name
        local found = false
        for filepath, _ in pairs(stats.issues) do
            if filepath:match(file .. "$") then
                printf(colored("red", "• High priority: Fix documentation in %s (mentioned in TODO.md)"), file)
                found = true
                break
            end
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

-- Main execution
local source_path = parse_args(arg)
analyze_path(source_path)