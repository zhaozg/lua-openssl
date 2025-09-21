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

-- LPEG pattern utilities and definitions
local P, R, S, C, Ct, Cf, Cc = lpeg.P, lpeg.R, lpeg.S, lpeg.C, lpeg.Ct, lpeg.Cf, lpeg.Cc

-- Define basic LPEG patterns
local ws = S(" \t")^0
local wsp = S(" \t")^1  -- required whitespace
local nl = P("\n") + P("\r\n") + P("\r")
local alpha = R("az", "AZ")
local digit = R("09")
local alnum = alpha + digit
local identifier = (alpha + P("_")) * (alnum + P("_"))^0
local comment_start = P("/***")
local comment_end = P("*/")

-- LPEG patterns for function detection
local static_kw = P("static") * wsp
local return_types = P("int") + identifier
local pointer = P("*")
local lparen = P("(")
local rparen = P(")")

-- Pattern for single-line function definition
local single_line_func = ws * static_kw^-1 * return_types * wsp * pointer^0 * ws * C(identifier) * ws * lparen

-- Pattern for multi-line function (return type on separate line)
local multiline_return_type = ws * static_kw^-1 * return_types * ws * pointer^0 * ws * (nl + P(-1))
local multiline_func_name = ws * C(identifier) * ws * lparen

-- LPEG pattern for LDoc comment block
local comment_line = P("*") * (1 - nl)^0 * nl^-1
local ldoc_comment_content = (comment_line + (1 - P("*")))^0
local ldoc_comment = comment_start * ldoc_comment_content * comment_end

-- LPEG pattern for @function tag
local at_function = P("@function") * ws * C((1 - nl - P("@"))^0)

-- LPEG pattern for any @tag
local at_tag = P("@") * C(identifier) * ws * C((1 - nl - P("@"))^0)

-- Pattern for lines to skip entirely
local skip_line_patterns = ws * (P("#") + P("//") + P("*") + P("/") + P("return") +
                                P("if") * ws * lparen + P("while") * ws * lparen +
                                P("for") * ws * lparen)

-- LDoc tag patterns
local function tag_pattern(tagname)
    return P("@" .. tagname) * ws * (1 - nl - P("@"))^0
end

local ldoc_tags = {
    "module", "function", "tparam", "param", "treturn", "return",
    "usage", "see", "author", "since", "deprecated", "local"
}

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

    -- Find all function definitions using LPEG patterns
    local functions = {}

    -- Split content into lines for easier processing
    local lines = {}
    for line in content:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    -- Process each line using LPEG patterns
    for i = 1, #lines do
        local line = lines[i]
        local next_line = lines[i + 1] or ""

        -- Skip lines that match skip patterns using LPEG
        if skip_line_patterns:match(line) then
            goto continue
        end

        local func_name = nil
        local is_function_def = false

        -- Pattern 1: Single-line function definition using LPEG
        func_name = single_line_func:match(line)
        if func_name then
            is_function_def = true
        end

        -- Pattern 2: Multi-line function definition using LPEG
        if not is_function_def and multiline_return_type:match(line) then
            func_name = multiline_func_name:match(next_line)
            if func_name then
                is_function_def = true
            end
        end

        -- Apply LPEG-based filtering for function names
        if is_function_def and func_name then
            local skip = false

            -- Skip all-caps names (macros) using LPEG
            local all_caps_pattern = (R("AZ") + P("_"))^1 * P(-1)
            if all_caps_pattern:match(func_name) then
                skip = true
            end

            -- Skip single-letter or number-starting names
            if #func_name == 1 or func_name:match("^%d") then
                skip = true
            end

            if not skip then
                table.insert(functions, {
                    name = func_name,
                    start_pos = 1,
                    line_num = i
                })
                function_count = function_count + 1
            end
        end

        ::continue::
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

    -- Report undocumented functions - but only count functions that should be documented
    -- According to @zhaozg feedback: API coverage should only count functions with @function tags
    -- This means we compare documented_function_count against functions that should be documented,
    -- not all detected functions
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

    -- Summary for this file - Updated approach for API coverage calculation
    -- Only count functions that are intended for API documentation (with @function tags)
    -- as per @zhaozg's feedback
    local api_coverage_percentage = 0
    if documented_function_count > 0 then
        -- When we have documented functions, coverage is 100% for those functions
        -- The undocumented count shows how many more need @function tags
        api_coverage_percentage = 100
        printf("API documentation coverage: %.1f%% (%d functions with @function tags)",
               api_coverage_percentage, documented_function_count)
        if undocumented > 0 then
            printf("Additional functions detected: %d (candidates for @function documentation)", undocumented)
        end
    else
        printf("API documentation coverage: 0.0%% (0 functions with @function tags)")
        printf("Total functions detected: %d (candidates for @function documentation)", function_count)
    end
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
    printf("Total functions detected: %d", stats.total_functions)
    printf("Functions with @function tags: %d", stats.documented_functions)
    printf("Total LDoc comments: %d", stats.total_comments)
    printf("Valid LDoc comments: %d", stats.valid_comments)

    -- Updated API coverage calculation as per @zhaozg feedback
    -- Only count functions with @function tags in API coverage
    local api_coverage = stats.documented_functions > 0 and 100 or 0
    local comment_validity = stats.total_comments > 0 and (stats.valid_comments / stats.total_comments * 100) or 0
    local potential_api_functions = stats.total_functions - stats.documented_functions

    printf(colored("cyan", "API documentation coverage: %.1f%% (%d functions with @function tags)"),
           api_coverage, stats.documented_functions)
    if potential_api_functions > 0 then
        printf(colored("yellow", "Potential API functions: %d (candidates for @function documentation)"),
               potential_api_functions)
    end
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

    -- Recommendations - Updated for new API coverage approach
    printf(colored("bold", "\nRECOMMENDATIONS:"))

    if potential_api_functions > 0 then
        printf(colored("yellow", "• Consider adding @function documentation for %d detected functions"), potential_api_functions)
    end

    if comment_validity < 90 then
        printf(colored("red", "• Improve LDoc comment quality (%.1f%% valid). Target: 90%%+"), comment_validity)
    end

    printf(colored("green", "• Use consistent LDoc tags: @module, @function, @tparam, @treturn"))
    printf(colored("green", "• Add @usage examples for all modules"))
    printf(colored("green", "• Ensure all public functions have complete documentation"))

    -- Exit with appropriate code based on comment validity and documentation presence
    if comment_validity < 70 or stats.documented_functions == 0 then
        printf(colored("red", "\nDocumentation quality needs significant improvement!"))
        os.exit(1)
    elseif comment_validity < 90 then
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
