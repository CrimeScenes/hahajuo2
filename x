local threads = {}

local gc = getgc(true)
local detection_funcs = {}

-- Ensure islclosure function is available
local islclosure = islclosure or function(f) return type(f) == "function" end

-- Utility to check if a function appears more than once in a table
local has_function_more_than_once = function(func, t)
    local count = 0
    for i = 1, #t do
        if t[i] == func then
            count = count + 1
            if count > 1 then
                return true
            end
        end
    end
    return false
end

-- Loop through the GC to find potential detection functions
for i = 1, #gc do
    local collection = gc[i]

    if type(collection) == "function" and islclosure(collection) then
        local constants = debug.getconstants(collection)

        for _, constant in ipairs(constants) do
            if type(constant) == "string" and constant:lower():find("not enough memory") then
                local func_info = debug.getinfo(collection)
                if func_info and func_info.short_src:lower():find("corepackages") then
                    -- Get upvalues for the function and add them to detection_funcs if they are closures
                    for index, upvalue in debug.getupvalues(collection) do
                        if type(upvalue) == "function" and islclosure(upvalue) then
                            table.insert(detection_funcs, upvalue)
                        end
                    end
                end
            end
        end
    end
end

-- Find a valid detection function
local detection_func = nil
for i = 1, #detection_funcs do
    local func = detection_funcs[i]
    
    if has_function_more_than_once(func, detection_funcs) then
        detection_func = func
        break
    end
end

-- Hook the detected function if found
if detection_func then
    -- Use pcall to safely attempt hooking
    local success, err = pcall(function()
        hookfunction(detection_func, function(detection)
            print(string.format("tried detecting %s", tostring(detection)))
        end)
    end)
    
    if not success then
        print("Error hooking function:", err)
    end
else
    print("No valid detection function found to hook.")
end
