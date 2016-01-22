local lfs = require"lfs"

function attrdir (path)
    for file in lfs.dir(path) do
        if file ~= "." and file ~= ".." then
            local f = path..'/'..file
            local attr = lfs.attributes (f)
            assert (type(attr) == "table")
            if attr.mode == "directory" then
                attrdir (f)
            else
                if file~='run-test.lua' and string.match(file,".+%.lua") then
                    print ("\t run "..f)
                    dofile(f)
                end
            end
        end
    end
end

attrdir (".")
