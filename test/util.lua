function readfile(path)
        local f = assert(io.open(path,'r'))
        local ctx = f:read('*a')
        f:close()
        return ctx        
end


function savefile(file,data)
        local f = assert(io.open(file,'w'))
        f:write(data)
        f:close()
end


function dump(t,i)
        for k,v in pairs(t) do
                if(type(v)=='table') then
                        print( string.rep('\t',i),k..'={')
                                dump(v,i+1)
                        print( string.rep('\t',i),k..'=}')
                else
                        print( string.rep('\t',i),k..'='..tostring(v))
                end
        end
end


