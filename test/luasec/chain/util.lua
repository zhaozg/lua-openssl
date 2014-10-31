local print  = print
local ipairs = ipairs

local _ENV = {}

function _ENV.show(cert)
  print("Serial:", cert:serial())
  print("NotBefore:", cert:notbefore())
  print("NotAfter:", cert:notafter())
  print("--- Issuer ---")           

  for k, v in ipairs(cert:issuer():info()) do    
    for name,value in pairs(v) do
      print(name .. " = " .. value)
    end
  end

  print("--- Subject ---")
  for k, v in ipairs(cert:subject():info()) do
    for name,value in pairs(v) do
      print(name .. " = " .. value)
    end
  end
  print("----------------------------------------------------------------------")
end

return _ENV
