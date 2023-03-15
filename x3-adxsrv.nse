local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Checks if an X3 AdxSrv service is present 
]]

---
-- @see 
-- @usage
-- nmap -p 50000 --script x3-adxsrv.nse <target>
--
-- @output
-- 50000/tcp open  
-- |x3-adxsrv: ADXSRV DETECTED

author = "@deadjakk"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

portrule = shortport.port_or_service (50000, "Sage X3 AdxSrv", {"tcp"})

action = function( host, port )

  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then 
      return
  end

  local one = "\x01\x00"

  socket:set_timeout(5000)

  socket:send(one)
  status, line = socket:receive_bytes(30)
  if not status then
      return 
  end

  if not string.sub(line,10,30) == "CreateProcess(AsUser)" then
     return 
  end

  if status then
    return "ADXSRV DETECTED" 
  end
  return
end
