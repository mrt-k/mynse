description = [[
The low interaction honeypot Dionaea is remotely detectable using information from the certificate used in the HTTPS and SIP-TLS services .
One can also calculate the uptime for Dionaea using the informaton in the certificate.

To the defence of the Dionaea developer this issue has been noted and written about. Although I understand the usability perspective the issue is still there for anyone who looks. 

http://carnivore.it/2011/04/13/convenience

Part of the script use code from another Nmap script created by: David Fifield
Although Dionaea is built for automatic attacks which would most likely not check the target before exploitation. 
However having a honeypot that can be easily finger printed could attract unwanted attention to the organization running the service. 

Thanks to Patrik Karlsson for his invaluable help during the research!
]]


--- Output:
--Host script results:
--| dionaea-detect-ssl: 
--|   Standard Dionaea certificat detected : commonName=Nepenthes Development Team/organizationName=dionaea.carnivore.it/countryName=DE
--|_  Dionaea daemon uptime: 11 days, 16:36:39.00

author = "Mikael Keri"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "default", "safe", "discovery" }

require 'sslcert'
require 'shortport'
require 'stdnse'

portrule = function(host, port)
    return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

function add_to_output(output_table, label, value, value_if_nil)
        if (value == nil and value_if_nil ~= nil) then
                value = value_if_nil
        end

        if (value ~= nil) then
                table.insert(output_table, string.format("%s: %s", label, value) )
        end
end

function table_find(t, value)
    local i, v
    for i, v in ipairs(t) do
        if v == value then
            return i
        end
    end
    return nil
end

local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
    "stateOrProvinceName", "countryName" }

function stringify_name(name)
    local fields = {}
    local _, k, v
    for _, k in ipairs(NON_VERBOSE_FIELDS) do
        v = name[k]
        if v then
            fields[#fields + 1] = string.format("%s=%s", k, v)
        end
    end
    return stdnse.strjoin("/", fields)
end

 function date_to_string(date)
        return os.date("%Y-%m-%d %H:%M:%S", os.time(date))
 end

action = function(host, port)
local  response = {}
    
 local status, cert = sslcert.getCertificate(host, port)
  local tm = {}
  tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec = date_to_string(cert.validity.notBefore):match("^(%d+)%-(%d+)%-(%d+) (%d+):(%d+):(%d+)$")
  local uptime = (os.time() - os.time(tm))

     local  days, hours, minutes, seconds, htime, mtime, stime
        days = math.floor(uptime / 86400)
        htime = math.fmod(uptime, 86400)
        hours = math.floor(htime / 3600)
        mtime = math.fmod(htime, 3600)
        minutes = math.floor(mtime / 60)
        stime = math.fmod(mtime, 60)
        seconds = stime / 1

      local  dayLabel

        if days == 1 then
                dayLabel = "day"
        else
                dayLabel = "days"
       end
  uptime =  string.format("%d %s, %d:%02d:%05.2f", days, dayLabel, hours, minutes, seconds)

      if(stringify_name(cert.subject)  == "commonName=Nepenthes Development Team/organizationName=dionaea.carnivore.it/countryName=DE") then 
             add_to_output( response, "Standard Dionaea certificat detected ",stringify_name(cert.subject)) 
             add_to_output( response, "Dionaea daemon uptime",uptime)   
         end

 return stdnse.format_output(true, response)
end

