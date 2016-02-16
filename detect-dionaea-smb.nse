description = [[
The low interaction honeypot Dionaea is remotely detectable using information from the SMB service.
The following two problems has been discovered:

1) The NetBIOS name is "hardcode" into the installation. One can changed it but few if any users change settings outside the configuration file
2) The system times remains the same over time and is set to the date/time when the honeypot was started.

Part of this script use code from other Nmap scripts created by: Thomas Buchanan and Ron Bowes

Although Dionaea is built for automatic attacks which would most likely not check the target before exploitation. 
However having a honeypot that can be easily finger printed could attract unwanted attention to the organization running the service. 

Thanks to Patrik Karlsson for his invaluable help during the research!

]]

--- Output:
--Host script results:
--| dionaea-detect-smb: 
--|   NetBIOS name indicates a Dionaea honeypot: HOMEUSER-3AF6FE
--|   Time does not update between request - R1:2012-03-09 20:08:40:  R2:2012-03-09 20:08:40
--|_  Dionaea daemon uptime: 0 days, 1:07:31.00


author = "Mikael Keri, Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require 'smb'
require 'stdnse'

hostrule = function(host)
    return smb.get_port(host) ~= nil
end

function add_to_output(output_table, label, value, value_if_nil)
    if (value == nil and value_if_nil ~= nil) then
        value = value_if_nil
    end
    
    if (value ~= nil) then
        table.insert(output_table, string.format("%s: %s", label, value) )
    end
end

action = function(host)
    local response = {}

    local status, result = smb.get_os(host)
    stdnse.sleep(2)
    local status, result2 = smb.get_os(host)

    local os_string, time_string, time_string2
     
       if (result['server'] == "HOMEUSER-3AF6FE") then
             add_to_output( response, "NetBIOS name indicates a Dionaea honeypot", result[ "server" ] )
        end
    
    if (result['date']) then
        time_string = string.format("%s", result['date'])
    end

    if (result2['date']) then
        time_string2 = string.format("%s", result2['date'])
        end
          
         if(time_string == time_string2) then
          add_to_output( response, "Time does not update between request - R1:" .. time_string, " R2:" ..time_string2 )
         end

  local tm = {}
  tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec = (time_string):match("^(%d+)%-(%d+)%-(%d+) (%d+):(%d+):(%d+)$")
  local uptime = (os.time() - os.time(tm))
   
     local days, hours, minutes, seconds, htime, mtime, stime
        days = math.floor(uptime / 86400)
        htime = math.fmod(uptime, 86400)
        hours = math.floor(htime / 3600)
        mtime = math.fmod(htime, 3600)
        minutes = math.floor(mtime / 60)
        stime = math.fmod(mtime, 60)
        seconds = stime / 1

        local dayLabel

        if days == 1 then
                dayLabel = "day"
        else
                dayLabel = "days"
        end

        uptime =  string.format("%d %s, %d:%02d:%05.2f", days, dayLabel, hours, minutes, seconds)
      if(time_string == time_string2) then
        add_to_output( response, "Dionaea daemon uptime", uptime)    
      end
    return stdnse.format_output(true, response)
end
