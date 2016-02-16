description = [[
The low interaction honeypot Dionaea is remotely detectable using information in the response from the MySQL service.

Part of the script use code from another Nmap script created by: Patrik Karlsson

Although Dionaea is built for automatic attacks which would most likely not check the target before exploitation.
However having a honeypot that can be easily fingerprinted could attract unwanted attention to the organization running the service.

Thanks to Patrik Karlsson for his invaluable help during the research!

]]

author = "Mikael Keri"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'mysql'

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

    local socket = nmap.new_socket()
    local result = {}

    socket:set_timeout(5000)
   
        local status, response = socket:connect(host, port)
        status, response = mysql.receiveGreeting( socket )
      
        status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, "root", nil, response.salt )  
                     if status and response.errorcode == 0 then
                 status, query_result = mysql.sqlQuery( socket, "SELECT @@version" )
                   end
        socket:close()
              
                if(query_result == "Learn SQL!") then
                  findings = ("Dionaea MySQL service detected: " .. query_result)      
                end  
    return stdnse.format_output(true, findings)  
end
