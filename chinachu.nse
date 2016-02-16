local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local unicode = require "unicode"

description = [[
Get to recorded full-title from Chinachu
]]

---
-- @usage
-- nmap --script chinachu-fulltitle -p10772 <host>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 12345/tcp open  netbus
-- | chinachu: 
-- |   Full Title: 無彩限のファントム・ワールド　第１話【新】
-- |   Full Title: 少女たちは荒野を目指す　第１話【新】
-- |   Full Title: 【新】僕だけがいない街＃１＜ノイタミナ＞【字】
-- |   Full Title: Fate/Zero　第十四話
-- |   Full Title: おそ松さん　＃１３
-- |   Full Title: 【新】だがしかし▽うまい棒とポテフと…▽コーヒー牛乳キャンディとヤングドーナツと…
-- |   Full Title: 紅殻のパンドラ　第１話【新】
-- |   Full Title: ヘヴィーオブジェクト　第13話
-- |   Full Title: 【新】アクティヴレイド　－機動強襲室第八係－　File1「コード№538」
-- |   ...
-----------------------------------------------------------------------

author = "Kouhei Morita"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


portrule = shortport.portnumber({12345,10772})

local PATH = stdnse.get_script_args(SCRIPT_NAME .. ".path")

local function parseRecordedTitle(recorded)
   local result = {}
   
   for k,v in ipairs(recorded) do
      table.insert(result, string.format("Full Title: %s", v.fullTitle))
   end

   return result
end

action = function(host, port)
   local answer = http.get(host, port, "/api/recorded.json")
   if answer.status ~= 200 then
      return nil
   end

   local status, json_data = json.parse(answer.body)
   if not status then
      return nil
   end

   return stdnse.format_output(true, parseRecordedTitle(json_data))
   
end
