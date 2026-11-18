// Immutable Lua admission action loaded by every HAProxy generation. Live counters are read from
// every worker through the master CLI, rather than copied at reload: leaving workers keep owning
// and decrementing their sessions. Pending admissions are tracked BEFORE this yielding action, so
// concurrent requests count each other conservatively. Inspection failure always denies admission.
export const L4_ADMISSION_LUA = String.raw`
local master = os.getenv("ARK_HAPROXY_MASTER_SOCKET") or "/var/run/haproxy/master.sock"
local function command(text)
  local s = core.tcp()
  s:settimeout(0.25)
  if not s:connect(master) then s:close(); error("admission master unavailable") end
  if not s:send(text .. "\nquit\n") then s:close(); error("admission send failed") end
  local data, err = s:receive("*a")
  s:close()
  if not data then error("admission read failed: " .. tostring(err)) end
  return data
end
local function workers()
  local data = command("show proc")
  local ids = {}
  for pid in data:gmatch("\n(%d+)%s+worker%s+") do ids[#ids + 1] = pid end
  if #ids == 0 then error("admission has no workers") end
  table.sort(ids)
  return ids
end
local function counters(pid, name, key)
  local data = command("@!" .. pid .. " show table " .. name .. " key " .. key)
  if data:find("No such table") then
    -- Workers from before this admission implementation can still hold this route. Refuse
    -- admission until they leave; absence of a counter is not evidence of zero sessions.
    local id = name:match("^ad_src_(.+)$") or name:match("^ad_total_(.+)$")
    local state = command("@!" .. pid .. " show servers state")
    if not state:find("# be_id", 1, true) then error("admission worker unavailable") end
    if state:find("%sbe_" .. id .. "[%s_]") then error("legacy route counters unavailable") end
    return 0, 0
  end
  -- A filtered lookup with no matching key returns only the master CLI terminator.
  if data:match("^%s*%.?%s*$") then return 0, 0 end
  if not data:find("# table:", 1, true) then error("admission table unavailable: " .. name .. ": " .. data) end
  local cur = tonumber(data:match("conn_cur=(%d+)")) or 0
  local rate = tonumber(data:match("conn_rate%(%d+%)=(%d+)")) or 0
  return cur, rate
end
core.register_action("ark-admit", {"tcp-req"}, function(txn, id, maxconn, perconn, perrate)
  txn:set_var("txn.ark_admitted", false)
  local ok, admitted = pcall(function()
    local before = workers()
    local total, source, rate = 0, 0, 0
    local key = txn.sf:src()
    -- The source table has IPv6 keys, including IPv4-mapped addresses.
    if not key:find(":", 1, true) then key = "::ffff:" .. key end
    for _, pid in ipairs(before) do
      local c, r = counters(pid, "ad_src_" .. id, key)
      source = source + c; rate = rate + r
      local n = counters(pid, "ad_total_" .. id, "1")
      total = total + n
    end
    local after = workers()
    if table.concat(before, ",") ~= table.concat(after, ",") then return false end
    return total <= tonumber(maxconn) and source <= tonumber(perconn) and rate <= tonumber(perrate)
  end)
  if not ok then txn:Warning("L4 admission inspection failed: " .. tostring(admitted)) end
  if ok and admitted then txn:set_var("txn.ark_admitted", true) end
end, 4)
`;
