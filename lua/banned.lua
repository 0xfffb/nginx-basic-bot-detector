-- Reusable module (require()'d) — not matched by nginx routing at all. `gate.lua` calls
-- `banned.serve()` directly whenever a request carries a validly-signed cookie whose payload says
-- is_bot == true. This is the one place 403 is actually used — see CLAUDE.md's "Status codes"
-- section for why 403 was reserved rather than used for the challenge/verify flow.
--
-- Same module-body-init pattern as challenge.lua/verify.lua: templates/banned.html is read once
-- per worker, the moment gate.lua's unconditional `require("banned")` first loads this module —
-- not on every banned request. No init_worker_by_lua_block wiring needed.
local banned = {}

-- templates/ is a sibling of lua/, not something under nginx's own install prefix — see the same
-- helper (and its comment) in challenge.lua for why.
local function templates_dir()
  local source = debug.getinfo(1, "S").source
  return (source:match("^@(.*/)") or "./") .. "../templates/"
end

local f = assert(io.open(templates_dir() .. "banned.html", "r"))
banned.template = f:read("*a")
f:close()

function banned.serve()
  ngx.status = 403
  ngx.header.content_type = "text/html; charset=utf-8"
  ngx.say(banned.template)
end

return banned
