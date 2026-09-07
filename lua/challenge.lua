-- Reusable module (require()'d) — not matched by nginx routing at all. `gate.lua` is the single
-- entry point for every request; it calls `challenge.serve()` directly (a plain function call,
-- not an internal redirect) whenever a request has no valid cookie.
--
-- The module body below (path derivation + template load) runs once per worker, the moment this
-- file is first require()'d — gate.lua requires it unconditionally on every request, and Lua's
-- require() caches a module after its first load, so this only actually executes once per
-- worker. No init_worker_by_lua_block wiring needed in nginx.conf; deriving the challenge path
-- (a SHA-256) and reading templates/challenge.html off disk don't happen on every render.
local core = require("core")
local crypto = require("crypto")
local config = require("config")

local challenge = {}

-- templates/ is a sibling of lua/, not something under nginx's own install prefix
-- (ngx.config.prefix()) — this project can be deployed anywhere, so the template path is found
-- relative to this file's own location instead of assumed relative to OpenResty itself.
local function templates_dir()
  local source = debug.getinfo(1, "S").source
  return (source:match("^@(.*/)") or "./") .. "../templates/"
end

-- Fails loudly on the first request a worker handles if config.lua is missing hmac_secret,
-- rather than serving with a blank/default secret. Deliberately no fallback default here: a
-- default secret would mean every install that forgets to set one signs cookies with a value an
-- attacker can just look up in this repo. (Trade-off vs. the old init_worker_by_lua_block
-- approach: a bad config now surfaces as a 500 on first request instead of a worker startup
-- failure — see CLAUDE.md.)
assert(
  config.hmac_secret and config.hmac_secret ~= "",
  "config.lua: hmac_secret is required (no default — see challenge.lua)"
)
challenge.path = core.derive_challenge_path(crypto.sha256, config.hmac_secret)

local f = assert(io.open(templates_dir() .. "challenge.html", "r"))
challenge.template = f:read("*a")
f:close()

-- The actual per-request handler. string.gsub returns a new string rather than mutating
-- challenge.template in place, so the cached template stays reusable across requests.
--
-- 503, not 403: this page isn't a rejection, it's "not verified yet, retry once the script
-- below finishes" — the client's own JS reloads the page momentarily and will get through.
-- 403 is reserved for an actual ban (not implemented yet — see CLAUDE.md's "Known gaps").
function challenge.serve()
  local html = challenge.template:gsub("{{script_path}}", challenge.path)
  ngx.status = 503
  ngx.header.content_type = "text/html; charset=utf-8"
  ngx.say(html)
end

return challenge
