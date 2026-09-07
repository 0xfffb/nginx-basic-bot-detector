-- content_by_lua_file target for the single entry point, `location /` (see example/nginx.conf)
-- — the only location a client can reach directly. Everything dispatches from here:
--
--   1. Bypass prefix          -> forward.
--   2. Path is the challenge
--      endpoint (verify.path) -> require("verify").serve() — GET script / POST scoring.
--   3. Valid signed cookie,
--      is_bot == false        -> forward.
--   4. Valid signed cookie,
--      is_bot == true         -> require("banned").serve() — the 403 ban page.
--   5. Anything else
--      (no/invalid/expired
--      cookie)                -> require("challenge").serve() — the JS challenge page.
--
-- No is_bot request header — the verdict never leaves this file as something the upstream sees;
-- it's consumed right here to decide forward vs. ban. See CLAUDE.md's "No is_bot header" for why
-- there's still no such header even though the verdict is now acted on.
--
-- "Forward" means `ngx.exec("@upstream")`, not falling through to a `proxy_pass` configured on
-- this same location — this file runs in the *content* phase (needed so cases 2, 4, and 5 can
-- write a response body at all; confirmed by hand that access-phase Lua can't reliably do that,
-- see CLAUDE.md), and content phase doesn't have an implicit "then also proxy_pass" the way access
-- phase does. `@upstream` is a separate internal-only location whose only job is `proxy_pass`.
--
-- verify.serve()/challenge.serve()/banned.serve() are plain function calls, not further `ngx.exec`
-- hops — only the upstream-forwarding case needs an internal redirect, because only that case
-- needs to reach a *different* location (one with `proxy_pass`); the others are just Lua functions
-- that write to the response directly, already running in the same content phase as this file.
local core = require("core")
local crypto = require("crypto")
local config = require("config")
local verify = require("verify")
local challenge = require("challenge")
local banned = require("banned")

local COOKIE_NAME = "__clr"

local function extract_cookie(header, name)
  if not header then
    return nil
  end
  for pair in header:gmatch("[^;]+") do
    local key, value = pair:match("^%s*(.-)%s*=%s*(.-)%s*$")
    if key == name then
      return value
    end
  end
  return nil
end

-- bypass_prefixes is an nginx-level routing concern, not detection-policy config — set via
-- `set $bypass_prefixes "...";` in example/nginx.conf, not in config.lua.
local path = ngx.var.uri
if core.matches_bypass_prefix(path, core.split_csv(ngx.var.bypass_prefixes)) then
  return ngx.exec("@upstream")
end

if path == verify.path then
  return verify.serve()
end

local token = extract_cookie(ngx.var.http_cookie, COOKIE_NAME)

-- Still an explicit nil-check, not `token and validate_token(...)` — validate_token legitimately
-- returns `false` for a validly-signed "not a bot" token, and `false` is itself falsy in Lua, so
-- a truthy-based shortcut would treat that the same as "no valid cookie" by accident. Now that
-- is_bot is actually branched on (see below), getting this wrong would ban every clean cookie.
local is_bot = nil
if token then
  is_bot = core.validate_token(crypto.hmac_sha256, crypto.json_decode, config.hmac_secret, token, ngx.time())
end

if is_bot == false then
  return ngx.exec("@upstream")
end

if is_bot == true then
  ngx.log(ngx.INFO, "gate: banned — cookie is signed and unexpired but tagged is_bot=true")
  return banned.serve()
end

ngx.log(ngx.DEBUG, "gate: no valid cookie, serving challenge")
return challenge.serve()
