-- Pure logic, zero dependency on OpenResty's `ngx.*` API or any specific crypto library — every
-- function that needs HMAC/SHA-256 takes it as a plain `function(key, data) -> raw_bytes`
-- argument instead of `require`-ing a crypto lib directly. That's what makes this file runnable
-- (and testable) under plain `lua`/`luajit` with no nginx/OpenResty involved at all; the
-- nginx-facing glue in `gate.lua`/`verify.lua` (via `crypto.lua`) is what actually
-- wires in `resty.openssl`.
local M = {}

-- ===== base64url (RFC 4648 §5), no padding — plain Lua, no library needed =====

local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

function M.base64url_encode(data)
  local out = {}
  local len = #data
  local i = 1
  while i <= len do
    local b1, b2, b3 = data:byte(i, i + 2)
    b2 = b2 or 0
    b3 = b3 or 0
    local n = b1 * 65536 + b2 * 256 + b3

    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64

    out[#out + 1] = B64_CHARS:sub(c1 + 1, c1 + 1)
    out[#out + 1] = B64_CHARS:sub(c2 + 1, c2 + 1)
    if len - i >= 1 then
      out[#out + 1] = B64_CHARS:sub(c3 + 1, c3 + 1)
    end
    if len - i >= 2 then
      out[#out + 1] = B64_CHARS:sub(c4 + 1, c4 + 1)
    end
    i = i + 3
  end
  return table.concat(out)
end

local B64_DECODE_MAP = (function()
  local map = {}
  for i = 1, #B64_CHARS do
    map[B64_CHARS:sub(i, i)] = i - 1
  end
  return map
end)()

-- Returns `nil` on malformed input (bad character, invalid length) rather than raising, so
-- callers validating an untrusted cookie can just treat it as "not a valid token".
function M.base64url_decode(str)
  local clean = str:gsub("[^A-Za-z0-9%-_]", "")
  if #clean ~= #str then
    return nil
  end

  local out = {}
  local i = 1
  local len = #clean
  while i <= len do
    local c1 = B64_DECODE_MAP[clean:sub(i, i)]
    local c2 = B64_DECODE_MAP[clean:sub(i + 1, i + 1)]
    if c1 == nil or c2 == nil then
      return nil
    end
    local c3 = B64_DECODE_MAP[clean:sub(i + 2, i + 2)]
    local c4 = B64_DECODE_MAP[clean:sub(i + 3, i + 3)]

    local n = c1 * 262144 + c2 * 4096 + (c3 or 0) * 64 + (c4 or 0)

    out[#out + 1] = string.char(math.floor(n / 65536) % 256)
    if c3 ~= nil then
      out[#out + 1] = string.char(math.floor(n / 256) % 256)
    end
    if c4 ~= nil then
      out[#out + 1] = string.char(n % 256)
    end
    i = i + 4
  end
  return table.concat(out)
end

-- ===== constant-time comparison, to avoid leaking the secret via a timing side channel on
-- signature checks (same reasoning as the standalone gateway's `Mac::verify_slice` usage) =====
-- Uses LuaJIT's `bit` library rather than Lua 5.3+ bitwise operators (`|`, `~`) — OpenResty runs
-- on LuaJIT, whose native syntax predates those operators.

local bit_ok, bit = pcall(require, "bit")
if not bit_ok then
  bit = require("bit32") -- PUC-Lua 5.2 fallback, for running this file's tests outside LuaJIT
end

function M.constant_time_eq(a, b)
  if #a ~= #b then
    return false
  end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end

-- ===== challenge path derivation: SHA-256(secret .. "challenge"), first 6 bytes hex-encoded =====

function M.derive_challenge_path(sha256_fn, secret)
  local digest = sha256_fn(secret .. "challenge")
  local hex = {}
  for i = 1, 6 do
    hex[i] = string.format("%02x", digest:byte(i))
  end
  return "/" .. table.concat(hex)
end

-- ===== token issue/validate =====
-- Same scheme as the standalone gateway: base64url(json(payload)) .. "." .. base64url(HMAC-SHA256(payload)).
-- `json_encode`/`json_decode` are injected too (glue supplies `cjson`) to keep this file
-- dependency-free.

function M.issue_token(hmac_fn, json_encode, secret, is_bot, ttl_secs, now)
  local payload = json_encode({ iat = now, exp = now + ttl_secs, is_bot = is_bot })
  local payload_b64 = M.base64url_encode(payload)
  local sig = hmac_fn(secret, payload_b64)
  local sig_b64 = M.base64url_encode(sig)
  return payload_b64 .. "." .. sig_b64
end

-- Checks signature (constant-time) and expiry. Returns the embedded `is_bot` boolean, or `nil`
-- if the token is malformed, tampered, or expired — callers must check for `nil` explicitly
-- (not just truthiness) since a validly-signed "not a bot" token legitimately carries `false`.
function M.validate_token(hmac_fn, json_decode, secret, token, now)
  local dot = token:find(".", 1, true)
  if not dot then
    return nil
  end
  local payload_b64 = token:sub(1, dot - 1)
  local sig_b64 = token:sub(dot + 1)

  local sig = M.base64url_decode(sig_b64)
  if not sig then
    return nil
  end

  local expected_sig = hmac_fn(secret, payload_b64)
  if not M.constant_time_eq(sig, expected_sig) then
    return nil
  end

  local payload_json = M.base64url_decode(payload_b64)
  if not payload_json then
    return nil
  end

  local ok, payload = pcall(json_decode, payload_json)
  if not ok or type(payload) ~= "table" or type(payload.exp) ~= "number" or type(payload.is_bot) ~= "boolean" then
    return nil
  end

  if payload.exp < now then
    return nil
  end
  return payload.is_bot
end

-- ===== fingerprint rule check — no scoring, a plain boolean judgment =====
-- Matches templates/fingerprint.js's `{ automation: {...}, version, seed }` payload shape — a
-- plain OR of independent automation-framework signals (`automation.*`) plus a version check.
-- All of the `automation.*` signals are equally "hard" detections (an actual automation
-- framework/protocol marker, not a soft heuristic), so unlike the old rule set there's no single
-- signal worth short-circuiting on — they're just OR'd together.
--
-- EXPECTED_VERSION must be kept in sync with fingerprint.js's own `version: '1.0.0'` literal by
-- hand — there's no shared source of truth between the JS and Lua sides. A mismatch is treated as
-- a red flag itself: a request that doesn't send the current script's version is either running a
-- stale/cached copy or (more likely, since this is meant to be judged suspicious) a forged
-- payload that never actually ran fingerprint.js at all.
--
-- Returns `(is_bot, fired)` — `fired` lists exactly which signal(s) matched, e.g.
-- `{"automation.webdriver", "version-mismatch:0.9.0"}`, for logging.

local EXPECTED_VERSION = "1.0.0"

local AUTOMATION_SIGNALS = {
  "cdp", "webdriver", "headless", "selenium", "phantom", "puppeteer", "playwright",
}

function M.is_bot(fp)
  local fired = {}

  if fp.version ~= EXPECTED_VERSION then
    fired[#fired + 1] = "version-mismatch:" .. tostring(fp.version)
  end

  local automation = fp.automation
  if type(automation) ~= "table" then
    fired[#fired + 1] = "missing-automation"
  else
    for _, signal in ipairs(AUTOMATION_SIGNALS) do
      if automation[signal] == true then
        fired[#fired + 1] = "automation." .. signal
      end
    end
  end

  return #fired > 0, fired
end

-- ===== bypass prefix check =====

function M.matches_bypass_prefix(path, prefixes)
  for _, prefix in ipairs(prefixes) do
    if path:sub(1, #prefix) == prefix then
      return true
    end
  end
  return false
end

-- ===== comma-separated string -> list =====
-- nginx `set $var "a,b,c";` directives only ever hand Lua a single string; this is how
-- bypass_prefixes (configured that way in nginx.conf, not in config.lua — see example/nginx.conf)
-- turns back into a list. Empty segments are dropped so a trailing/leading comma is harmless.

function M.split_csv(str)
  local out = {}
  for item in (str or ""):gmatch("[^,]+") do
    out[#out + 1] = item
  end
  return out
end

return M
