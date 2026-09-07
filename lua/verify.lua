-- Reusable module (require()'d) — not matched by nginx routing at all. `gate.lua` is the single
-- entry point for every request; it compares `ngx.var.uri` against `verify.path` itself and only
-- calls `verify.serve()` when they match, so there's nothing left for this file to re-check.
--
-- GET serves fingerprint.js; POST accepts a posted fingerprint and always issues a signed
-- cookie (pass or fail — a fingerprint judged bot-like still gets tagged, not left without a
-- cookie). One path, method-multiplexed, so nothing about the URL itself distinguishes "serves a
-- script" from "accepts data".
--
-- The module body below (path derivation + fingerprint.js load) runs once per worker, the moment
-- this file is first require()'d — same reasoning as challenge.lua: gate.lua requires it
-- unconditionally on every request, and require() caches a module after its first load, so this
-- only actually executes once per worker. No init_worker_by_lua_block wiring needed in
-- nginx.conf.
local core = require("core")
local crypto = require("crypto")
local config = require("config")

local MAX_BODY_BYTES = 16 * 1024
local COOKIE_NAME = "__clr"

local verify = {}

-- templates/ is a sibling of lua/, not something under nginx's own install prefix — see the same
-- helper (and its comment) in challenge.lua for why.
local function templates_dir()
  local source = debug.getinfo(1, "S").source
  return (source:match("^@(.*/)") or "./") .. "../templates/"
end

-- Same reasoning as challenge.lua: fails loudly on the first request a worker handles if
-- hmac_secret is missing, rather than serving with a blank/default secret. Each module asserts
-- this independently rather than relying on any particular require() order.
assert(
  config.hmac_secret and config.hmac_secret ~= "",
  "config.lua: hmac_secret is required (no default — see challenge.lua)"
)
assert(
  config.rsa_private_key and config.rsa_private_key ~= "",
  "config.lua: rsa_private_key is required — must match the public key baked into fingerprint.js"
)
verify.path = core.derive_challenge_path(crypto.sha256, config.hmac_secret)

-- cookie_ttl_secs comes from config.lua, not nginx.conf — a plain table with no
-- request-context dependency, so it can be read here at module-load time like hmac_secret,
-- rather than per-request via ngx.var. Falls back to 3600 (1 hour) if left unset.
verify.cookie_ttl_secs = tonumber(config.cookie_ttl_secs) or 3600

local f = assert(io.open(templates_dir() .. "fingerprint.js", "r"))
verify.script = f:read("*a")
f:close()

-- The actual per-request handler.
function verify.serve()
  local method = ngx.req.get_method()

  if method == "GET" then
    ngx.header.content_type = "application/javascript; charset=utf-8"
    ngx.say(verify.script)
    return
  end

  if method ~= "POST" then
    return ngx.exit(405)
  end

  local cookie_ttl_secs = verify.cookie_ttl_secs

  -- Issues the cookie and ends the response — no body, pass or fail (see below). Every exit from
  -- this handler past read_body() goes through here, including the malformed-payload paths: a
  -- request that can't even produce a valid fingerprint (bad envelope, bad base64, a decrypt
  -- failure, or junk JSON after decrypt) isn't a real browser that ran fingerprint.js correctly
  -- either, so it's tagged is_bot=true and cookied exactly like a fingerprint that ran but failed
  -- core.is_bot's checks — not given a bare 4xx with no cookie. gate.lua enforces the verdict
  -- (banned.serve() on the next request) either way; see CLAUDE.md's "Status codes".
  local function issue_and_respond(is_bot)
    local token = core.issue_token(crypto.hmac_sha256, crypto.json_encode, config.hmac_secret, is_bot, cookie_ttl_secs, ngx.time())
    local cookie = string.format(
      "%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=Lax",
      COOKIE_NAME, token, cookie_ttl_secs
    )
    ngx.header["Set-Cookie"] = cookie
    -- No response body at all, pass or fail — the verdict isn't handed back to the client in any
    -- readable form beyond the cookie itself (see CLAUDE.md's "No response body on verify").
    ngx.status = 200
  end

  ngx.req.read_body()
  local raw_body = ngx.req.get_body_data()
  if not raw_body then
    -- Body was buffered to a temp file (larger than client_body_buffer_size) or genuinely empty.
    ngx.log(ngx.INFO, "verify: no body (tagging is_bot=true)")
    return issue_and_respond(true)
  end
  if #raw_body > MAX_BODY_BYTES then
    ngx.log(ngx.INFO, "verify: body too large (tagging is_bot=true)")
    return issue_and_respond(true)
  end

  -- The client wraps its RSA-OAEP-encrypted fingerprint as `{"data": "<base64 ciphertext>"}` —
  -- see templates/fingerprint.js's rsaEncrypt()/init(). Decrypt before touching core.is_bot at
  -- all; a payload that doesn't even parse as this envelope, isn't valid base64, or doesn't
  -- decrypt (wrong key, tampered, or an OAEP hash mismatch between client and server) is itself
  -- treated as a bot signal.
  local ok, envelope = pcall(crypto.json_decode, raw_body)
  if not ok or type(envelope) ~= "table" or type(envelope.data) ~= "string" then
    ngx.log(ngx.INFO, "verify: malformed envelope JSON (tagging is_bot=true)")
    return issue_and_respond(true)
  end

  local ciphertext = ngx.decode_base64(envelope.data)
  if not ciphertext then
    ngx.log(ngx.INFO, "verify: malformed base64 in envelope (tagging is_bot=true)")
    return issue_and_respond(true)
  end

  local plaintext, decrypt_err = crypto.rsa_oaep_decrypt(config.rsa_private_key, ciphertext)
  if not plaintext then
    ngx.log(ngx.INFO, "verify: rsa-oaep decrypt failed (tagging is_bot=true): ", decrypt_err)
    return issue_and_respond(true)
  end

  local ok2, fingerprint = pcall(crypto.json_decode, plaintext)
  if not ok2 or type(fingerprint) ~= "table" then
    ngx.log(ngx.INFO, "verify: malformed fingerprint JSON after decrypt (tagging is_bot=true)")
    return issue_and_respond(true)
  end

  local is_bot, fired = core.is_bot(fingerprint)
  if is_bot then
    ngx.log(ngx.INFO, "verify: failed (tagging is_bot=true) fired=", table.concat(fired, ","))
  else
    ngx.log(ngx.DEBUG, "verify: passed")
  end

  return issue_and_respond(is_bot)
end

return verify
