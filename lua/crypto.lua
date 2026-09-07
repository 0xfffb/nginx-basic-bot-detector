-- Wires core's injected-dependency functions to real implementations. Split out of
-- core.lua specifically so that file stays runnable under plain lua/luajit with zero
-- OpenResty dependencies (see core.lua (formerly had a companion test file; removed)) — only this file, and the two
-- nginx-phase-facing scripts that require it, need `resty.openssl`/`cjson` to actually exist.
local hmac = require("resty.openssl.hmac")
local digest = require("resty.openssl.digest")
local pkey = require("resty.openssl.pkey")
local cjson = require("cjson")

local M = {}

function M.sha256(data)
  local d = assert(digest.new("sha256"))
  assert(d:update(data))
  return assert(d:final())
end

function M.hmac_sha256(key, data)
  local h = assert(hmac.new(key, "sha256"))
  assert(h:update(data))
  return assert(h:final())
end

M.json_encode = cjson.encode
M.json_decode = cjson.decode

-- Matches the browser side's `crypto.subtle.encrypt({ name: "RSA-OAEP" }, ...)` with the key
-- imported via `{ hash: "SHA-256" }` — Web Crypto uses that one hash for both the OAEP digest
-- and the MGF1 digest, so both must be set to "sha256" here too or the padding check fails.
-- `private_key_pem` is PKCS8 PEM (`-----BEGIN PRIVATE KEY-----`); returns raw plaintext bytes,
-- or nil+err if the key is malformed or the ciphertext doesn't decrypt (wrong key, tampered
-- data, or a padding/hash mismatch between client and server).
function M.rsa_oaep_decrypt(private_key_pem, ciphertext)
  local key, err = pkey.new(private_key_pem)
  if not key then
    return nil, err
  end
  return key:decrypt(ciphertext, pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING, { oaep_md = "sha256", mgf1_md = "sha256" })
end

return M
