# vpn-decryptor

Opens the encrypted config exports used by the popular tunnel clients and gives
back the profile inside — plus any share link it contains. Ships as an HTTP API
and a Telegram bot; both share the same core.

**Author:** [RayanErfan](https://github.com/RayanErfan)

## Formats

| Client | File / link | Status |
| --- | --- | --- |
| V2Box | `.v2box` | decode, incl. password-protected |
| HTTP Injector | `.ehi` | decode, incl. Argon2id + XChaCha20 envelope |
| HA Tunnel Plus | `.hat` | decode |
| NetMod | `.nm`, `nm-vless://`, `nm-vmess://`, … | decode (settings JSON or bare link) |
| SlipNet | `slipnet-enc://` | decode, profile v1–v28 |
| HTTP Custom | `.hc` | stream v2.6/2.7 + legacy CJK-XOR builds, password prompt |
| NPVT / NPVS | `.npvt`, `.npvtsub`, `.npvs` | not yet |

`.hc` files that carry a user password or a device lock are reported as
`password_required` instead of guessing: the payload is unreadable without the
secret. A password that also fails returns `bad_password` with an honest
"newer build or HWID lock" message. Everything else is decrypted in memory;
nothing is written to disk.

## Passwords

Password-protected exports are supported end to end. The password is read from
the post the file came with, so a forwarded caption like

```
🔓Password: @DigiHubAI
```

is enough: the bot and the API both pick it up from `caption`/`post` before
asking. If it is missing or wrong the bot asks once and retries the same file;
the API returns `password_required` (401) or `bad_password` (403) and the caller
sends `password` explicitly.

Labels understood: `password`, `passphrase`, `pass`, `pwd`, `pw`, `key`,
`secret`, `رمز`, `پسورد`, `پاسورد`, `کلید`, `کلمه عبور` — followed by `:`, `=`,
`->` or `➜`. Both the value and its `@`-stripped form are tried.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10 or newer.

## API

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

`POST /decrypt` accepts any of three body shapes:

```bash
# 1. file upload
curl -sS -F "file=@Amir.ehi" http://localhost:8000/decrypt

# 2. JSON — raw text, base64, and an optional password / caption
curl -sS -X POST http://localhost:8000/decrypt \
  -H 'content-type: application/json' \
  -d '{"text":"slipnet-enc://AWfgaefr...","name":"Amir"}'

# 3. raw body
curl -sS --data-binary @config.nm \
  'http://localhost:8000/decrypt?name=config.nm'

# 4. locked file with the password written in the post it came from
curl -sS -F "file=@locked.hc" \
  -F "caption=🔥 new drop
🔓Password: @DigiHubAI" http://localhost:8000/decrypt
```

Response:

```json
{
  "format": "ehi",
  "detected": "ehi",
  "links": ["vless://..."],
  "config": { "...": "..." },
  "notes": []
}
```

`links` may be empty — several clients (`.ehi` DNSTT profiles, `.hat`, `.nm`
settings) store connection parameters instead of a share URI. `config` then
holds the decoded document.

Errors always use the same envelope:

```json
{"error": {"code": "password_required", "message": "this V2Box export is password protected"}}
```

| Code | HTTP | Meaning |
| --- | --- | --- |
| `password_required` | 401 | send `password` and retry |
| `bad_password` | 403 | wrong password |
| `hardware_locked` | 403 | file bound to a device |
| `unsupported_format` | 415 | format known but not implemented |
| `not_encrypted` | 400 | plain config, nothing to do |
| `decrypt_failed` | 422 | corrupt or unrecognised data |

Other routes: `GET /health`, `GET /formats`, `GET /`.

Set `VPN_ALLOW_ORIGINS` (comma-separated) to enable CORS for a web front end.
Uploads are capped at 2 MiB.

## Bot

1. Create a bot with [@BotFather](https://t.me/BotFather).
2. Run it:

```bash
export BOT_TOKEN=123456:ABC...
python -m bot.main
```

Send a file, paste a `slipnet-enc://` / `nm-*://` link, or paste the whole
channel post — the link and the `Password: …` line are both taken from it.
Password-protected files are opened with the caption password automatically; if
it is missing or wrong the bot asks once and retries the pending document, which
is tracked per chat with aiogram FSM state.

### systemd

```ini
[Unit]
Description=vpn-decryptor api
After=network.target

[Service]
WorkingDirectory=/opt/vpn-decryptor
Environment=BOT_TOKEN=123456:ABC...
ExecStart=/opt/vpn-decryptor/.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Use `ExecStart=... python -m bot.main` in a second unit for the bot.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Fixtures are generated inside the tests, so no real config is checked in.

## How the formats work

Short notes, one per format, so the code stays readable:

- **V2Box** — JSON envelope, AES-256-GCM, app key or `sha256(password)`.
  Profiles are rebuilt into VLESS/Trojan/VMess/SS links.
- **HTTP Injector** — five layers: length-prefixed container, AES-256-CBC over
  one of six IVs, AES-128-CBC, XXTEA, then Argon2id + XChaCha20-Poly1305 with
  the container header as AAD. Field strings are XOR-masked per file.
- **HA Tunnel Plus** — base64 AES-128-ECB, key = SHA-1 of the import passphrase.
- **NetMod** — base64 AES-128-ECB with three build keys; plaintext is either a
  settings JSON or a bare URI whose scheme comes from the `nm-<proto>://` prefix.
- **SlipNet** — AES-256-GCM, version byte, 12-byte nonce, pipe-delimited profile.
- **HTTP Custom** — mask → hex → ChaCha20 JSON envelope, then per-token
  ChaCha20 / XOR / braille / decimal layers; older builds use a CJK-XOR + AES
  chain instead. Builds that no published scheme covers yet are reported as
  locked rather than mangled.

The format constants (keys, IVs, token order) are properties of each file
format. The implementations here were written from scratch for this project.

## Author

© 2026 RayanErfan — https://github.com/RayanErfan

All code in this repository is original work by the author above. No code was
copied from other decryptors; nothing here is derived from GPL or AGPL sources.
