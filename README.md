# Universal Cookie / Session Tool

Single interactive CLI for **decoding, verifying, brute-forcing and re-encoding** all common web session cookies — `JWT`, `Flask/Django (itsdangerous)`, `Express`, `Generic HMAC`, `AES-CBC`, `Base64` — with **auto SecLists wordlist selection** and **tamper loop**.

**Location:** 
```
/universal-cookie-tool.py
```
Run from either:
```bash
cd ~/TOOLS/sess_enc_dec
python3 universal-cookie-tool.py
# or
python3 /home/kali/TOOLS/universal-cookie-tool.py
/usr/bin/python3 universal-cookie-tool.py  # if venv python used
```

---

## Features
- **Only 2 options** → rest auto: `1. Decode` / `2. Encode`
- **Auto-detect** algorithm from token format
- **Without secret** → shows `Header/Payload JSON` + `Algorithm name` (for tampering)
- **With secret** → `Valid ✅ / Invalid ❌` (like jwt.io, with `BASE64URL` toggle)
- **Tamper loop** → decoded JSON shown pretty → choose `Paste` or `Open in editor (nano/vim)` with arrow keys → re-encode with same/new alg/secret
- **Auto brute-force** → auto-picks `SecLists` based on type (`scraped-JWT-secrets.txt` for JWT, `rockyou.txt` for Flask/Express/HMAC/AES) — just press Enter
- **Auto-fix JSON** → `'` → `"` and `=` → `:` (e.g. `{"id"=22}` → `{"id":22}`)

---

## Supported Cookies / Sessions

| Type | Example | Detection | Notes |
|------|---------|-----------|-------|
| **JWT** `HS256/384/512` `RS256` `none` | `eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjo...N4AigW...` | `eyJ` + 2 dots + `alg` in header | `none` tested, `BASE64URL` toggle supported |
| **Flask / Django** `itsdangerous` | `eyJ1c2VyIjo...arDmhA.wJHh...` | 3 parts | `HMAC-SHA1` |
| **Flask Compressed** `dot` | `.eJyrViot...arDmhA.wJHh...` | leading `.` + 3 `.` | `zlib` decompressed |
| **Flask Compressed** `colon` **(fixed)** | `.eJyrViot...:1x8Z6q:y7pk...` | leading `.` + 2 `:` | same payload, `:` replaced with `.` for decode |
| **Express** `s:` | `s:abc123sessionid.ZulUOQ7...` | `s:` prefix | `HMAC-SHA256` of `value`, plain value not base64 |
| **Generic HMAC** | `eyJ1c2Vy...AYOSxBE...` | `data.sig` hex/base64 | tries `SHA1/256/512/MD5` |
| **AES-256-CBC** | `zk qFIPG7... (base64 len%16==0)` | random base64 | `IV(16)+CT`, key=`SHA256(secret)` |
| **Base64/Hex** | `eyJ1c2VyIjo...`, `61646d696e` | plain | decoded directly |

`UNKNOWN` → shown as raw + length, fallback tries JWT.

---

## Installation
```bash
chmod +x universal-cookie-tool.py
# optional for AES + Flask verification:
pip install pycryptodome itsdangerous --break-system-packages
# or for venv:
uv pip install pycryptodome --python /opt/newpt/tools/venv/bin/python3
# SecLists already on Kali:
ls /usr/share/seclists/Passwords/scraped-JWT-secrets.txt
ls /usr/share/wordlists/rockyou.txt  # if gz: sudo gzip -d .../rockyou.txt.gz
```

---

## Usage

### 1. Decode (you HAVE a token)
```
Choice: 1
Paste Token/Session Cookie: .eJyrViotTi2Kz0xRsjI0NjbXAXPzEnNTlayUElNyM_OUdJSK8nMQ3FoAnVoQMA:1x8Z6q:y7pkb6Qev3wZmuKpedLOSQ6Qqho
[*] Detected: FLASK | itsdangerous-compressed
[Decoded Payload] {"user_id":1337,"username":"admin","role":"admin"}
[Algorithm] itsdangerous-HMAC-SHA1

Enter Secret/Key (press Enter for WITHOUT secret):  [Enter]
[*] Without secret mode...
Do you want to BRUTE-FORCE now? [Y/n]: Y  -> auto picks rockyou.txt -> FOUND

Do you want to tamper? [y/N]: y
Current JSON:
{
  "user_id": 1337,
  "username": "admin",
  "role": "admin"
}
How to edit?
  1. Paste new JSON [Enter]
  2. Open in editor (nano/vim) - arrow keys
Choice [1/2]: 2  -> nano opens -> edit id/role -> Ctrl+O Enter Ctrl+X
Choice [1]: 1 -> Keep same alg (flask) -> new token + Cookie header
```

**Express example:**
```
Paste: s:abc123sessionid.ZulUOQ7ArQrtSXyJZ6XnMavWISFv9EWj5rpoxLr9TXM
[*] Detected: EXPRESS | HMAC-SHA256
[Decoded Payload] {"value":"abc123sessionid"}
Enter Secret: mysecret -> Valid ✅ -> tamper value -> encode via Express
```

**JWT example (your previous Invalid Signature):**
```
Paste: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpZCI6MX0.TyrFwe1Vh09xID3xDuP6T5QfbJ67l7V3BlJD9D9BHNqk
Enter Secret: secret123 + BASE64URL N -> Invalid ❌ -> Y for brute-force -> found N4AigW... -> tamper
Correct for secret123: eyJhbGciOi...N4AigWaFgPjiZuiiKR1YMo1x3-JfM9aHvdfuCPzaDG8
```

### 2. Encode (you WANT to create)
```
Choice: 2
Enter Payload JSON: {"user":"admin","role":"admin"}
Enter Secret (Enter for none): secret123
Is secret BASE64URL? [y/N]: N
Choose Algorithm: 1.HS256 2.HS384 3.HS512 4.none 5.Flask 6.Express 7.HMAC 8.AES 9.Base64
-> Generated token + Cookie: session=...
```

---

## Tamper Tips
- **Paste:** paste single `{"user":"admin","id":22}` or multi-line, end with empty line. `=` auto-fixed.
- **Editor:** choose `2` → `nano` → use arrows up/down, edit, `Ctrl+O` `Enter` `Ctrl+X` (vim: `:wq`)
- **Flask raw?** Still JSON dict — edit same way. If raw string, shown as raw.
- **Keep same:** Choice `1` keeps original alg (detected `ttype`), so Flask stays Flask, Express stays Express.

---

## Troubleshooting

| Error | Why | Fix |
|-------|-----|-----|
| `UNKNOWN / Base64 decode failed: Expecting value` with `:` token `.eJyr...:ts:sig` | Old version only handled `.` not `:` | **Fixed** — now `:` auto-converted to `.` and `zlib` decompressed. Update via `cp /home/kali/TOOLS/sess_enc_dec/universal-cookie-tool.py /home/kali/TOOLS/universal-cookie-tool.py` |
| `Invalid Signature` with `secret123` | Token not signed with that secret (`TyrFwe...` ≠ `N4AigW...`) | Use `Y` brute-force or paste correct token `...N4AigWa...` |
| `pycryptodome not found` | AES needs lib | `pip install pycryptodome --break-system-packages` or `uv pip install pycryptodome` for venv |
| `wordlist not found` | `rockyou.txt.gz` not extracted | `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz` |
| Paste breaks | Used `=` not `:` | Auto-fixed now, but use `:` and `"` — e.g. `{"id":22}` |

---

## Files
```
~/TOOLS/sess_enc_dec/
  universal-cookie-tool.py  # main (877 lines, handles all above)
  README.md                 # this file
~/TOOLS/
  universal-cookie-tool.py  # synced copy
  README.md                 # overview
```

Only use on authorized labs / PT scopes.
