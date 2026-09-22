#!/usr/bin/env python3
"""
Universal Cookie / Session Token Tool
- Encode & Decode with/without secret
- Auto-detect algorithm, show header/payload JSON for tampering
- Supports: JWT (HS256/384/512, RS256, none), Flask/Django, Express, Generic HMAC, AES-CBC/GCM, Base64/Hex
- Auto Brute-Force with SecLists auto-selection
- Interactive: only 2 options (Encode / Decode), rest auto
Author: PT Helper
"""
import os, sys, json, base64, binascii, hmac, hashlib, re, glob, time, subprocess, tempfile, zlib
from pathlib import Path

# Optional libs
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    HAS_CRYPTO = True
except: HAS_CRYPTO = False

try:
    from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
    HAS_ITSDANGEROUS = True
except: HAS_ITSDANGEROUS = False

# Colors
G, R, Y, C, W, B = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[0m", "\033[94m"
def ok(m): return f"{G}{m}{W}"
def err(m): return f"{R}{m}{W}"
def info(m): return f"{C}{m}{W}"
def warn(m): return f"{Y}{m}{W}"

# ---------- Helpers ----------
def b64url_encode(data: bytes) -> str:
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def is_b64(s):
    try:
        if not s or len(s) % 4 == 1: return False
        base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        return True
    except: return False

def pretty_json(obj):
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except:
        return str(obj)

def try_json_load(s):
    try:
        return json.loads(s)
    except: return None

# ---------- Wordlist Auto Finder ----------
def find_wordlists():
    search_roots = ["/usr/share/seclists", "/usr/share/wordlists", "/usr/share/seclists/Passwords", str(Path.home())+"/SecLists"]
    found = []
    for root in search_roots:
        if os.path.isdir(root):
            for p in Path(root).rglob("*.txt"):
                found.append(str(p))
    return found

def auto_pick_wordlist(token_type="jwt"):
    # Priority mapping
    priority = {
        "jwt": ["scraped-JWT-secrets", "jwt.secrets", "jwt", "rockyou", "xato", "darkc0de"],
        "flask": ["rockyou", "darkc0de", "openwall", "common", "password"],
        "hmac": ["rockyou", "xato", "common", "password"],
        "aes": ["rockyou", "password", "common"],
        "generic": ["rockyou", "xato", "darkc0de"]
    }
    keywords = priority.get(token_type, priority["generic"])
    candidates = find_wordlists()
    # Check exact known files first - priority depends on token_type
    if token_type == "jwt":
        known = [
            "/usr/share/seclists/Passwords/scraped-JWT-secrets.txt",
            "/usr/share/wordlists/seclists/Passwords/scraped-JWT-secrets.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/darkc0de.txt",
        ]
    else:
        known = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/darkc0de.txt",
            "/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/seclists/Passwords/scraped-JWT-secrets.txt",
        ]
    for k in known:
        if os.path.isfile(k):
            # for jwt need jwt keyword, for others need rockyou etc - already ordered
            return k
    # Search by keyword
    for kw in keywords:
        for f in candidates:
            if kw.lower() in f.lower() and os.path.getsize(f) < 200*1024*1024: # avoid 40M file unless needed
                return f
    # Fallback smallest rockyou
    for f in candidates:
        if "rockyou" in f.lower():
            return f
    return candidates[0] if candidates else None

def load_wordlist(path, limit=0):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', errors='ignore') as fh:
            if limit>0:
                return [next(fh).strip() for _ in range(limit)]
            return [l.strip() for l in fh if l.strip()]
    except Exception as e:
        print(err(f"[!] Wordlist read error: {e}"))
        return None

# ---------- Detection ----------
def detect_token(token: str):
    token = token.strip()
    # Flask compressed: starts with . and has 3 separators ( .<data>.<timestamp>.<sig> or .<data>:<timestamp>:<sig> )
    if token.startswith('.') and (token.count('.') + token.count(':') == 3):
        return "flask", "itsdangerous-compressed"
    # Express signed cookie: s:xxx.yyy (plain, not base64 json)
    if token.startswith('s:') or token.startswith('s%3A'):
        return "express", "HMAC-SHA256"
    # JWT vs Flask (both 3 parts) - check header for alg
    if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token):
        try:
            hdr = json.loads(b64url_decode(token.split('.')[0]))
            if "alg" in hdr:
                return "jwt", hdr.get("alg", "unknown")
            else:
                # Header is JSON but no alg -> likely Flask (itsdangerous payload)
                # Flask payload is like {"user":"admin"} not {"alg":...}
                return "flask", "itsdangerous"
        except:
            # first part not JSON -> could be flask or generic
            pass
        # fallback: try payload decode, if it looks like flask timestamp sig, treat as flask
        parts = token.split(".")
        try:
            # Flask has timestamp as second part (base64 of time)
            # If third part fails jwt sig check, still could be flask
            payload = b64url_decode(parts[0])
            if payload.startswith(b'{'):
                return "flask", "itsdangerous"
        except: pass
        return "jwt", "HS256?"
    if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', token) and token.count('.')==2:
        return "flask", "itsdangerous"
    if token.startswith("s:") or token.startswith("s%3A"):
        return "express", "HMAC-SHA256"
    if "." in token and len(token.split("."))==2:
        parts = token.split(".")
        if is_b64(parts[0]) and (len(parts[1]) in [32,40,64,128] or is_b64(parts[1])):
            return "hmac", "SHA256"
    # Base64 only JSON
    try:
        d = base64.b64decode(token + "="*(-len(token)%4))
        if d.startswith(b'{') and try_json_load(d):
            return "base64", "plain"
    except: pass
    try:
        d = b64url_decode(token)
        if d.startswith(b'{'):
            return "base64", "plain"
    except: pass
    # AES-like random base64 length multiple 16
    try:
        raw = base64.b64decode(token + "="*(-len(token)%4))
        if len(raw) % 16 == 0 and len(raw) >= 16 and re.match(r'^[A-Za-z0-9+/=]+$', token):
            return "aes", "AES-CBC?"
    except: pass
    # Hex
    if re.match(r'^[0-9a-fA-F]+$', token) and len(token) % 2 ==0:
        return "hex", "hex"
    return "unknown", "unknown"

# ---------- JWT ----------
def decode_jwt(token, secret=None, verify=True, b64_secret=False):
    parts = token.strip().split(".")
    if len(parts) not in [2,3]:
        raise ValueError("JWT must have 2 or 3 parts")
    header_b64, payload_b64 = parts[0], parts[1]
    sig_b64 = parts[2] if len(parts)==3 else ""
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")
    alg = header.get("alg", "unknown")
    result = {"header": header, "payload": payload, "alg": alg, "signature": sig_b64, "valid": None, "error": None}
    if not verify or not secret or alg=="none":
        result["valid"] = None if alg=="none" else False
        if alg=="none":
            result["valid"] = True
            result["error"] = "alg:none - no signature"
        return result
    # verify
    try:
        secret_bytes = secret.encode() if isinstance(secret, str) else secret
        if b64_secret:
            # decode secret as base64url
            try:
                secret_bytes = b64url_decode(secret) if isinstance(secret, str) else secret
            except: pass
        header_payload = f"{header_b64}.{payload_b64}".encode()
        hash_algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
        calc = b64url_encode(hmac.new(secret_bytes, header_payload, hash_algo).digest())
        result["valid"] = hmac.compare_digest(calc, sig_b64)
        if not result["valid"]:
            result["error"] = "signature verification failed"
    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)
    return result

def encode_jwt(payload, secret=None, alg="HS256", b64_secret=False):
    if isinstance(payload, str):
        payload = json.loads(payload)
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",",":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",",":")).encode())
    if alg == "none":
        return f"{header_b64}.{payload_b64}."
    if secret is None:
        secret = ""
    secret_bytes = secret.encode() if isinstance(secret, str) else secret
    if b64_secret:
        try: secret_bytes = b64url_decode(secret)
        except: pass
    hash_algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    sig = b64url_encode(hmac.new(secret_bytes, f"{header_b64}.{payload_b64}".encode(), hash_algo).digest())
    return f"{header_b64}.{payload_b64}.{sig}"

# ---------- Flask / itsdangerous ----------
def decode_flask(token, secret=None):
    # Handle Flask compressed: .<compressed_b64>.<timestamp>.<sig> or .<compressed_b64>:<timestamp>:<sig>
    if token.startswith('.'):
        norm = token.replace(':', '.')
        parts = norm.split('.')
        # Expected: ['', compressed_b64, timestamp, sig] = 4 parts
        if len(parts) == 4 and parts[0] == '':
            compressed_b64, ts_b64, sig = parts[1], parts[2], parts[3]
            payload = None
            try:
                raw = b64url_decode(compressed_b64)
                # try zlib decompress (Flask compresses with zlib)
                try:
                    decompressed = zlib.decompress(raw)
                    payload = json.loads(decompressed)
                except:
                    # not compressed or not json
                    try:
                        payload = json.loads(raw)
                    except:
                        payload = {"raw": raw.decode(errors='ignore')}
            except Exception as e:
                payload = {"raw": compressed_b64, "error": str(e)}
            valid = None
            error = None
            if secret and HAS_ITSDANGEROUS:
                try:
                    s = URLSafeTimedSerializer(secret)
                    data = s.loads(token)
                    valid = True
                    payload = data
                except BadSignature as e:
                    valid = False
                    error = f"BadSignature: {e}"
                except Exception as e:
                    valid = False
                    error = str(e)
            return {"header": {"alg":"itsdangerous","typ":"Flask-compressed"}, "payload": payload, "alg":"itsdangerous-HMAC-SHA1", "signature": sig, "valid": valid, "error": error}
    # Normal Flask: payload.timestamp.signature (3 parts)
    parts = token.split(".")
    payload_b64 = parts[0]
    try:
        # try urlsafe base64 then zlib decompress attempt
        raw = b64url_decode(payload_b64)
        try:
            # Flask may compress large payloads without leading dot? Try zlib
            dec = zlib.decompress(raw)
            payload = json.loads(dec)
        except:
            payload = json.loads(raw)
    except:
        try:
            payload = json.loads(base64.b64decode(payload_b64 + "="*(-len(payload_b64)%4)))
        except Exception as e:
            payload = {"raw": payload_b64, "error": str(e)}
    # Try itsdangerous verify if secret provided and lib available
    valid = None
    error = None
    if secret and HAS_ITSDANGEROUS:
        try:
            s = URLSafeTimedSerializer(secret)
            data = s.loads(token)
            valid = True
            payload = data
        except BadSignature as e:
            valid = False
            error = f"BadSignature: {e}"
        except Exception as e:
            valid = False
            error = str(e)
    elif secret:
        # fallback manual HMAC-SHA1 (flask default uses SHA1)
        try:
            # itsdangerous does: base64(payload).timestamp.hmac
            if len(parts)==3:
                payload_part, ts, sig = parts
                to_sign = f"{payload_part}.{ts}".encode()
                calc = b64url_encode(hmac.new(secret.encode(), to_sign, hashlib.sha1).digest())
                valid = hmac.compare_digest(calc, sig)
                if not valid: error="HMAC-SHA1 mismatch"
            elif len(parts)==4 and token.startswith('.'):
                # compressed case manual
                compressed_b64, ts_b64, sig = parts[1], parts[2], parts[3]
                to_sign = f".{compressed_b64}.{ts_b64}".encode()  # Flask signs with leading dot
                calc = b64url_encode(hmac.new(secret.encode(), to_sign, hashlib.sha1).digest())
                valid = hmac.compare_digest(calc, sig)
                if not valid: error="HMAC-SHA1 mismatch (compressed)"
        except Exception as e:
            error=str(e)
    return {"header": {"alg":"itsdangerous","typ":"Flask"}, "payload": payload, "alg":"itsdangerous-HMAC-SHA1", "signature": parts[-1] if len(parts)>1 else "", "valid": valid, "error": error}

def encode_flask(payload, secret):
    if isinstance(payload, str):
        payload = json.loads(payload)
    if HAS_ITSDANGEROUS:
        s = URLSafeTimedSerializer(secret)
        return s.dumps(payload)
    else:
        # fallback manual (simplified without timestamp)
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",",":")).encode())
        sig = b64url_encode(hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha1).digest())
        return f"{payload_b64}.{sig}"

def decode_express(token, secret=None):
    # Express signed cookie: s:<value>.<sig>  where sig = base64url(HMAC-SHA256(value, secret))
    raw = token.strip()
    if raw.startswith("s%3A"):
        raw = raw.replace("s%3A", "s:", 1)
    if not raw.startswith("s:"):
        return {"header":{"alg":"HMAC-SHA256","typ":"Express"},"payload":{"raw":token},"alg":"HMAC-SHA256","signature":"","valid":None,"error":"not express format"}
    body = raw[2:]
    if "." not in body:
        return {"header":{"alg":"HMAC-SHA256","typ":"Express"},"payload":{"value":body},"alg":"HMAC-SHA256","signature":"","valid":None,"error":"no sig"}
    value, sig = body.rsplit(".",1)
    # Try to decode value
    payload = None
    try:
        import urllib.parse
        decoded_val = urllib.parse.unquote(value)
        try:
            raw_b = b64url_decode(decoded_val)
            if raw_b.startswith(b'{'):
                payload = json.loads(raw_b)
            else:
                payload = {"value": decoded_val}
        except:
            payload = {"value": decoded_val}
    except:
        payload = {"value": value}
    valid = None
    error = None
    if secret:
        try:
            # Express signs the value as-is (value part after s:)
            val_to_sign = value
            # Try URL decoded also
            candidates = [val_to_sign]
            try:
                import urllib.parse
                candidates.append(urllib.parse.unquote(val_to_sign))
            except: pass
            found=False
            for cand in candidates:
                for enc in ["b64url", "b64"]:
                    if enc=="b64url":
                        calc = b64url_encode(hmac.new(secret.encode(), cand.encode(), hashlib.sha256).digest())
                    else:
                        calc = base64.b64encode(hmac.new(secret.encode(), cand.encode(), hashlib.sha256).digest()).decode().rstrip("=")
                    # also try base64 with urlsafe replace
                    calc_u = calc.replace("+","-").replace("/","_")
                    if hmac.compare_digest(calc, sig) or hmac.compare_digest(calc_u, sig):
                        found=True
                        break
                    # try base64 standard without urlsafe
                    calc2 = base64.b64encode(hmac.new(secret.encode(), cand.encode(), hashlib.sha256).digest()).decode()
                    if hmac.compare_digest(calc2, sig) or hmac.compare_digest(calc2.rstrip("="), sig):
                        found=True
                        break
                if found: break
            if found:
                valid=True
            else:
                valid=False
                error="HMAC-SHA256 mismatch"
        except Exception as e:
            error=str(e)
            valid=False
    return {"header":{"alg":"HMAC-SHA256","typ":"Express"},"payload":payload,"alg":"HMAC-SHA256","signature":sig,"valid":valid,"error":error}

def encode_express(value, secret):
    if isinstance(value, dict):
        value = b64url_encode(json.dumps(value, separators=(",",":")).encode())
    value = str(value)
    sig = b64url_encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest())
    return f"s:{value}.{sig}"

# ---------- Generic HMAC ----------
def decode_generic_hmac(token, secret=None, algo="sha256"):
    if "." not in token:
        return {"header":{"alg":algo},"payload":{"raw":token},"alg":algo,"signature":"","valid":None,"error":"no dot found"}
    data, sig = token.rsplit(".",1)
    # Try decode data as base64 json
    try:
        decoded = b64url_decode(data)
        payload = json.loads(decoded) if decoded.startswith(b'{') else {"data": data, "decoded": decoded.decode(errors='ignore')}
    except:
        payload = {"data": data}
    valid=None
    error=None
    if secret:
        try:
            hash_fn = getattr(hashlib, algo.lower().replace("-",""))
            # try hex and base64url signatures
            calc_hex = hmac.new(secret.encode(), data.encode(), hash_fn).hexdigest()
            calc_b64 = b64url_encode(hmac.new(secret.encode(), data.encode(), hash_fn).digest())
            calc_b64_std = base64.b64encode(hmac.new(secret.encode(), data.encode(), hash_fn).digest()).decode()
            if hmac.compare_digest(calc_hex, sig) or hmac.compare_digest(calc_b64, sig) or hmac.compare_digest(calc_b64_std, sig):
                valid=True
            else:
                valid=False
                error="HMAC mismatch (tried hex/base64/base64url)"
        except Exception as e:
            error=str(e)
    return {"header":{"alg":algo},"payload":payload,"alg":f"HMAC-{algo.upper()}","signature":sig,"valid":valid,"error":error}

def encode_generic_hmac(payload, secret, algo="sha256", as_hex=False):
    if isinstance(payload, dict):
        # encode payload as base64url json
        data = b64url_encode(json.dumps(payload, separators=(",",":")).encode())
    else:
        data = str(payload)
        if try_json_load(data):
            data = b64url_encode(json.dumps(json.loads(data), separators=(",",":")).encode())
    hash_fn = getattr(hashlib, algo.lower().replace("-",""))
    if as_hex:
        sig = hmac.new(secret.encode(), data.encode(), hash_fn).hexdigest()
    else:
        sig = b64url_encode(hmac.new(secret.encode(), data.encode(), hash_fn).digest())
    return f"{data}.{sig}"

# ---------- AES ----------
def decode_aes(token, key_str):
    if not HAS_CRYPTO:
        return {"header":{"alg":"AES-CBC"},"payload":{"error":"pycryptodome not installed (pip install pycryptodome)"},"alg":"AES-CBC","signature":"","valid":False,"error":"missing pycryptodome"}
    try:
        raw = base64.b64decode(token + "="*(-len(token)%4))
        key = hashlib.sha256(key_str.encode()).digest()  # 32 bytes for AES256
        # try IV = first 16 bytes
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        payload = json.loads(pt) if pt.startswith(b'{') else {"decrypted": pt.decode(errors='ignore')}
        return {"header":{"alg":"AES-256-CBC"},"payload":payload,"alg":"AES-256-CBC","signature":"","valid":True,"error":None}
    except Exception as e:
        return {"header":{"alg":"AES-256-CBC"},"payload":{},"alg":"AES-256-CBC","signature":"","valid":False,"error":str(e)}

def encode_aes(payload, key_str):
    if not HAS_CRYPTO:
        raise RuntimeError("pycryptodome not installed: pip install pycryptodome")
    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(",",":"))
    if isinstance(payload, str):
        payload = payload.encode()
    key = hashlib.sha256(key_str.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(payload, AES.block_size))
    return base64.b64encode(iv+ct).decode()

# ---------- Brute Force ----------
def brute_force(token, token_type, wordlist_path, algo="HS256", b64_secret=False):
    print(info(f"[*] Brute-forcing {token_type} with {wordlist_path}"))
    if not os.path.isfile(wordlist_path):
        print(err(f"[!] Wordlist not found: {wordlist_path}"))
        return None
    # Detect correct brute method
    if token_type == "jwt":
        parts = token.split(".")
        if len(parts)!=3:
            print(err("[!] JWT must have 3 parts"))
            return None
        header_payload = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]
        alg = "HS256"
        try:
            hdr = json.loads(b64url_decode(parts[0]))
            alg = hdr.get("alg","HS256")
        except: pass
        hash_algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
        count=0
        start=time.time()
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                secret=line.strip()
                if not secret: continue
                count+=1
                if count % 10000 == 0:
                    print(f"  ...tried {count}  ({secret[:15]}...)")
                # try plain and base64 decoded secret
                for sec in [secret, secret.strip()]:
                    try:
                        sec_bytes = sec.encode()
                        if b64_secret:
                            try: sec_bytes = b64url_decode(sec)
                            except: pass
                        calc = b64url_encode(hmac.new(sec_bytes, header_payload.encode(), hash_algo).digest())
                        if hmac.compare_digest(calc, target_sig):
                            print(ok(f"\n[+] FOUND! Secret: '{sec}'  (tried {count})  time {time.time()-start:.1f}s"))
                            return sec
                    except: continue
        print(err(f"[-] Not found after {count} tries"))
        return None
    elif token_type == "flask":
        if not HAS_ITSDANGEROUS:
            print(warn("[!] itsdangerous not installed, trying manual HMAC-SHA1"))
        count=0
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                secret=line.strip()
                if not secret: continue
                count+=1
                if count % 5000==0: print(f"  ...tried {count}")
                try:
                    if HAS_ITSDANGEROUS:
                        s = URLSafeTimedSerializer(secret)
                        s.loads(token)
                        print(ok(f"\n[+] FOUND Flask secret: '{secret}'"))
                        return secret
                    else:
                        # manual
                        parts=token.split(".")
                        if len(parts)==3:
                            payload_part, ts, sig = parts
                            calc = b64url_encode(hmac.new(secret.encode(), f"{payload_part}.{ts}".encode(), hashlib.sha1).digest())
                            if hmac.compare_digest(calc, sig):
                                print(ok(f"\n[+] FOUND Flask secret: '{secret}'"))
                                return secret
                        elif len(parts)==4 and token.startswith('.'):
                            # compressed Flask: .<data>.<ts>.<sig> -> to_sign is .<data>.<ts>
                            compressed_b64, ts_b64, sig = parts[1], parts[2], parts[3]
                            to_sign = f".{compressed_b64}.{ts_b64}".encode()
                            calc = b64url_encode(hmac.new(secret.encode(), to_sign, hashlib.sha1).digest())
                            if hmac.compare_digest(calc, sig):
                                print(ok(f"\n[+] FOUND Flask secret: '{secret}'"))
                                return secret
                except: continue
        print(err(f"[-] Not found after {count}"))
        return None
    elif token_type == "express":
        # Express: s:value.sig  sig = base64url(HMAC-SHA256(value, secret))
        tmp_tok = token.strip()
        if tmp_tok.startswith("s%3A"):
            tmp_tok = tmp_tok.replace("s%3A", "s:", 1)
        if not tmp_tok.startswith("s:"):
            print(err("[!] Not express format"))
            return None
        body = tmp_tok[2:]
        if "." not in body:
            print(err("[!] No sig"))
            return None
        value, target_sig = body.rsplit(".",1)
        count=0
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                secret=line.strip()
                if not secret: continue
                count+=1
                if count%5000==0: print(f"  ...tried {count} ({secret[:12]}...)")
                try:
                    # Try both b64url and standard b64
                    calc_u = b64url_encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest())
                    calc_s = base64.b64encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()).decode().rstrip("=")
                    calc_u2 = calc_s.replace("+","-").replace("/","_")
                    if hmac.compare_digest(calc_u, target_sig) or hmac.compare_digest(calc_s, target_sig) or hmac.compare_digest(calc_u2, target_sig):
                        print(ok(f"\n[+] FOUND Express secret: '{secret}'  (tried {count})"))
                        return secret
                except: continue
        print(err(f"[-] Not found after {count}"))
        return None
    elif token_type == "hmac":
        data, sig = token.rsplit(".",1)
        for algo in ["sha256","sha1","sha512","md5"]:
            print(info(f"[*] Trying HMAC-{algo}"))
            hash_fn = getattr(hashlib, algo)
            count=0
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    secret=line.strip()
                    if not secret: continue
                    count+=1
                    calc_hex = hmac.new(secret.encode(), data.encode(), hash_fn).hexdigest()
                    calc_b64 = b64url_encode(hmac.new(secret.encode(), data.encode(), hash_fn).digest())
                    if hmac.compare_digest(calc_hex, sig) or hmac.compare_digest(calc_b64, sig):
                        print(ok(f"\n[+] FOUND HMAC-{algo} secret: '{secret}'"))
                        return secret
            print(warn(f"[-] Not found for {algo}"))
        return None
    elif token_type == "aes":
        if not HAS_CRYPTO:
            print(err("[!] Need pycryptodome for AES brute"))
            return None
        try:
            raw = base64.b64decode(token + "="*(-len(token)%4))
            iv, ct = raw[:16], raw[16:]
        except Exception as e:
            print(err(f"[!] AES decode error: {e}"))
            return None
        count=0
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                secret=line.strip()
                if not secret: continue
                count+=1
                if count%5000==0: print(f"  ...tried {count}")
                try:
                    key = hashlib.sha256(secret.encode()).digest()
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    if b'{' in pt or pt.isascii():
                        # likely correct padding -> found
                        print(ok(f"\n[+] Probable AES key found: '{secret}' -> {pt[:80]}"))
                        return secret
                except: continue
        print(err("[-] AES key not found"))
        return None
    else:
        print(err("[!] Brute not implemented for this type, trying JWT method"))
        return brute_force(token, "jwt", wordlist_path, algo, b64_secret)

# ---------- Interactive Handlers ----------
def handle_decode():
    print("\n"+B+"--- DECODE MODE ---"+W)
    token = input(info("Paste Token/Session Cookie: ")).strip().strip('"').strip("'")
    if not token:
        print(err("[!] Empty token"))
        return
    ttype, alg_hint = detect_token(token)
    print(info(f"[*] Detected: {ttype.upper()}  | Hint Alg: {alg_hint}"))
    # show raw decoded attempt without secret first
    try:
        if ttype=="jwt":
            res = decode_jwt(token, secret=None, verify=False)
            print(ok("\n[Decoded Header]"))
            print(pretty_json(res["header"]))
            print(ok("\n[Decoded Payload] - COPY THIS JSON FOR TAMPERING:"))
            print(pretty_json(res["payload"]))
            print(warn(f"\n[Algorithm] {res['alg']} ( {res['alg']} - HMAC with SHA-256 )" if res['alg']=="HS256" else f"\n[Algorithm] {res['alg']}"))
            print(info(f"[Signature] {res['signature'][:40]}... (not verified yet)"))
        elif ttype=="flask":
            res = decode_flask(token, secret=None)
            print(ok("\n[Decoded Payload]"))
            print(pretty_json(res["payload"]))
            print(warn(f"\n[Algorithm] {res['alg']}"))
        elif ttype=="express":
            res = decode_express(token, secret=None)
            print(ok("\n[Decoded Payload]"))
            print(pretty_json(res["payload"]))
            print(warn(f"\n[Algorithm] {res['alg']} (Express signed cookie)"))
        elif ttype=="hmac":
            res = decode_generic_hmac(token, secret=None)
            print(ok("\n[Decoded Payload]"))
            print(pretty_json(res["payload"]))
            print(warn(f"\n[Algorithm] {res['alg']}"))
        elif ttype=="aes":
            print(warn("[*] Looks like AES-CBC (base64, len %16==0). Need key to decrypt."))
            res = {"payload":{}, "alg":"AES-CBC", "valid":None}
        elif ttype=="base64":
            try:
                raw = base64.b64decode(token + "="*(-len(token)%4))
                j = try_json_load(raw)
                print(ok("\n[Decoded Base64]"))
                print(pretty_json(j if j else raw.decode(errors='ignore')))
            except Exception as e:
                print(err(f"Decode error: {e}"))
            res = {"payload": try_json_load(raw) if 'raw' in locals() else {}, "alg":"BASE64", "header":{}}
        else:
            # try JWT decode as fallback
            try:
                res = decode_jwt(token, secret=None, verify=False)
                print(pretty_json(res["payload"]))
            except Exception as e:
                print(err(f"[!] Unknown type, raw: {e}"))
                print(info(f"Raw token length {len(token)}, showing as is"))
                res = {"payload":{"raw":token}, "alg":"unknown", "header":{}}
    except Exception as e:
        print(err(f"[!] Decode error: {e}"))
        res = {"payload":{}, "header":{}, "alg":ttype}

    # Ask secret
    print("\n"+C+"--- Verification ---"+W)
    secret = input(info("Enter Secret/Key (press Enter for WITHOUT secret): ")).strip()
    b64_secret = False
    if secret:
        b64q = input(info("Is secret BASE64URL encoded? (like jwt.io toggle) [y/N]: ")).strip().lower()
        b64_secret = (b64q=="y")
    else:
        print(warn("[*] Without secret mode: showing decoded data only, signature not verified"))
        # Offer brute-force even without secret
        try:
            qb = input(warn("Do you want to BRUTE-FORCE secret with SecLists now? [Y/n]: ")).strip().lower()
        except: qb = "n"
        if qb != "n":
            wl = auto_pick_wordlist(ttype)
            print(info(f"[*] Auto-selected wordlist: {wl}"))
            custom = input(info(f"Press Enter to use this, or type custom path: ")).strip()
            if custom: wl = custom
            found = brute_force(token, ttype, wl, alg_hint, b64_secret)
            if found:
                secret = found
                print(ok(f"[+] Using found secret for tamper step: '{found}'"))

    valid = None
    if secret:
        print(info(f"[*] Verifying with secret '{secret}' (b64={b64_secret})..."))
        try:
            if ttype=="jwt":
                res2 = decode_jwt(token, secret=secret, verify=True, b64_secret=b64_secret)
                valid = res2["valid"]
                print(ok("[+] Signature Valid âœ…") if valid else err("[-] Invalid Signature âŒ - signature verification failed"))
                if res2.get("error"): print(err(f"    {res2['error']}"))
            elif ttype=="flask":
                res2 = decode_flask(token, secret=secret)
                valid = res2["valid"]
                print(ok("[+] Valid âœ…") if valid else err("[-] Invalid âŒ"))
                if res2.get("error"): print(err(f"    {res2['error']}"))
            elif ttype=="express":
                res2 = decode_express(token, secret=secret)
                valid = res2["valid"]
                print(ok("[+] Valid âœ…") if valid else err("[-] Invalid âŒ"))
                if res2.get("error"): print(err(f"    {res2['error']}"))
                if valid:
                    print(ok("[Payload]"))
                    print(pretty_json(res2["payload"]))
                    res=res2
            elif ttype=="hmac":
                res2 = decode_generic_hmac(token, secret=secret)
                valid = res2["valid"]
                print(ok("[+] Valid âœ…") if valid else err("[-] Invalid âŒ"))
            elif ttype=="aes":
                res2 = decode_aes(token, secret)
                valid = res2["valid"]
                print(ok("[+] Decrypted âœ…") if valid else err("[-] Decrypt failed âŒ"))
                if valid:
                    print(ok("[Payload]"))
                    print(pretty_json(res2["payload"]))
                    res=res2
                else:
                    print(err(res2.get("error","")))
            else:
                res2 = decode_jwt(token, secret=secret, verify=True, b64_secret=b64_secret)
                valid=res2["valid"]
                print(ok("[+] Valid âœ…") if valid else err("[-] Invalid âŒ"))
        except Exception as e:
            print(err(f"[!] Verify error: {e}"))
            valid=False
        if not valid:
            q = input(warn("Do you want to BRUTE-FORCE secret with SecLists? [Y/n]: ")).strip().lower()
            if q != "n":
                wl = auto_pick_wordlist(ttype)
                print(info(f"[*] Auto-selected wordlist: {wl}"))
                custom = input(info(f"Press Enter to use this, or type custom path: ")).strip()
                if custom: wl = custom
                found = brute_force(token, ttype, wl, alg_hint, b64_secret)
                if found:
                    secret = found
                    valid = True
                    # re-decode with found secret to show payload
                    try:
                        if ttype=="jwt":
                            res = decode_jwt(token, secret=found, verify=True, b64_secret=b64_secret)
                            print(ok("[Decoded with FOUND secret]"))
                            print(pretty_json(res["payload"]))
                    except: pass

    # Tamper -> Re-encode loop (auto)
    print("\n"+C+"--- Tamper & Re-encode ---"+W)
    q = input(info("Do you want to tamper this JSON and re-encode? [y/N]: ")).strip().lower()
    if q == "y":
        # show current JSON for editing
        cur_payload = None
        try:
            if "res" in locals() and "payload" in res:
                cur_payload = res["payload"]
            elif "res2" in locals() and "payload" in res2:
                cur_payload = res2["payload"]
        except: pass
        if cur_payload is None:
            cur_payload = {"user":"admin","id":1}
        # Handle non-JSON payloads (e.g., Flask raw string, AES decrypted text)
        is_json = isinstance(cur_payload, (dict, list))
        if is_json:
            cur_str = json.dumps(cur_payload, indent=2)
        else:
            cur_str = str(cur_payload)
            print(warn("[*] Payload is not JSON (raw), showing raw value:"))
        print(ok("\nCurrent JSON (copy & edit):"))
        print(cur_str)
        if not is_json:
            print(warn("Note: This token type is not JSON. Edit as raw string or JSON if applicable. For Flask it is JSON dict."))
        print(warn("\nHow to edit?"))
        print(info("  1. Paste new JSON (multi-line, end with empty line) [press Enter]"))
        print(info("  2. Open in editor (nano/vim) - allows arrow keys, up/down to move & edit"))
        edit_choice = input(info("Choice [1/2] or Enter for 1: ")).strip()
        new_json_str = None
        if edit_choice == "2":
            editor = os.environ.get("EDITOR", "")
            candidates = [editor, "nano", "vim", "vi"] if editor else ["nano", "vim", "vi"]
            chosen = None
            for ed in candidates:
                if not ed: continue
                if subprocess.run(["which", ed], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    chosen = ed
                    break
            if not chosen:
                print(warn("[!] No editor found (nano/vim), falling back to paste"))
            else:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as tf:
                    tf.write(cur_str)
                    tf_path = tf.name
                print(info(f"[*] Opening {chosen} ... edit JSON, then save & exit (nano: Ctrl+O Enter Ctrl+X | vim: :wq)"))
                try:
                    subprocess.call([chosen, tf_path])
                    with open(tf_path, 'r', encoding='utf-8') as f:
                        new_json_str = f.read()
                    if not new_json_str.strip():
                        print(warn("[*] Empty file, keeping original"))
                        new_json_str = cur_str
                    else:
                        print(ok("[*] Loaded from editor:"))
                        print(new_json_str[:800])
                except Exception as e:
                    print(err(f"[!] Editor error: {e}"))
                    new_json_str = cur_str
                finally:
                    try: os.unlink(tf_path)
                    except: pass
        if new_json_str is None:
            # Paste mode (default)
            print(warn("\nEnter NEW JSON for tampering:"))
            print(info("â€¢ Paste single-line OR multi-line JSON, then press Enter on empty line to finish"))
            print(info("â€¢ Press Enter alone to keep same"))
            print(info("â€¢ Example: {\"user\":\"admin\", \"id\":22}  (use ':' not '=')"))
            print(info("\nPaste new JSON now (end with empty line):"))
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line == "" and not lines:
                    new_json_str = cur_str
                    break
                if line == "":
                    break
                lines.append(line)
            if lines:
                new_json_str = "\n".join(lines)
            else:
                if 'new_json_str' not in locals() or not new_json_str:
                    new_json_str = cur_str
            if not new_json_str.strip():
                new_json_str = cur_str
        # Validate with retry loop (no termination on invalid)
        new_payload = None
        while True:
            try:
                if is_json:
                    new_payload = json.loads(new_json_str)
                else:
                    # Try JSON first, fallback to raw string
                    try:
                        new_payload = json.loads(new_json_str)
                    except:
                        new_payload = new_json_str
                break
            except json.JSONDecodeError as e:
                # Try auto-fix common mistakes: = -> :, ' -> "
                fixed = new_json_str.replace("'", '"')
                # Only replace = that is between quotes and value (simple heuristic)
                if "=" in fixed and ":" not in fixed.split("=")[0][-10:]:
                    # naive fix: replace first = after key
                    fixed = fixed.replace("=", ":")
                if fixed != new_json_str:
                    try:
                        new_payload = json.loads(fixed)
                        print(warn(f"[!] Auto-fixed JSON (replaced '='/' with ':'): {fixed[:120]}"))
                        break
                    except: pass
                print(err(f"[!] Invalid JSON: {e}"))
                print(warn("Hint: Use double quotes and ':' -> {\"id\":22} not {\"id\"=22}"))
                print(info("Paste again (press Enter empty to keep original, or paste corrected JSON then empty line):"))
                retry_lines = []
                while True:
                    try:
                        rl = input()
                    except EOFError:
                        break
                    if rl == "" and not retry_lines:
                        new_json_str = cur_str
                        new_payload = cur_payload
                        break
                    if rl == "":
                        break
                    retry_lines.append(rl)
                if retry_lines:
                    new_json_str = "\n".join(retry_lines)
                    continue
                else:
                    # keep original if they pressed enter
                    if 'new_payload' not in locals() or new_payload is None:
                        new_payload = cur_payload
                    break
            except Exception as e:
                print(err(f"[!] Error: {e}, using raw string"))
                new_payload = new_json_str
                break
        # Choose algorithm for re-encode
        print(info(f"\nCurrent algorithm: {res.get('alg','HS256') if 'res' in locals() else alg_hint}  (detected: {ttype})"))
        print(info("Choose algorithm for re-encode:"))
        print("  1. Keep same  2. HS256  3. HS384  4. HS512  5. none (no signature)  6. Flask  7. Express  8. HMAC-SHA256  9. AES-256-CBC  10. Base64")
        choice = input(info("Choice [1]: ")).strip()
        alg_map = {"1": None, "2":"HS256","3":"HS384","4":"HS512","5":"none","6":"flask","7":"express","8":"hmac","9":"aes","10":"base64"}
        new_alg = alg_map.get(choice, None)
        if new_alg is None:
            # keep same - preserve original type
            if ttype in ["flask", "express", "hmac", "aes", "base64"]:
                new_alg = ttype
            else:
                try:
                    new_alg = res.get("alg","HS256")
                    if new_alg not in ["HS256","HS384","HS512","none"]:
                        new_alg="HS256"
                except: new_alg="HS256"
        # Need secret for encode unless none
        if new_alg != "none" and not secret:
            print(warn("[*] No secret provided - need secret to sign."))
            secret = input(info("Enter secret for re-encode (or Enter for none): ")).strip()
            if not secret:
                new_alg="none"
        print(info(f"[*] Encoding with alg={new_alg}, secret={'***' if secret else 'none'}..."))
        try:
            if new_alg in ["HS256","HS384","HS512","none"]:
                new_token = encode_jwt(new_payload, secret if new_alg!="none" else None, alg=new_alg, b64_secret=b64_secret)
            elif new_alg=="flask":
                if not secret: secret=input(info("Flask needs secret: ")).strip()
                new_token = encode_flask(new_payload, secret)
            elif new_alg=="express":
                if not secret: secret=input(info("Express needs secret: ")).strip()
                # Express value: if payload is dict with "value", use that, else json dump or raw
                if isinstance(new_payload, dict) and "value" in new_payload and len(new_payload)==1:
                    val = new_payload["value"]
                elif isinstance(new_payload, dict):
                    # try to use as plain string if possible, else json
                    try:
                        val = json.dumps(new_payload, separators=(",",":"))
                    except:
                        val = str(new_payload)
                else:
                    val = str(new_payload)
                new_token = encode_express(val, secret)
            elif new_alg=="hmac":
                if not secret: secret=input(info("HMAC needs secret: ")).strip()
                new_token = encode_generic_hmac(new_payload, secret)
            elif new_alg=="aes":
                if not secret: secret=input(info("AES needs key: ")).strip()
                new_token = encode_aes(new_payload, secret)
            elif new_alg=="base64":
                s = json.dumps(new_payload, separators=(",",": ")) if isinstance(new_payload, dict) else str(new_payload)
                s = json.dumps(new_payload, separators=(",",":")) if isinstance(new_payload, dict) else s
                new_token = base64.b64encode(s.encode()).decode()
            else:
                new_token = encode_jwt(new_payload, secret, alg=new_alg)
            print(ok("\n[+] NEW TOKEN (copy for Burp/Cookie):"))
            print(new_token)
            print(info("\nUse: Cookie: session="+new_token))
        except Exception as e:
            print(err(f"[!] Encode error: {e}"))

def handle_encode():
    print("\n"+B+"--- ENCODE MODE ---"+W)
    print(info("You want to CREATE a new token. Provide payload JSON."))
    print(warn('Example: {"user":"admin","id":1,"role":"admin"}'))
    payload_str = input(info("Enter Payload JSON: ")).strip()
    if not payload_str:
        print(err("[!] Empty payload"))
        return
    # Allow pretty multi-line if needed
    if payload_str.count('{') != payload_str.count('}'):
        print(info("Continue pasting JSON (end with empty line):"))
        lines=[payload_str]
        while True:
            line=input()
            if line=="": break
            lines.append(line)
        payload_str="\n".join(lines)
    try:
        payload = json.loads(payload_str)
        print(ok("[+] Valid JSON"))
        print(pretty_json(payload))
    except Exception as e:
        print(err(f"[!] Invalid JSON: {e}"))
        print(warn("[*] Will treat as raw string"))
        payload = payload_str

    secret = input(info("Enter Secret/Key (press Enter for WITHOUT secret -> alg:none): ")).strip()
    b64_secret=False
    if secret:
        b64q = input(info("Is secret BASE64URL encoded? [y/N]: ")).strip().lower()
        b64_secret=(b64q=="y")
    print(info("\nChoose Algorithm:"))
    print("  1. JWT HS256 (default)  2. HS384  3. HS512  4. none  5. Flask (itsdangerous)  6. Express-style HMAC  7. Generic HMAC-SHA256  8. AES-256-CBC  9. Base64")
    choice = input(info("Choice [1]: ")).strip() or "1"
    alg_map = {"1":"HS256","2":"HS384","3":"HS512","4":"none","5":"flask","6":"express","7":"hmac","8":"aes","9":"base64"}
    alg = alg_map.get(choice, "HS256")
    if alg!="none" and not secret and alg not in ["base64"]:
        print(warn("[*] No secret -> forcing alg:none"))
        alg="none"
    print(info(f"[*] Encoding payload with alg={alg}, secret={'***' if secret else 'none'}..."))
    try:
        if alg in ["HS256","HS384","HS512","none"]:
            token = encode_jwt(payload, secret if alg!="none" else None, alg=alg, b64_secret=b64_secret)
        elif alg=="flask":
            token = encode_flask(payload, secret)
        elif alg in ["express","hmac"]:
            token = encode_generic_hmac(payload, secret, algo="sha256")
        elif alg=="aes":
            if not HAS_CRYPTO:
                print(err("[!] pip install pycryptodome needed for AES"))
                return
            token = encode_aes(payload, secret)
        elif alg=="base64":
            s = json.dumps(payload, separators=(",",":")) if isinstance(payload, dict) else str(payload)
            token = base64.b64encode(s.encode()).decode()
        else:
            token = encode_jwt(payload, secret, alg=alg)
        print(ok("\n[+] GENERATED TOKEN:"))
        print(token)
        if alg.startswith("HS") or alg=="none":
            print(info("jwt.io verify: paste token + secret, BASE64URL toggle = "+str(b64_secret)))
        print(info("Use in header: Cookie: session="+token))
        # also decode to verify
        try:
            if alg in ["HS256","HS384","HS512"]:
                r=decode_jwt(token, secret=secret, b64_secret=b64_secret)
                print(info(f"Verified: {r['valid']}"))
        except: pass
    except Exception as e:
        print(err(f"[!] Encode error: {e}"))
        import traceback; traceback.print_exc()

def banner():
    print(C+"""
  _   _       _                    _    ___           _    _
 | | | |_ __ (_)_   _____ _ __ ___  __ _| |  / __\\___   ___ | | _(_) ___
 | | | | '_ \\| \\ \\ / / _ \\ '__/ __|/ _` | | / /  / _ \\ / _ \\| |/ / |/ _ \\
 | |_| | | | | |\\ V /  __/ |  \\__ \\ (_| | |/ /__| (_) | (_) |   <| |  __/
  \\___/|_| |_|_| \\_/ \\___|_|  |___/\\__,_|_|\\____/\\___/ \\___/|_|\\_\\_|\\___|
    """+W)
    print(Y+"  Universal Cookie/Session Tool â€” JWT / Flask / HMAC / AES / Base64"+W)
    print(C+"  Auto-detect | With/Without Secret | Brute-Force SecLists | Tamper Loop"+W)
    print(W+"  Location: /home/kali/TOOLS/universal-cookie-tool.py")
    print()

def main():
    banner()
    if not HAS_CRYPTO:
        print(warn("[!] pycryptodome not found â€” AES will not work. Install: pip install pycryptodome"))
    if not HAS_ITSDANGEROUS:
        print(warn("[!] itsdangerous not found â€” Flask will use fallback. Install: pip install itsdangerous"))
    while True:
        print("\n"+B+"What do you want to do?"+W)
        print(f"  {G}1.{W} Decode  (you HAVE a token/session)")
        print(f"  {G}2.{W} Encode  (you WANT to create a token)")
        print(f"  {R}3.{W} Exit")
        choice = input(info("Choice [1/2/3]: ")).strip()
        if choice=="1":
            handle_decode()
        elif choice=="2":
            handle_encode()
        elif choice=="3" or choice.lower()=="exit":
            print(ok("Bye!"))
            sys.exit(0)
        else:
            print(err("[!] Choose 1, 2 or 3"))

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n"+warn("[!] Interrupted"))
        sys.exit(0)