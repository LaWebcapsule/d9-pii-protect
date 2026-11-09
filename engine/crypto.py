"""PII masking tokens.

Two strategies, both keyed by PII_PROTECT_KEY (custody = the security boundary):

  hash   (default) : NON-reversible, consistent keyed hash → [TYPE:hexdigest]. Same value+type → same
                     token (joins/dedup still work), but no way back to the clear. This is the hoop-style
                     "mask what goes out" mode — no decryption oracle, nothing to rehydrate.
  marker (legacy)  : reversible AES-256-GCM [[PII:TYPE:b64]] (kept for callers that still ask for it).
"""
import base64, hashlib, hmac, os, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ===== KEY: required, no default. Inject via a secret manager / KMS in production. =====
_secret = os.environ.get("PII_PROTECT_KEY")
if not _secret:
    raise RuntimeError("PII_PROTECT_KEY is required — refusing to start without an encryption key (no default).")
# Derive a 32-byte key from the secret (any length) via HKDF-SHA256 — no silent truncation/padding.
_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"d9-pii-protect").derive(_secret.encode())
_aes = AESGCM(_KEY)

HASH_LEN = max(8, int(os.environ.get("PII_HASH_LEN", "12")))  # hex chars; 12 = 48 bits, collisions negligible

def hashtok(entity: str, plain: str) -> str:
    """Consistent, keyed, NON-reversible token. HMAC so it can't be brute-forced without the key."""
    h = hmac.new(_KEY, plain.encode(), hashlib.sha256).hexdigest()[:HASH_LEN]
    return f"[{entity}:{h}]"

MARKER_RE = re.compile(r"\[\[PII:([A-Z_]+):([A-Za-z0-9_\-]+={0,2})\]\]")

def encrypt(plain: str) -> str:
    nonce = os.urandom(12)
    return base64.urlsafe_b64encode(nonce + _aes.encrypt(nonce, plain.encode(), None)).decode()

def decrypt(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode())
    return _aes.decrypt(raw[:12], raw[12:], None).decode()

def marker(entity: str, plain: str) -> str:
    return f"[[PII:{entity}:{encrypt(plain)}]]"

def rehydrate(text: str):
    """Replace each marker with its decrypted value. Returns (text, count)."""
    n = 0
    def repl(m):
        nonlocal n
        try:
            v = decrypt(m.group(2)); n += 1; return v
        except Exception:
            return m.group(0)
    return MARKER_RE.sub(repl, text), n
