"""PII masking token — one-way, consistent, keyed.

Each detected value is replaced by [TYPE:hexdigest]. Same value+type → same token (joins/dedup still work),
but there is no way back to the clear (HMAC, so it can't be brute-forced without PII_PROTECT_KEY).
Key custody (PII_PROTECT_KEY) is the security boundary.
"""
import hashlib, hmac, os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ===== KEY: required, no default. Inject via a secret manager / KMS in production. =====
_secret = os.environ.get("PII_PROTECT_KEY")
if not _secret:
    raise RuntimeError("PII_PROTECT_KEY is required — refusing to start without a key (no default).")
# Derive a 32-byte key from the secret (any length) via HKDF-SHA256 — no silent truncation/padding.
_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"d9-pii-protect").derive(_secret.encode())

HASH_LEN = max(8, int(os.environ.get("PII_HASH_LEN", "12")))  # hex chars; 12 = 48 bits, collisions negligible

def hashtok(entity: str, plain: str) -> str:
    return f"[{entity}:{hmac.new(_KEY, plain.encode(), hashlib.sha256).hexdigest()[:HASH_LEN]}]"
