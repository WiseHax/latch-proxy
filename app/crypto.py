import os
import hmac
import hashlib

LATCH_HMAC_SECRET = os.getenv("LATCH_HMAC_SECRET", "latch-dev-secret-key-2026")

def generate_session_signature(user_id: str, role: str) -> str:
    """
    Computes an HMAC-SHA256 signature binding user_id and role together.
    """
    payload = f"{user_id.strip()}:{role.strip().lower()}".encode("utf-8")
    secret = LATCH_HMAC_SECRET.encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify_session_signature(user_id: str, role: str, signature: str) -> bool:
    """
    Uses constant-time comparison (hmac.compare_digest) to prevent timing side-channel attacks.
    """
    expected = generate_session_signature(user_id, role)
    return hmac.compare_digest(expected, signature.strip())