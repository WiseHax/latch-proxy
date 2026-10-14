import os
from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict
from app.crypto import verify_session_signature
from app.audit import log_security_event

REQUIRE_HMAC = os.getenv("LATCH_REQUIRE_HMAC", "false").lower() == "true"

class SessionContext(BaseModel):
    """
    Immutable server-side identity lock.
    frozen=True prevents any downstream code or payload from mutating user_id or role.
    """
    model_config = ConfigDict(frozen=True)

    user_id: str
    role: str
    hmac_verified: bool = False

async def get_session_context(
    x_user_id: str = Header(..., description="Authenticated User ID from session/JWT"),
    x_user_role: str = Header(default="user", description="Role: user, analyst, or admin"),
    x_latch_signature: str | None = Header(default=None, description="HMAC-SHA256 signature of 'user_id:role'")
) -> SessionContext:
    cleaned_id = x_user_id.strip()
    cleaned_role = x_user_role.strip().lower()

    if not cleaned_id:
        raise HTTPException(status_code=401, detail="Missing X-User-ID header")

    if cleaned_role not in {"user", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Invalid role specified")

    if REQUIRE_HMAC and not x_latch_signature:
        raise HTTPException(status_code=401, detail="Missing required X-Latch-Signature header")

    hmac_ok = False
    if x_latch_signature is not None:
        if not verify_session_signature(cleaned_id, cleaned_role, x_latch_signature):
            log_security_event(
                user_id=cleaned_id,
                role=cleaned_role,
                is_tainted=False,
                tool_name="auth_handshake",
                allowed=False,
                rule_triggered="HMAC_SIGNATURE_MISMATCH",
                secrets_redacted=0,
                reason=f"Cryptographic HMAC verification failed for claimed identity '{cleaned_id}' (role={cleaned_role})."
            )
            raise HTTPException(
                status_code=401,
                detail="HMAC signature verification failed: Tampered identity headers detected."
            )
        hmac_ok = True

    return SessionContext(user_id=cleaned_id, role=cleaned_role, hmac_verified=hmac_ok)