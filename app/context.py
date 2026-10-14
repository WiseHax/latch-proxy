from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict

class SessionContext(BaseModel):
    """
    Immutable server-side identity lock.
    frozen=True prevents any downstream code or payload from mutating user_id or role.
    """
    model_config = ConfigDict(frozen=True)

    user_id: str
    role: str

async def get_session_context(
    x_user_id: str = Header(..., description="Authenticated User ID from session/JWT"),
    x_user_role: str = Header(default="user", description="Role: user, analyst, or admin")
) -> SessionContext:
    cleaned_id = x_user_id.strip()
    cleaned_role = x_user_role.strip().lower()

    if not cleaned_id:
        raise HTTPException(status_code=401, detail="Missing X-User-ID header")

    if cleaned_role not in {"user", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Invalid role specified")

    return SessionContext(user_id=cleaned_id, role=cleaned_role)