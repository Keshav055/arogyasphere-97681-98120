import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Callable, List, Dict, Any

from fastapi import Depends, HTTPException, Request
from jose import jwt, JWTError
from pydantic import BaseModel

DATABASE_PATH = os.environ.get("SQLITE_PATH", "./db.sqlite3")
SECRET_KEY = os.environ.get("SECRET_KEY", "YOUR_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


class Role(str, Enum):
    patient = "patient"
    doctor = "doctor"
    admin = "admin"


class TokenPayload(BaseModel):
    sub: int
    role: Role
    exp: int


# PUBLIC_INTERFACE
def create_jwt_token(
    user_id: int, role: Role, expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT token with role context."""
    to_encode = {"sub": str(user_id), "role": role.value}
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = int(expire.timestamp())
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# PUBLIC_INTERFACE
def decode_jwt_token(token: str) -> TokenPayload:
    """Decode JWT token and return user_id and role."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenPayload(
            sub=int(payload.get("sub")),
            role=payload.get("role"),
            exp=payload.get("exp")
        )
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token or expired"
        )


# PUBLIC_INTERFACE
def get_current_user_and_role(token: str = Depends(lambda: None)) -> Dict[str, Any]:
    """FastAPI Dependency: get current user id and role from JWT token."""
    from fastapi.security import OAuth2PasswordBearer

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # noqa: F841
    _token = token
    if _token is None:
        import inspect
        frame = inspect.currentframe()
        context = None
        while frame:
            if "request" in frame.f_locals:
                context = frame.f_locals["request"]
                break
            frame = frame.f_back
        if context and hasattr(context, "headers"):
            _token = context.headers.get(
                "Authorization", ""
            ).removeprefix("Bearer ").strip()
        if not _token:
            raise HTTPException(status_code=401, detail="Not authenticated")
    data = decode_jwt_token(_token)
    return {"user_id": data.sub, "role": data.role}


# PUBLIC_INTERFACE
def require_role(*allowed_roles: List[Role]) -> Callable:
    """FastAPI-compatible dependency for requiring certain roles."""

    def role_guard(current_user: dict = Depends(get_current_user_and_role)):
        user_role = current_user["role"]
        valid_roles = [r.value if isinstance(r, Enum) else r for r in allowed_roles]
        if user_role not in valid_roles:
            raise HTTPException(status_code=403, detail="Insufficient role privileges")
        return current_user

    return role_guard


# PUBLIC_INTERFACE
def audit_log_event(
    event_type: str,
    user_id: Optional[int] = None,
    role: Optional[str] = None,
    metadata: Optional[dict] = None,
):
    """Store an audit log event into the database (can be extended)."""
    import sqlite3
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    # Ensure audit_log table exists
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            user_id INTEGER,
            role TEXT,
            meta TEXT,
            event_time TEXT
        )
        """
    )
    meta_str = str(metadata) if metadata else None
    c.execute(
        "INSERT INTO audit_log (event_type, user_id, role, meta, event_time) "
        "VALUES (?, ?, ?, ?, ?)",
        (event_type, user_id, role, meta_str, now)
    )
    conn.commit()
    conn.close()


def restrict_patient_data_access(
    user_id: int, target_user_id: int, user_role: str
):
    """
    Only allow users to access their own health data, unless doctor/admin.
    """
    if user_id != target_user_id and user_role not in [Role.doctor, Role.admin]:
        raise HTTPException(
            status_code=403,
            detail="Access to this health data is restricted."
        )


def redact_sensitive_fields(data: dict, viewer_role: str) -> dict:
    """
    Redact PHI/PII fields for non-privileged viewers (example: only admin/doctor can see all).
    """
    redacted = data.copy()
    sensitive_keys = [
        "ssn", "aadhaar", "diagnosis_notes", "prescription", "contact_info"
    ]
    if viewer_role == Role.patient:
        for k in sensitive_keys:
            if k in redacted:
                redacted[k] = None
    return redacted


# PUBLIC_INTERFACE
def log_and_protect_event(
    event_type: str, request: Request, current_user: dict, extra: dict = None
):
    """Convenience helper for logging and returning generic security errors."""
    audit_log_event(
        event_type=event_type,
        user_id=current_user.get("user_id"),
        role=current_user.get("role"),
        metadata={
            "ip": request.client.host, **(extra or {})
        }
    )
