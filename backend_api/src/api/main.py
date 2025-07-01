import os
import sqlite3
from typing import List, Optional
from uuid import uuid4

from fastapi import FastAPI, Request, Depends, HTTPException
from pydantic import BaseModel, Field, EmailStr

from .security_utils import (
    require_role,
    audit_log_event,
    redact_sensitive_fields,
    Role,
    create_jwt_token
)

DATABASE_PATH = os.environ.get("SQLITE_PATH", "./db.sqlite3")
UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "./uploads")


app = FastAPI(
    title="ArogyaMitr API",
    version="1.0.0",
    description="Backend for ArogyaMitr project"
)


# === Signup Models ===

class SignupRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    phone: str = Field(..., description="User phone number")
    password: str = Field(..., min_length=6, description="User password")
    role: Optional[Role] = Field(Role.patient, description="User role (default: patient)")


class SignupResponse(BaseModel):
    user_id: int = Field(..., description="New user ID")
    email: EmailStr = Field(..., description="Registered email")
    phone: str = Field(..., description="Registered phone")
    role: Role = Field(..., description="Registered role")
    token: str = Field(..., description="JWT session token for the user")


# PUBLIC_INTERFACE
@app.post(
    "/signup",
    response_model=SignupResponse,
    summary="User signup endpoint",
    description="Creates a new user account if email and phone are unique.",
    tags=["Authentication"],
    responses={
        409: {"description": "Email or phone already registered"},
        400: {"description": "Signup failed: invalid or incomplete data"},
    }
)
def signup(request: SignupRequest):
    """
    Signup endpoint to create a new user. Returns JWT on success or error on unique/email conflict.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Ensure users table exists (for robustness)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'patient'
        )
        """
    )

    try:
        cur.execute(
            "INSERT INTO users (email, phone, password, role) VALUES (?, ?, ?, ?)",
            (
                request.email,
                request.phone,
                request.password,
                request.role.value if isinstance(request.role, Role) else request.role
            )
        )
        user_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError as e:
        # Map unique constraint violation to a proper error
        msg = None
        if "UNIQUE constraint failed: users.email" in str(e):
            msg = "Signup failed: email already registered"
        elif "UNIQUE constraint failed: users.phone" in str(e):
            msg = "Signup failed: phone number already registered"
        else:
            msg = "Signup failed: email or phone already in use"
        audit_log_event(
            event_type="signup_failed",
            metadata={
                "email": request.email,
                "phone": request.phone,
                "reason": msg
            }
        )
        raise HTTPException(
            status_code=409,
            detail=msg
        )
    except Exception as e:
        audit_log_event(
            event_type="signup_failed",
            metadata={
                "email": request.email,
                "phone": request.phone,
                "reason": str(e)
            }
        )
        raise HTTPException(
            status_code=400,
            detail="Signup failed: " + str(e)
        )
    finally:
        conn.close()

    # Issue JWT, audit event, and return the response
    token = create_jwt_token(user_id, request.role)
    audit_log_event(
        event_type="signup",
        user_id=user_id,
        role=request.role,
        metadata={
            "email": request.email,
            "phone": request.phone
        }
    )
    return SignupResponse(
        user_id=user_id,
        email=request.email,
        phone=request.phone,
        role=request.role,
        token=token
    )


class FileUploadMeta(BaseModel):
    file_id: str = Field(..., description="File ID")
    user_id: int = Field(..., description="Uploader's user id")
    original_filename: str = Field(..., description="Original filename")
    filename: str = Field(..., description="Saved path/filename")
    content_type: str = Field(
        ...,
        description="Mime type (as determined or declared)"
    )
    upload_time: str = Field(..., description="Timestamp")
    module: str = Field(
        None,
        description="Optional: module context for file"
    )


class VideoConsultRequest(BaseModel):
    doctor_id: int = Field(..., description="Doctor's user id")
    user_id: int = Field(..., description="User's id requesting session")
    purpose: str = Field(..., description="Purpose of video consultation")


class VideoConsultResponse(BaseModel):
    session_id: str
    join_url: str


class AIChatPrompt(BaseModel):
    user_id: int = Field(..., description="Sender user id")
    message: str = Field(..., description="Prompt or chat message text")


class AIChatResponse(BaseModel):
    response: str


class MapResourceRequest(BaseModel):
    search: str
    location: str


class MapResourceResponse(BaseModel):
    result: dict


@app.get(
    "/files/list",
    response_model=List[FileUploadMeta],
    tags=["User"],
    summary="List uploaded files by user",
    description="Lists metadata for files uploaded by the current user or, for admin/doctor, all files."
)
def list_my_files(
    request: Request,
    current_user: dict = Depends(require_role(Role.patient, Role.doctor, Role.admin))
):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if current_user["role"] in [Role.admin, Role.doctor]:
        cur.execute("SELECT * FROM file_uploads ORDER BY upload_time DESC")
    else:
        cur.execute(
            "SELECT * FROM file_uploads WHERE user_id = ? ORDER BY upload_time DESC",
            (current_user["user_id"],)
        )
    rows = cur.fetchall()
    conn.close()
    audit_log_event(
        event_type="file_listed",
        user_id=current_user["user_id"],
        role=current_user["role"],
        metadata={
            "scope": (
                "admin/doctor"
                if current_user["role"] in [Role.admin, Role.doctor]
                else "patient"
            )
        }
    )
    return [
        FileUploadMeta(
            **redact_sensitive_fields(
                dict(row),
                current_user["role"]
            )
        )
        for row in rows
    ]


@app.post(
    "/integration/video/start-session",
    response_model=VideoConsultResponse,
    tags=["TeleConsultation"],
    summary="Start video consult session (integration stub)",
    description=(
        "Returns placeholder video session link. "
        "To be replaced with real video SDK. Only patients & doctors may start."
    )
)
def start_video_consult(
    request: VideoConsultRequest,
    current_user: dict = Depends(require_role(Role.patient, Role.doctor))
):
    audit_log_event(
        event_type="video_consult_start",
        user_id=current_user["user_id"],
        role=current_user["role"],
        metadata={
            "doctor_id": request.doctor_id,
            "user_id": request.user_id,
            "purpose": request.purpose,
        }
    )
    dummy_session_id = str(uuid4())
    return VideoConsultResponse(
        session_id=dummy_session_id,
        join_url=(
            "https://videoconsult.staging.arogyamitr.com/"
            "join/"
            + str(dummy_session_id)
        ),
    )


@app.post(
    "/integration/ai/chat",
    response_model=AIChatResponse,
    tags=["AI"],
    summary="Send message to AI health assistant (integration stub)",
    description="Stub endpoint for AI assistant chat. Returns canned response. RBAC and audit included."
)
def ai_chat_endpoint(
    request: AIChatPrompt,
    current_user: dict = Depends(require_role(Role.patient, Role.doctor, Role.admin))
):
    audit_log_event(
        event_type="ai_chat",
        user_id=current_user["user_id"],
        role=current_user["role"],
        metadata={
            "user_id": request.user_id,
            "msg_chars": len(request.message)
        }
    )
    return AIChatResponse(
        response=(
            "🩺 Thank you for your question. "
            "(This is a stubbed response. "
            "AI/doctor assistance will be integrated here in production. "
            "You asked: "
            + f"{request.message[:80]}"
            + f"{request.message[80:160]}"
            + f"{request.message[160:200]}"
            + ")"
        )
    )


@app.post(
    "/integration/maps/search",
    response_model=MapResourceResponse,
    tags=["Community"],
    summary="Search for health/community maps/resources (integration stub)",
    description="Returns a stubbed placeholder map search result. Only logged-in users."
)
def map_search(
    request: MapResourceRequest,
    current_user: dict = Depends(require_role(Role.patient, Role.doctor, Role.admin))
):
    audit_log_event(
        event_type="map_search",
        user_id=current_user["user_id"],
        role=current_user["role"],
        metadata={
            "query": request.search,
            "location": request.location
        }
    )
    result = {
        "query": request.search,
        "location": request.location,
        "found": False,
        "resources": [],
        "note": (
            "Stub only. Map provider coming soon."
        ),
    }
    return MapResourceResponse(result=result)
