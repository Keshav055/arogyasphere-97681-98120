import os
from typing import Optional, List
from fastapi import (
    FastAPI, Depends, HTTPException, File, UploadFile, Form, Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sqlite3
from datetime import datetime
from uuid import uuid4
import aiofiles
import mimetypes
from pathlib import Path

from .security_utils import (
    Role, require_role, audit_log_event, restrict_patient_data_access,
    redact_sensitive_fields, log_and_protect_event
)


DATABASE_PATH = os.environ.get("SQLITE_PATH", "./db.sqlite3")
UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "./uploaded_files")
SECRET_KEY = os.environ.get("SECRET_KEY", "YOUR_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


openapi_tags = [
    {
        "name": "Authentication",
        "description": "User sign up/in, OAuth, JWT session management."
    },
    {
        "name": "User",
        "description": "User profile, settings, dashboard."
    },
    {
        "name": "Wellness",
        "description": "Diet, fitness, mindfulness, sleep features."
    },
    {
        "name": "SustainableLiving",
        "description": "Product scanner, business directory, carbon tracker."
    },
    {
        "name": "ChronicDisease",
        "description": "Dashboards for diabetes etc."
    },
    {
        "name": "TeleConsultation",
        "description": "Consultation booking, session, prescription."
    },
    {
        "name": "Community",
        "description": "Forums, events, peer groups, map resources."
    },
    {
        "name": "Education",
        "description": "Articles, videos, hub."
    },
    {
        "name": "AI",
        "description": "AI assistant chat endpoints."
    },
    {
        "name": "HealthCheck",
        "description": "Database and app status."
    },
]


app = FastAPI(
    title="ArogyaMitr Backend API",
    description="REST API backend for ArogyaMitr health and wellness app.",
    version="1.0.0",
    openapi_tags=openapi_tags,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def init_db_and_upload_folder():
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS file_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            user_id INTEGER,
            size INTEGER,
            upload_time TEXT NOT NULL,
            description TEXT,
            module TEXT,
            ref_id INTEGER
        )
        """
    )
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_file_metadata(
    filename: str,
    original_filename: str,
    content_type: str,
    size: int,
    user_id: int = None,
    description: str = None,
    module: str = None,
    ref_id: int = None
) -> int:
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DATABASE_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO file_uploads
        (filename, original_filename, content_type, user_id, size, upload_time,
         description, module, ref_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            original_filename,
            content_type,
            user_id,
            size,
            now,
            description,
            module,
            ref_id,
        )
    )
    file_id = cur.lastrowid
    conn.commit()
    conn.close()
    return file_id


def get_file_metadata(file_id: int) -> Optional[dict]:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM file_uploads WHERE id = ?", (file_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


class FileUploadMeta(BaseModel):
    """
    Metadata for uploaded file records.
    """

    id: Optional[int] = Field(None)
    filename: str = Field(..., description="Stored file name on server")
    original_filename: str = Field(
        ..., description="Original file name as uploaded"
    )
    content_type: str = Field(..., description="MIME type")
    user_id: Optional[int] = Field(None, description="ID of the uploading user")
    size: int = Field(..., description="File size in bytes")
    upload_time: str = Field(..., description="Upload ISO timestamp")
    description: Optional[str] = Field(
        None, description="User-entered description"
    )
    module: Optional[str] = Field(
        None,
        description="Module or feature this file relates to (e.g. 'teleconsult')"
    )
    ref_id: Optional[int] = Field(
        None, description="External app/entity id associated"
    )


class VideoConsultRequest(BaseModel):
    user_id: int = Field(..., description="User ID (patient)")
    doctor_id: int = Field(..., description="Doctor ID")
    purpose: Optional[str] = Field(None, description="Reason for consult")


class VideoConsultResponse(BaseModel):
    session_id: str
    join_url: str


class AIChatPrompt(BaseModel):
    user_id: int
    message: str


class AIChatResponse(BaseModel):
    response: str


class MapResourceRequest(BaseModel):
    search: str
    location: str


class MapResourceResponse(BaseModel):
    result: dict


# PUBLIC_INTERFACE
@app.post(
    "/files/upload",
    response_model=FileUploadMeta,
    tags=["User", "TeleConsultation", "Education"],
    summary="Upload file securely",
    description=(
        "Upload a file (medical record, prescription, video etc.) "
        "with strict RBAC and audit. Admins, doctors, and patients may upload as "
        "per module context; files are tightly access-controlled."
    ),
)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None, description="Short description or note"),
    module: Optional[str] = Form(None, description="Subsystem/module this file belongs to."),
    ref_id: Optional[int] = Form(None, description="Optional record/entity the file associates with."),
    current_user: dict = Depends(require_role(Role.patient, Role.doctor, Role.admin))
) -> FileUploadMeta:
    extension = Path(file.filename).suffix
    uid = str(uuid4())
    stored_fname = f"{uid}{extension}"
    dest_path = os.path.join(UPLOAD_ROOT, stored_fname)
    size = 0
    try:
        async with aiofiles.open(dest_path, "wb") as out_file:
            while True:
                content = await file.read(4096)
                if not content:
                    break
                size += len(content)
                await out_file.write(content)
        fid = insert_file_metadata(
            filename=stored_fname,
            original_filename=file.filename,
            content_type=file.content_type,
            size=size,
            user_id=current_user["user_id"],
            description=description,
            module=module,
            ref_id=ref_id,
        )
        audit_log_event(
            event_type="file_uploaded",
            user_id=current_user["user_id"],
            role=current_user["role"],
            metadata={
                "filename": file.filename,
                "description": description,
                "module": module,
                "ref_id": ref_id,
            }
        )
    except Exception as e:
        log_and_protect_event(
            "file_upload_error", request, current_user, {"error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"File upload error: {str(e)}")

    meta = get_file_metadata(fid)
    return FileUploadMeta(**meta)


# PUBLIC_INTERFACE
@app.get(
    "/files/{file_id}/download",
    response_class=FileResponse,
    tags=["User", "TeleConsultation", "Education"],
    summary="Download a previously uploaded file",
    description=(
        "RBAC-protected file download. Only the uploader (patient) "
        "and admins/doctors can download."
    ),
)
async def download_file(
    request: Request,
    file_id: int,
    current_user: dict = Depends(require_role(Role.patient, Role.doctor, Role.admin))
):
    meta = get_file_metadata(file_id)
    if not meta:
        log_and_protect_event("file_download_not_found", request, current_user, {"file_id": file_id})
        raise HTTPException(status_code=404, detail="File not found")
    restrict_patient_data_access(
        current_user["user_id"], meta.get("user_id"), current_user["role"]
    )
    file_path = os.path.join(UPLOAD_ROOT, meta["filename"])
    if not os.path.exists(file_path):
        log_and_protect_event(
            "file_download_deleted", request, current_user, {"file_id": file_id}
        )
        raise HTTPException(status_code=410, detail="File deleted")
    media_type = meta["content_type"] or mimetypes.guess_type(
        meta["original_filename"]
    )[0]
    audit_log_event(
        event_type="file_downloaded",
        user_id=current_user["user_id"],
        role=current_user["role"],
        metadata={"file_id": file_id}
    )
    return FileResponse(
        path=file_path,
        filename=meta["original_filename"],
        media_type=media_type,
        headers={
            "X-File-Module": meta["module"] or "",
            "X-Uploaded-By": str(meta["user_id"] or "")
        }
    )


# PUBLIC_INTERFACE
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
        FileUploadMeta(**redact_sensitive_fields(dict(row), current_user["role"]))
        for row in rows
    ]


# PUBLIC_INTERFACE
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
    dummy_url = (
        "https://videoconsult.staging.arogyamitr.com/join/"
        f"{dummy_session_id}"
    )
    return VideoConsultResponse(
        session_id=dummy_session_id,
        join_url=dummy_url
    )


# PUBLIC_INTERFACE
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
    text = (
        "🩺 Thank you for your question. (This is a stubbed response. "
        "AI/doctor assistance will be integrated here in production. You asked: "
        f"{request.message[:200]})"
    )
    return AIChatResponse(response=text)


# PUBLIC_INTERFACE
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
        "note": "Stub only. Map provider coming soon.",
    }
    return MapResourceResponse(
        result=result
    )
