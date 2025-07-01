... (unchanged portions above)
    file_path = os.path.join(UPLOAD_ROOT, meta["filename"])
    if not os.path.exists(file_path):
        log_and_protect_event(
            "file_download_deleted", request, current_user, {"file_id": file_id}
        )
        raise HTTPException(status_code=410, detail="File deleted")
    # LINT: break at operator:
    media_type = (
        meta["content_type"]
        or mimetypes.guess_type(meta["original_filename"])[0]
    )
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
    # LINT: break into multiple lines
    return [
        FileUploadMeta(
            **redact_sensitive_fields(
                dict(row),
                current_user["role"]
            )
        )
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
    # LINT: break url concat at operator
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
    # LINT: break stubbed text over 100 chars in multiple lines
    text = (
        "🩺 Thank you for your question. (This is a stubbed response. AI/doctor assistance will be "
        "integrated here in production. You asked: "
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
