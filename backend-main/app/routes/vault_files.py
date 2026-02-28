from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Request
from datetime import datetime
from bson import ObjectId
import hashlib
import os
from app.database import files_col, audit_col
from app.dependencies import get_current_user
from app.services.gridfs_service import upload_file as gridfs_upload
from app.models.vault_schemas import FileMetadataResponse
from app.services.redaction_engine import RedactionEngine

router = APIRouter(prefix="/vault", tags=["Vault Files"])

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024

# Lazy-initialized PII scanner (heavy NLP model — only load if needed)
_pii_engine = None


def _get_pii_engine():
    global _pii_engine
    if _pii_engine is None:
        _pii_engine = RedactionEngine()
    return _pii_engine


def file_doc_to_response(doc: dict) -> FileMetadataResponse:
    # Ensure uploaded_at is serialized as ISO 8601 with 'Z' (UTC) suffix
    # so the frontend's new Date() correctly interprets it as UTC
    uploaded_at_raw = doc["uploaded_at"]
    if isinstance(uploaded_at_raw, datetime):
        uploaded_at_str = uploaded_at_raw.isoformat() + "Z"
    else:
        uploaded_at_str = str(uploaded_at_raw)
        if not uploaded_at_str.endswith("Z") and "+" not in uploaded_at_str:
            uploaded_at_str += "Z"

    return FileMetadataResponse(
        id=str(doc["_id"]),
        filename=doc["filename"],
        display_name=doc.get("display_name", doc["filename"]),
        size_bytes=doc["size_bytes"],
        mime_type=doc["mime_type"],
        file_hash=doc["file_hash"],
        uploaded_at=uploaded_at_str,
        is_deleted=doc.get("is_deleted", False),
        pii_scan=doc.get("pii_scan", {}),
    )


@router.post("/upload", response_model=FileMetadataResponse)
async def upload(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    request: Request = None,
):
    file_data = await file.read()
    if len(file_data) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max {MAX_UPLOAD_SIZE // (1024 * 1024)}MB",
        )

    file_hash = hashlib.sha256(file_data).hexdigest()
    owner_id = str(current_user["_id"])
    gridfs_id = await gridfs_upload(
        file_data,
        file.filename,
        file.content_type or "application/octet-stream",
        owner_id,
    )

    # PII scan (never fail the upload due to PII scan)
    pii_scan = {
        "scanned": False,
        "scan_at": None,
        "entities_found": [],
        "entity_count": 0,
        "was_redacted": False,
        "redaction_mode": None,
    }
    SCANNABLE = [
        "text/plain",
        "text/csv",
        "text/html",
        "application/json",
        "text/markdown",
    ]
    try:
        if file.content_type in SCANNABLE:
            text_content = file_data.decode("utf-8", errors="ignore")[:100000]
            engine = _get_pii_engine()
            # RedactionEngine.sanitize(text, mode, entities) returns:
            # {"clean_text": str, "items": List[str], "synthetic_map": dict}
            scan_result = engine.sanitize(text_content, mode="strict")
            entities_found = scan_result.get("items", [])
            pii_scan = {
                "scanned": True,
                "scan_at": datetime.utcnow().isoformat() + "Z",
                "entities_found": entities_found,
                "entity_count": len(entities_found),
                "was_redacted": False,
                "redaction_mode": None,
            }
    except Exception as e:
        print(f"[PII SCAN] Error scanning file: {e}")

    # Insert file document
    file_doc = {
        "owner_id": ObjectId(owner_id),
        "filename": file.filename,
        "display_name": file.filename,
        "gridfs_id": ObjectId(gridfs_id),
        "size_bytes": len(file_data),
        "mime_type": file.content_type or "application/octet-stream",
        "file_hash": file_hash,
        "uploaded_at": datetime.utcnow(),
        "is_deleted": False,
        "deleted_at": None,
        "pii_scan": pii_scan,
    }
    result = await files_col.insert_one(file_doc)
    file_doc["_id"] = result.inserted_id

    # Log audit event
    await audit_col.insert_one(
        {
            "event_type": "file_upload",
            "timestamp": datetime.utcnow(),
            "user_id": owner_id,
            "metadata": {
                "filename": file.filename,
                "size_bytes": len(file_data),
                "pii_entities": pii_scan.get("entity_count", 0),
            },
            "request": {
                "ip": (
                    request.client.host
                    if request and request.client
                    else "unknown"
                )
            },
        }
    )

    return file_doc_to_response(file_doc)


@router.get("/files", response_model=list[FileMetadataResponse])
async def list_files(current_user: dict = Depends(get_current_user)):
    cursor = files_col.find(
        {"owner_id": current_user["_id"], "is_deleted": False}
    ).sort("uploaded_at", -1)
    files = await cursor.to_list(length=100)
    return [file_doc_to_response(f) for f in files]


@router.get("/files/{file_id}", response_model=FileMetadataResponse)
async def get_file(file_id: str, current_user: dict = Depends(get_current_user)):
    doc = await files_col.find_one({"_id": ObjectId(file_id), "is_deleted": False})
    if not doc:
        raise HTTPException(status_code=404, detail="File not found")
    if doc["owner_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return file_doc_to_response(doc)


@router.delete("/files/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    doc = await files_col.find_one(
        {
            "_id": ObjectId(file_id),
            "owner_id": current_user["_id"],
            "is_deleted": False,
        }
    )
    if not doc:
        raise HTTPException(status_code=404, detail="File not found")
    await files_col.update_one(
        {"_id": doc["_id"]},
        {"$set": {"is_deleted": True, "deleted_at": datetime.utcnow()}},
    )
    return {"deleted": True, "file_id": file_id}
