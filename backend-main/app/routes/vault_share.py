from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import StreamingResponse
from datetime import datetime, timedelta
from bson import ObjectId
import uuid
import io
import base64
# QKD-CHANGE
import hashlib
# QKD-CHANGE
import hmac
from app.database import links_col, files_col, audit_col
# QKD-CHANGE
from app.services.qkd_service import QKDService
from app.services.email_service import (
    send_share_notification_email,
    decode_email_token,
)
from app.dependencies import get_current_user
from app.services.auth_service import (
    hash_password,
    verify_password,
    create_view_token,
    decode_token,
)
from app.services.gridfs_service import download_file
from app.services.geo_service import is_location_allowed, get_country_from_ip
from app.services.device_service import compute_device_hash
from app.models.vault_schemas import (
    ShareLinkCreate,
    ShareLinkResponse,
    VerifyRequest,
    VerifyResponse,
)

router = APIRouter(prefix="/vault", tags=["Vault Sharing"])
# QKD-CHANGE
qkd_service = QKDService()


def link_doc_to_response(doc: dict) -> ShareLinkResponse:
    # Ensure datetimes are serialized as ISO with 'Z' suffix for UTC
    def serialize_val(v):
        if isinstance(v, datetime):
            return v.isoformat() + "Z"
        if isinstance(v, ObjectId):
            return str(v)
        return v

    return ShareLinkResponse(
        id=str(doc["_id"]),
        token=doc["token"],
        file_id=str(doc["file_id"]),
        recipient_email=doc["recipient_email"],
        status=doc["status"],
        created_at=serialize_val(doc["created_at"]),
        security={k: serialize_val(v) for k, v in doc["security"].items()},
        share_url=f"http://localhost:3000/viewer/{doc['token']}",
        access_code=doc.get("access_code"),
    )


# ──────────────────────────────────────────────
# POST /vault/share — Create a share link
# ──────────────────────────────────────────────
@router.post("/share", response_model=ShareLinkResponse)
async def create_share_link(
    body: ShareLinkCreate, current_user: dict = Depends(get_current_user)
):
    # Verify file exists and belongs to user
    file_doc = await files_col.find_one(
        {"_id": ObjectId(body.file_id), "owner_id": current_user["_id"], "is_deleted": False}
    )
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    token = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(hours=body.security.expiry_hours)
    access_code_hash = hash_password(body.access_code)

    # QKD-CHANGE — Generate QKD token alongside SHA-256
    qkd_data = None
    if body.access_code:
        try:
            # QKD-CHANGE
            qkd_result = qkd_service.generate_qkd_access_token(
                access_code=body.access_code,
                link_token=token
            )
            # QKD-CHANGE
            qkd_data = qkd_result
            # QKD-CHANGE
            print(f"[QKD] Generated BB84 token for link. "
                  f"Session: {qkd_result['session_id']}, "
                  f"Sifted bits: {qkd_result['metadata']['n_bits_sifted']}, "
                  f"Match rate: {qkd_result['metadata']['match_percentage']:.1f}%")
        except Exception as e:
            # QKD-CHANGE
            print(f"[QKD] WARNING: QKD generation failed, "
                  f"falling back to SHA-256 only: {e}")
            # QKD-CHANGE
            qkd_data = None

    link_doc = {
        "token": token,
        "file_id": ObjectId(body.file_id),
        "created_by": current_user["_id"],
        "recipient_email": body.recipient_email.lower().strip(),
        "access_code_hash": access_code_hash,
        "access_code": body.access_code,  # Store for easy retrieval/sharing
        "status": "active",
        "created_at": datetime.utcnow(),
        "last_accessed": None,
        "revoked_at": None,
        "revoke_reason": None,
        "security": {
            "expiry": expiry,
            "max_views": body.security.max_views,
            "views_used": 0,
            "burn_after_reading": body.security.burn_after_reading,
            "allowed_countries": body.security.allowed_countries,
            "allowed_cities": body.security.allowed_cities,
            "block_vpn": body.security.block_vpn,
            "require_device_lock": body.security.require_device_lock,
            "locked_device_hash": None,
            "screenshot_attempts": 0,
            # QKD-CHANGE
            "qkd_data": qkd_data,
            # SCREENSHOT-TOGGLE
            "allow_screenshots": body.security.allow_screenshots,
            "watermark_text": body.security.watermark_text
            or f"CONFIDENTIAL - {body.recipient_email}",
        },
    }

    result = await links_col.insert_one(link_doc)
    link_doc["_id"] = result.inserted_id

    await audit_col.insert_one(
        {
            "event_type": "link_created",
            "timestamp": datetime.utcnow(),
            "user_id": str(current_user["_id"]),
            "metadata": {
                "token": token,
                "file_id": body.file_id,
                "recipient": body.recipient_email,
            },
        }
    )

    # Send notification email to recipient with share link + access code
    try:
        share_url = f"http://localhost:3000/viewer/{token}"
        send_share_notification_email(
            recipient=body.recipient_email.lower().strip(),
            access_code=body.access_code,
            share_url=share_url,
            filename=file_doc.get("filename", "Shared File"),
            share_token=token,
        )
        print(f"[EMAIL] Share notification sent to {body.recipient_email}")
    except Exception as e:
        print(f"[EMAIL] ⚠️ Failed to send share notification: {e}")

    return link_doc_to_response(link_doc)


# ──────────────────────────────────────────────
# GET /vault/links — List share links
# ──────────────────────────────────────────────
@router.get("/links")
async def list_links(
    status_filter: str = None, current_user: dict = Depends(get_current_user)
):
    query = {"created_by": current_user["_id"]}
    if status_filter:
        query["status"] = status_filter
    cursor = links_col.find(query).sort("created_at", -1)
    links = await cursor.to_list(length=200)

    # Auto-expire check
    for link in links:
        if (
            link["status"] == "active"
            and link["security"]["expiry"] < datetime.utcnow()
        ):
            await links_col.update_one(
                {"_id": link["_id"]}, {"$set": {"status": "expired"}}
            )
            link["status"] = "expired"

    return {
        "links": [link_doc_to_response(l) for l in links],
        "total": len(links),
    }


# ──────────────────────────────────────────────
# PATCH /vault/links/{token}/revoke
# ──────────────────────────────────────────────
@router.patch("/links/{token}/revoke")
async def revoke_link(token: str, current_user: dict = Depends(get_current_user)):
    link = await links_col.find_one(
        {"token": token, "created_by": current_user["_id"]}
    )
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link["status"] != "active":
        raise HTTPException(
            status_code=400, detail=f"Link already {link['status']}"
        )

    await links_col.update_one(
        {"_id": link["_id"]},
        {
            "$set": {
                "status": "revoked",
                "revoked_at": datetime.utcnow(),
                "revoke_reason": "manual",
            }
        },
    )
    await audit_col.insert_one(
        {
            "event_type": "link_revoked",
            "timestamp": datetime.utcnow(),
            "user_id": str(current_user["_id"]),
            "metadata": {"token": token, "reason": "manual"},
        }
    )
    return {"revoked": True, "token": token}


# ──────────────────────────────────────────────
# DELETE /vault/links/{token} — Delete share link
# ──────────────────────────────────────────────
@router.delete("/links/{token}")
async def delete_link(token: str, current_user: dict = Depends(get_current_user)):
    link = await links_col.find_one(
        {"token": token, "created_by": current_user["_id"]}
    )
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    await links_col.delete_one({"_id": link["_id"]})
    
    # Audit trail for the deletion
    await audit_col.insert_one({
        "event_type": "link_deleted",
        "timestamp": datetime.utcnow(),
        "user_id": str(current_user["_id"]),
        "metadata": {"token": token, "recipient": link.get("recipient_email")}
    })
    
    return {"message": "Link deleted successfully"}


# ──────────────────────────────────────────────
# POST /vault/verify/{token} — Zero-trust verification (public)
# ──────────────────────────────────────────────
@router.post("/verify/{token}", response_model=VerifyResponse)
async def verify_link(token: str, body: VerifyRequest, request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.headers.get("x-real-ip", request.client.host if request.client else "unknown")
    user_agent = request.headers.get("user-agent", "unknown")

    # Step 1: Find link
    link = await links_col.find_one({"token": token})
    if not link:
        await audit_col.insert_one(
            {
                "event_type": "access_denied",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token, "reason": "not_found"},
                "request": {"ip": ip},
            }
        )
        raise HTTPException(status_code=403, detail="Link not found or revoked")

    # Step 2: Check status
    if link["status"] != "active":
        await audit_col.insert_one(
            {
                "event_type": "access_denied",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token, "reason": f"status_{link['status']}"},
                "request": {"ip": ip},
            }
        )
        raise HTTPException(status_code=403, detail=f"Link is {link['status']}")

    sec = link["security"]

    # Step 3: Check expiry
    if sec["expiry"] < datetime.utcnow():
        await links_col.update_one(
            {"_id": link["_id"]}, {"$set": {"status": "expired"}}
        )
        await audit_col.insert_one(
            {
                "event_type": "link_expired",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token},
            }
        )
        raise HTTPException(status_code=403, detail="Link has expired")

    # Step 4: Check view limit
    if sec["max_views"] > 0 and sec["views_used"] >= sec["max_views"]:
        await links_col.update_one(
            {"_id": link["_id"]}, {"$set": {"status": "burned"}}
        )
        await audit_col.insert_one(
            {
                "event_type": "link_burned",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token},
            }
        )
        raise HTTPException(status_code=403, detail="View limit reached")

    # Step 5: Check email
    if body.email.lower().strip() != link["recipient_email"]:
        await audit_col.insert_one(
            {
                "event_type": "access_denied",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token, "reason": "email_mismatch"},
                "request": {"ip": ip},
            }
        )
        raise HTTPException(status_code=403, detail="Unauthorized recipient")

    # QKD-CHANGE — Step 6: Try QKD verification first, fallback to SHA-256
    access_verified = False
    verification_method = "NONE"

    # QKD-CHANGE
    stored_qkd_data = sec.get("qkd_data")

    # QKD-CHANGE
    if stored_qkd_data and not stored_qkd_data.get("used", False):
        # QKD-CHANGE — PRIMARY: Try QKD verification
        qkd_result = qkd_service.verify_qkd_token(
            access_code=body.access_code,
            stored_qkd_data=stored_qkd_data
        )
        # QKD-CHANGE
        if qkd_result["verified"]:
            access_verified = True
            verification_method = "QKD-BB84-verified"
            # QKD-CHANGE — Invalidate QKD session (one-time use)
            await links_col.update_one(
                {"_id": link["_id"]},
                {"$set": {"security.qkd_data.used": True}}
            )
            # QKD-CHANGE
            print(f"[QKD] ✅ Access verified via BB84 QKD. "
                  f"Session {stored_qkd_data['session_id']} invalidated.")
        # QKD-CHANGE
        elif qkd_result.get("reason") == "QKD_SESSION_EXPIRED":
            # QKD-CHANGE — QKD used up — fall back to SHA-256
            verification_method = "SHA256-fallback"
            access_verified = verify_password(body.access_code, link["access_code_hash"])
            # QKD-CHANGE
            print(f"[QKD] ⚠️ QKD session expired, "
                  f"using SHA-256 fallback.")
        else:
            # QKD-CHANGE
            access_verified = False
            verification_method = "QKD-failed"
    else:
        # QKD-CHANGE — FALLBACK: No QKD data, use SHA-256
        verification_method = "SHA256-only"
        access_verified = verify_password(body.access_code, link["access_code_hash"])
        # QKD-CHANGE
        print(f"[QKD] ℹ️ No QKD data found, "
              f"using SHA-256 verification.")

    # QKD-CHANGE
    if not access_verified:
        await audit_col.insert_one(
            {
                "event_type": "access_denied",
                "timestamp": datetime.utcnow(),
                "metadata": {"token": token, "reason": "invalid_code", "method": verification_method},
                "request": {"ip": ip},
            }
        )
        raise HTTPException(status_code=403, detail="Invalid access code")

    # QKD-CHANGE
    print(f"[QKD] Access code verified via: {verification_method}")

    # GEO-FIX: Step 7: Geo-fencing (city-level + alias-aware)
    allowed, detected_loc = is_location_allowed(
        ip, 
        sec.get("allowed_countries", []),
        sec.get("allowed_cities", [])
    )
    if not allowed:
        # GEO-FIX: Clear error logging with IP, detected city, and allowed locations
        allowed_countries = sec.get("allowed_countries", [])
        allowed_cities = sec.get("allowed_cities", [])
        print(
            f"[GEO-BLOCK] Geo-blocked: User IP={ip}, "
            f"Detected City={detected_loc}, "
            f"Allowed={{'countries': {allowed_countries}, 'cities': {allowed_cities}}}"
        )
        await audit_col.insert_one(
            {
                "event_type": "geo_blocked",
                "timestamp": datetime.utcnow(),
                "metadata": {
                    "token": token,
                    "location": detected_loc,
                    # GEO-FIX: Include allowed list in audit for debugging
                    "allowed_countries": allowed_countries,
                    "allowed_cities": allowed_cities,
                },
                "request": {"ip": ip},
            }
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access not permitted from your location ({detected_loc})",
        )

    # Step 8: Device lock
    device_hash = compute_device_hash(user_agent, ip)
    if sec.get("require_device_lock", False):
        if sec.get("locked_device_hash") is None:
            # First access — lock to this device
            await links_col.update_one(
                {"_id": link["_id"]},
                {"$set": {"security.locked_device_hash": device_hash}},
            )
        elif sec["locked_device_hash"] != device_hash:
            await audit_col.insert_one(
                {
                    "event_type": "device_mismatch",
                    "timestamp": datetime.utcnow(),
                    "metadata": {"token": token},
                    "request": {"ip": ip, "device_hash": device_hash},
                }
            )
            raise HTTPException(
                status_code=403, detail="Access denied: unauthorized device"
            )

    # Step 9: All checks passed — grant access
    new_views = sec["views_used"] + 1
    update_fields = {
        "security.views_used": new_views,
        "last_accessed": datetime.utcnow(),
    }
    if (
        sec.get("burn_after_reading", False)
        and sec["max_views"] > 0
        and new_views >= sec["max_views"]
    ):
        update_fields["status"] = "burned"
    await links_col.update_one({"_id": link["_id"]}, {"$set": update_fields})

    file_doc = await files_col.find_one({"_id": link["file_id"]})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    view_token = create_view_token(token, str(link["file_id"]))

    await audit_col.insert_one(
        {
            "event_type": "link_accessed",
            "timestamp": datetime.utcnow(),
            "metadata": {"token": token, "views_used": new_views},
            "request": {"ip": ip, "location": detected_loc, "device_hash": device_hash},
        }
    )

    return VerifyResponse(
        view_token=view_token,
        expires_in_minutes=15,
        filename=file_doc["filename"],
        mime_type=file_doc["mime_type"],
        file_size=file_doc["size_bytes"],
        # SCREENSHOT-TOGGLE
        allow_screenshots=sec.get("allow_screenshots", True),
        watermark_text=sec.get("watermark_text", f"CONFIDENTIAL - {body.email}")
    )


# ──────────────────────────────────────────────
# GET /vault/stream/{token} — Stream file content
# ──────────────────────────────────────────────
@router.get("/stream/{token}")
async def stream_file(
    token: str, view_token: str = Query(...), request: Request = None
):
    # Decode view_token
    try:
        payload = decode_token(view_token)
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid or expired view token")

    if payload.get("type") != "view":
        raise HTTPException(status_code=403, detail="Invalid token type")
    if payload.get("token") != token:
        raise HTTPException(status_code=403, detail="Token mismatch")

    link = await links_col.find_one({"token": token})
    if not link:
        raise HTTPException(status_code=403, detail="Link not available")

    file_doc = await files_col.find_one({"_id": link["file_id"]})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    file_data, filename, mime_type = await download_file(str(file_doc["gridfs_id"]))

    # Determine response format
    if mime_type.startswith("image/"):
        encoded = base64.b64encode(file_data).decode("utf-8")
        return {
            "type": "image",
            "data": encoded,
            "mime_type": mime_type,
            "filename": filename,
            # SCREENSHOT-TOGGLE
            "allow_screenshots": link["security"].get("allow_screenshots", True),
        }
    elif mime_type in (
        "text/plain",
        "text/csv",
        "text/html",
        "application/json",
        "text/markdown",
    ):
        text = file_data.decode("utf-8", errors="replace")
        return {
            "type": "text",
            "data": text,
            "mime_type": mime_type,
            "filename": filename,
            # SCREENSHOT-TOGGLE
            "allow_screenshots": link["security"].get("allow_screenshots", True),
        }
    elif mime_type == "application/pdf":
        encoded = base64.b64encode(file_data).decode("utf-8")
        return {
            "type": "pdf",
            "data": encoded,
            "mime_type": mime_type,
            "filename": filename,
            # SCREENSHOT-TOGGLE
            "allow_screenshots": link["security"].get("allow_screenshots", True),
        }
    else:
        return StreamingResponse(
            io.BytesIO(file_data),
            media_type=mime_type,
            headers={
                "Content-Disposition": f'inline; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )


# ──────────────────────────────────────────────
# POST /vault/verify-email-token — Decode JWT from email for auto-fill
# ──────────────────────────────────────────────
@router.post("/verify-email-token")
async def verify_email_token(body: dict):
    """
    Decode a share access JWT token (from notification email).
    Returns the pre-populated email, access_code, and share_token
    so the frontend can auto-fill and auto-submit the verify form.
    """
    vt = body.get("token", "")
    if not vt:
        raise HTTPException(status_code=400, detail="Missing token")

    try:
        payload = decode_email_token(vt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if payload.get("type") != "share_access":
        raise HTTPException(status_code=400, detail="Invalid token type")

    return {
        "email": payload.get("sub", ""),
        "access_code": payload.get("access_code", ""),
        "share_token": payload.get("share_token", ""),
        "valid": True,
    }
