from fastapi import APIRouter, HTTPException, Depends, Request
from datetime import datetime, timedelta
from bson import ObjectId
import os
from app.database import links_col, audit_col, files_col
from app.dependencies import get_current_user

router = APIRouter(prefix="/vault", tags=["Vault Security"])
SCREENSHOT_THRESHOLD = int(os.getenv("SCREENSHOT_REVOKE_THRESHOLD", "5"))


# ──────────────────────────────────────────────
# POST /vault/screenshot/{token} — Report screenshot (public)
# ──────────────────────────────────────────────
@router.post("/screenshot/{token}")
async def report_screenshot(token: str, request: Request):
    link = await links_col.find_one({"token": token})
    if not link:
        return {"logged": True}  # Do not reveal existence
    if link["status"] != "active":
        return {"logged": True}

    await links_col.update_one(
        {"_id": link["_id"]}, {"$inc": {"security.screenshot_attempts": 1}}
    )
    current_count = link["security"].get("screenshot_attempts", 0) + 1

    ip = request.client.host if request.client else "unknown"
    await audit_col.insert_one(
        {
            "event_type": "screenshot_attempt",
            "timestamp": datetime.utcnow(),
            "user_id": str(link["created_by"]),
            "metadata": {"token": token, "screenshot_count": current_count},
            "request": {"ip": ip},
        }
    )

    if current_count >= SCREENSHOT_THRESHOLD:
        await links_col.update_one(
            {"_id": link["_id"]},
            {
                "$set": {
                    "status": "revoked",
                    "revoked_at": datetime.utcnow(),
                    "revoke_reason": "screenshot",
                }
            },
        )
        await audit_col.insert_one(
            {
                "event_type": "link_revoked",
                "timestamp": datetime.utcnow(),
                "user_id": str(link["created_by"]),
                "metadata": {"token": token, "reason": "screenshot"},
            }
        )

    return {"logged": True}


# ──────────────────────────────────────────────
# GET /vault/status/{token} — Check link status (public)
# ──────────────────────────────────────────────
@router.get("/status/{token}")
async def get_link_status(token: str):
    link = await links_col.find_one({"token": token})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    
    # Auto-expiry check
    if link["status"] == "active" and link["security"]["expiry"] < datetime.utcnow():
        await links_col.update_one(
            {"_id": link["_id"]}, {"$set": {"status": "expired"}}
        )
        link["status"] = "expired"
        
    sec = link["security"]
    
    # Auto-burn check
    if link["status"] == "active" and sec["max_views"] > 0 and sec["views_used"] >= sec["max_views"]:
        if sec.get("burn_after_reading", False):
            await links_col.update_one(
                {"_id": link["_id"]}, {"$set": {"status": "burned"}}
            )
            link["status"] = "burned"

    return {
        "status": link["status"],
        "views_used": sec["views_used"],
        "max_views": sec["max_views"],
        "screenshot_attempts": sec.get("screenshot_attempts", 0)
    }


# ──────────────────────────────────────────────
# POST /vault/killswitch — Revoke all active links
# ──────────────────────────────────────────────
@router.post("/killswitch")
async def kill_switch(current_user: dict = Depends(get_current_user)):
    result = await links_col.update_many(
        {"created_by": current_user["_id"], "status": "active"},
        {
            "$set": {
                "status": "revoked",
                "revoked_at": datetime.utcnow(),
                "revoke_reason": "killswitch",
            }
        },
    )
    await audit_col.insert_one(
        {
            "event_type": "kill_switch",
            "timestamp": datetime.utcnow(),
            "user_id": str(current_user["_id"]),
            "metadata": {"links_revoked": result.modified_count},
        }
    )
    return {
        "revoked_count": result.modified_count,
        "message": f"Emergency: {result.modified_count} links revoked",
    }


# ──────────────────────────────────────────────
# GET /vault/risk/{token} — Risk score for a link
# ──────────────────────────────────────────────
@router.get("/risk/{token}")
async def get_risk_score(
    token: str, current_user: dict = Depends(get_current_user)
):
    link = await links_col.find_one(
        {"token": token, "created_by": current_user["_id"]}
    )
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    events = await audit_col.find({"metadata.token": token}).to_list(length=1000)

    score = 0
    factors = []

    # Geo violations
    geo_blocks = sum(1 for e in events if e.get("event_type") == "geo_blocked")
    if geo_blocks > 0:
        pts = min(geo_blocks * 30, 60)
        score += pts
        factors.append(
            {
                "factor": "Geo Violation",
                "points": pts,
                "detail": f"{geo_blocks} blocked attempts",
            }
        )

    # Device mismatches
    device_issues = sum(
        1 for e in events if e.get("event_type") == "device_mismatch"
    )
    if device_issues > 0:
        pts = min(device_issues * 25, 50)
        score += pts
        factors.append(
            {
                "factor": "Device Mismatch",
                "points": pts,
                "detail": f"{device_issues} unauthorized devices",
            }
        )

    # Screenshot attempts
    ss_count = link["security"].get("screenshot_attempts", 0)
    if ss_count == 1:
        score += 15
        factors.append({"factor": "Screenshot", "points": 15, "detail": "1 attempt"})
    elif ss_count == 2:
        score += 25
        factors.append({"factor": "Screenshot", "points": 25, "detail": "2 attempts"})
    elif ss_count >= 3:
        score += 50
        factors.append(
            {
                "factor": "Screenshot",
                "points": 50,
                "detail": f"{ss_count} attempts",
            }
        )

    # Failed access attempts
    denied = sum(1 for e in events if e.get("event_type") == "access_denied")
    if denied > 0:
        pts = min(denied * 5, 20)
        score += pts
        factors.append(
            {
                "factor": "Failed Access",
                "points": pts,
                "detail": f"{denied} denied attempts",
            }
        )

    score = min(score, 100)

    if score == 0:
        level = "SECURE"
    elif score <= 25:
        level = "LOW"
    elif score <= 50:
        level = "MEDIUM"
    elif score <= 74:
        level = "HIGH"
    else:
        level = "CRITICAL"

    recommendations = {
        "SECURE": "No threats detected. Link is operating normally.",
        "LOW": "Minor concerns detected. Monitor activity.",
        "MEDIUM": "Moderate risk. Review security settings.",
        "HIGH": "Significant risk! Consider revoking this link.",
        "CRITICAL": "CRITICAL THREAT! Use Kill Switch immediately.",
    }

    return {
        "token": token,
        "score": score,
        "level": level,
        "factors": factors,
        "recommendation": recommendations[level],
    }


# ──────────────────────────────────────────────
# GET /vault/security-events — Recent security events
# ──────────────────────────────────────────────
@router.get("/security-events")
async def get_security_events(current_user: dict = Depends(get_current_user)):
    security_types = [
        "geo_blocked",
        "device_mismatch",
        "screenshot_attempt",
        "access_denied",
        "kill_switch",
        "link_revoked",
    ]
    cursor = (
        audit_col.find({"event_type": {"$in": security_types}, "user_id": str(current_user["_id"])})
        .sort("timestamp", -1)
        .limit(100)
    )
    events = await cursor.to_list(length=100)
    for e in events:
        e["_id"] = str(e["_id"])
        if "timestamp" in e:
            ts = e["timestamp"]
            if isinstance(ts, datetime):
                e["timestamp"] = ts.isoformat() + "Z"
            else:
                e["timestamp"] = str(ts)
    return events


# ──────────────────────────────────────────────
# DELETE /vault/security-events — Clear security events
# ──────────────────────────────────────────────
@router.delete("/security-events")
async def clear_security_events(current_user: dict = Depends(get_current_user)):
    from app.services.audit_log_service import AuditLogService
    service = AuditLogService()
    user_id = str(current_user["_id"])
    count = service.clear_all_logs(user_id=user_id)
    return {"message": f"Cleared {count} security events"}
