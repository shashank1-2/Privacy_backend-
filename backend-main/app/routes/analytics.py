from fastapi import APIRouter, Depends
from datetime import datetime, timedelta
from app.database import files_col, links_col, audit_col
from app.dependencies import get_current_user

router = APIRouter(prefix="/vault", tags=["Vault Analytics"])


@router.get("/analytics")
async def get_vault_analytics(current_user: dict = Depends(get_current_user)):
    user_id = current_user["_id"]
    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)

    total_files = await files_col.count_documents({"owner_id": user_id, "is_deleted": False})

    total_links = await links_col.count_documents({"created_by": user_id})
    active_links = await links_col.count_documents({"created_by": user_id, "status": "active"})
    expired_links = await links_col.count_documents({"created_by": user_id, "status": "expired"})
    revoked_links = await links_col.count_documents({"created_by": user_id, "status": "revoked"})
    burned_links = await links_col.count_documents({"created_by": user_id, "status": "burned"})

    # Sum views_used using aggregation
    views_pipeline = [
        {"$match": {"created_by": user_id}},
        {"$group": {"_id": None, "total": {"$sum": "$security.views_used"}}}
    ]
    views_result = await links_col.aggregate(views_pipeline).to_list(1)
    total_views = views_result[0]["total"] if views_result else 0

    files_with_pii = await files_col.count_documents({
        "owner_id": user_id,
        "is_deleted": False,
        "pii_scan.entity_count": {"$gt": 0}
    })

    # Get user's link tokens for filtering audit events
    user_links = await links_col.find({"created_by": user_id}, {"token": 1}).to_list(500)
    user_tokens = [l["token"] for l in user_links]

    security_types = ["geo_blocked", "device_mismatch", "screenshot_attempt", "access_denied"]
    security_24h = await audit_col.count_documents({
        "metadata.token": {"$in": user_tokens},
        "event_type": {"$in": security_types},
        "timestamp": {"$gte": day_ago}
    }) if user_tokens else 0

    screenshot_total = await audit_col.count_documents({
        "metadata.token": {"$in": user_tokens},
        "event_type": "screenshot_attempt"
    }) if user_tokens else 0

    return {
        "total_files": total_files,
        "total_links": total_links,
        "active_links": active_links,
        "expired_links": expired_links,
        "revoked_links": revoked_links,
        "burned_links": burned_links,
        "total_views": total_views,
        "files_with_pii": files_with_pii,
        "security_events_24h": security_24h,
        "screenshot_attempts": screenshot_total,
        "links_by_status": {
            "active": active_links,
            "expired": expired_links,
            "revoked": revoked_links,
            "burned": burned_links
        }
    }
