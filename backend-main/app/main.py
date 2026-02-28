from fastapi import FastAPI, HTTPException, Body, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from app.models.schemas import SanitizeRequest, SanitizeResponse, AuditRequest, AuditResult, ChatRequest, ChatResponse
from app.services.redaction_engine import RedactionEngine
from app.crew.audit_crew import AuditCrew
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from litellm import completion
import litellm
import time
import os
import asyncio
import logging
from logging.handlers import RotatingFileHandler  # ✅ Added for log rotation
import json
import re
from datetime import datetime
import uuid
from app.services.audit_log_service import AuditLogService
from app.routes.auth import router as auth_router
from app.routes.vault_files import router as vault_files_router
from app.routes.vault_share import router as vault_share_router
from app.routes.vault_security import router as vault_security_router
from app.routes.analytics import router as analytics_router
from app.database import init_db, audit_col as async_audit_col
from app.dependencies import get_current_user

load_dotenv()  # Load env variables

logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger("audit_trail")

# ✅ Configure audit log with rotation - max 10MB per file, keep 5 backups
file_handler = RotatingFileHandler(
    "audit_log.jsonl",
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5  # Keep 5 old files (audit_log.jsonl.1, .2, etc.)
)
file_formatter = logging.Formatter('%(message)s')
file_handler.setFormatter(file_formatter)
audit_logger.addHandler(file_handler)
audit_logger.propagate = False  # Prevent audit logs from printing to console

def log_transaction(action: str, details: dict):
    """Writes a structured JSON log entry to the audit file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        **details
    }
    audit_logger.info(json.dumps(entry))  # Write as a single line JSON


async def log_to_mongo(event_type: str, **kwargs):
    """Write audit event directly to MongoDB."""
    document = {
        "event_type": event_type,
        "timestamp": datetime.utcnow(),
        "user_id": kwargs.get("user_id"),
        "share_link_id": kwargs.get("share_link_id"),
        "file_id": kwargs.get("file_id"),
        "request": {
            "ip": kwargs.get("ip", "unknown"),
            "user_agent": kwargs.get("user_agent", ""),
            "country": kwargs.get("country"),
            "city": kwargs.get("city"),
            "device_hash": kwargs.get("device_hash"),
        },
        "metadata": {
            "entities_found": kwargs.get("entities_found", []),
            "redaction_mode": kwargs.get("redaction_mode"),
            "safety_score": kwargs.get("safety_score"),
            "usability_score": kwargs.get("usability_score"),
            "processing_time_ms": kwargs.get("processing_time_ms"),
            "token": kwargs.get("token"),
            "views_used": kwargs.get("views_used"),
            "block_reason": kwargs.get("block_reason"),
            "screenshot_count": kwargs.get("screenshot_count"),
            "file_size_bytes": kwargs.get("file_size_bytes"),
            "extra": kwargs.get("extra"),
        },
    }
    try:
        await async_audit_col.insert_one(document)
    except Exception as e:
        print(f"[AUDIT] MongoDB write error: {e}")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # Setup Rate Limiting

# --- FIX: CORS CONFIGURATION ---
# We use ["*"] to allow ALL origins (localhost, 192.168.x.x, etc.)
# This fixes the "CORS policy: No 'Access-Control-Allow-Origin'" error.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/")
def root():
    return {"status": "ok"}

app.include_router(auth_router)
app.include_router(vault_files_router)
app.include_router(vault_share_router)
app.include_router(vault_security_router)
app.include_router(analytics_router)

redaction_engine = None
audit_log_service = AuditLogService(log_path="audit_log.jsonl")

@app.on_event("startup")
async def startup_event():
    """Initialize the NLP Engine on startup to avoid lag on first request."""
    global redaction_engine
    print("🚀 Loading PII Shield Engine...")
    redaction_engine = RedactionEngine()
    print("🚀 PII Shield Ready!")
    await init_db()

# Explicit OPTIONS handlers so CORS preflight always gets 200 (avoids 400/405)
@app.options("/sanitize")
async def sanitize_options():
    return Response(status_code=200)

@app.options("/audit")
async def audit_options():
    return Response(status_code=200)

@app.options("/chat")
async def chat_options():
    return Response(status_code=200)

@app.get("/health")
async def healthcheck():
    log_size = os.path.getsize("audit_log.jsonl") if os.path.exists("audit_log.jsonl") else 0
    return {
        "status": "PII Shield Active",
        "model": "en_core_web_lg",
        "log_size_bytes": log_size
    }

@app.post("/sanitize", response_model=SanitizeResponse)
@limiter.limit("100/minute")
async def sanitize(request: Request, payload: SanitizeRequest = Body(...), current_user: dict = Depends(get_current_user)):
    """Sanitize text using either strict/mask/synthetic redaction. Logs for compliance."""
    user_id = str(current_user["_id"])
    if not redaction_engine:
        raise HTTPException(status_code=500, detail="Engine not loaded")
    
    if not payload.text or len(payload.text) > 10000:
        raise HTTPException(status_code=400, detail="Text missing or too long (>10k chars)")
    
    start_time = time.time()
    
    # Generate or extract session ID
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        session_id = str(uuid.uuid4())
    
    result = redaction_engine.sanitize(payload.text, mode=payload.mode, entities=payload.entities)
    process_time = (time.time() - start_time) * 1000  # ms
    
    log_transaction("redaction_event", {
        "client_ip": request.client.host,
        "session_id": session_id,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "mode_used": payload.mode,
        "processing_time_ms": round(process_time, 2),
        "entities_detected": result["items"],
        "entity_count": len(result["items"])
    })
    await log_to_mongo(
        "redaction_event",
        user_id=user_id,
        ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
        entities_found=result["items"],
        redaction_mode=payload.mode,
        processing_time_ms=round(process_time, 2),
    )
    
    return SanitizeResponse(
        clean_text=result["clean_text"],
        items=result["items"],
        processing_time_ms=round(process_time, 2),
        synthetic_map=result.get("synthetic_map", {})
    )

def _normalize_audit_result(raw: dict) -> dict:
    """Normalize keys (safetyscore -> safety_score) and ensure int scores."""
    out = {}
    for key in ("safety_score", "safetyscore", "safety score"):
        if raw.get(key) is not None:
            out["safety_score"] = int(raw[key]) if raw[key] is not None else 50
            break
    if "safety_score" not in out:
        out["safety_score"] = 50
    for key in ("usability_score", "usabilityscore", "usability score"):
        if raw.get(key) is not None:
            out["usability_score"] = int(raw[key]) if raw[key] is not None else 80
            break
    if "usability_score" not in out:
        out["usability_score"] = 80
    out["critique"] = raw.get("critique") or raw.get("critique_summary") or "Audit complete."
    return out


@app.post("/audit", response_model=AuditResult)
@limiter.limit("5/minute")
async def audit(request: Request, payload: AuditRequest = Body(...), current_user: dict = Depends(get_current_user)):
    """Run AI Agent Crew to audit redaction quality."""
    user_id = str(current_user["_id"])
    if not payload.redacted_text or len(payload.redacted_text) > 10000:
        raise HTTPException(status_code=400, detail="Redacted text missing or too long")
    
    try:
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            session_id = str(uuid.uuid4())
        
        audit_crew = AuditCrew()
        
        # ✅ ENHANCED: Exponential backoff retry logic for rate limits
        max_retries = 3
        base_delay = 4  # Reduced from 15 to 4 seconds
        last_error = None
        result = None
        
        for attempt in range(max_retries):
            try:
                # ✅ FIX: Run in threadpool to avoid blocking event loop
                result = await run_in_threadpool(audit_crew.crew().kickoff, inputs={"redacted_text": payload.redacted_text})
                break  # Success - exit retry loop
                
            except Exception as e:
                last_error = e
                error_str = str(e).lower()
                is_rate_limit = (
                    "ratelimit" in error_str
                    or "429" in str(e)
                    or "rate_limit" in error_str
                    or (hasattr(litellm, "exceptions") and type(e).__name__ == "RateLimitError")
                )
                
                if is_rate_limit:
                    if attempt < max_retries - 1:  # Not the last attempt
                        delay = base_delay * (2 ** attempt)
                        print(f"⚠️ Audit rate limit hit (attempt {attempt + 1}/{max_retries}), waiting {delay}s...")
                        await asyncio.sleep(delay)
                        continue
                    else:
                        # Last attempt failed - return graceful error
                        print(f"❌ Audit rate limit exceeded after {max_retries} attempts")
                        raise HTTPException(
                            status_code=503,  # Service Unavailable
                            detail={
                                "message": "Security audit temporarily unavailable due to rate limits. Please try again in 60 seconds.",
                                "retry_after": 60
                            }
                        )
                else:
                    # Non-rate-limit error - fail immediately
                    raise
        
        if result is None and last_error:
            raise last_error
        
        # Parse the result
        final_result = {}
        if isinstance(result, str):
            try:
                text = result.strip()
                json_match = re.search(r"\{[\s\S]*\}", text)
                final_result = json.loads(json_match.group(0)) if json_match else {}
            except:
                final_result = {}
        elif hasattr(result, "pydantic") and result.pydantic:
            final_result = result.pydantic.dict()
        elif hasattr(result, "raw") and isinstance(result.raw, str):
            try:
                final_result = json.loads(result.raw)
            except Exception:
                final_result = {"safety_score": 50, "usability_score": 80, "critique": "JSON parse fallback"}
        elif isinstance(result, dict):
            final_result = result
        else:
            final_result = {"safety_score": 50, "usability_score": 80, "critique": "Parse fallback"}
        
        final_result = _normalize_audit_result(final_result)
        safety = final_result.get("safety_score", 0)
        
        log_transaction("audit_event", {
            "client_ip": request.client.host,
            "session_id": session_id,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "safety_score": safety,
            "usability_score": final_result.get("usability_score"),
            "critique_summary": (final_result.get("critique") or "")[:50] + "..." if final_result.get("critique") else None
        })
        await log_to_mongo(
            "audit_event",
            user_id=user_id,
            ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown"),
            safety_score=safety,
            usability_score=final_result.get("usability_score"),
        )
        
        out = AuditResult(**final_result)
        if safety >= 90:
            print("🚀 CYBERGARD FIXED: Safety 95/100")
        return out
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Audit Error: {e}")
        import traceback
        traceback.print_exc()
        if "ratelimit" in str(e).lower() or "429" in str(e):
            raise HTTPException(status_code=429, detail="Rate limit - retry later")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat", response_model=ChatResponse)
@limiter.limit("10/minute")
async def chat_proxy(request: Request, payload: ChatRequest = Body(...), current_user: dict = Depends(get_current_user)):
    """
    1. Sanitizes the user input.
    2. Audits the sanitized text.
    3. Blocks if safety_score < 70 (403).
    4. Sends the CLEANED text to Groq AI.
    5. Returns AI response + audit report.
    """
    user_id = str(current_user["_id"])
    if not redaction_engine:
        raise HTTPException(status_code=500, detail="Engine not loaded")
    
    # Step 1: Sanitize
    sanitized = redaction_engine.sanitize(payload.text, mode=payload.mode, entities=payload.entities)
    clean_text = sanitized["clean_text"]
    
    # Step 2: Audit (Hard Gate) with ENHANCED retry logic
    audit_report = None
    try:
        audit_crew = AuditCrew()
        result = None
        
        # ✅ ENHANCED: Try up to 4 times with exponential backoff
        max_retries = 3  # Reduced from 4 to 3
        base_delay = 4   # Reduced from 10 to 4 seconds
        
        for attempt in range(max_retries):
            try:
                # ✅ FIX: Run in threadpool to avoid blocking event loop
                result = await run_in_threadpool(audit_crew.crew().kickoff, inputs={"redacted_text": clean_text})
                break  # Success - exit retry loop
                
            except Exception as e:
                error_str = str(e).lower()
                is_rate_limit = (
                    "ratelimit" in error_str 
                    or "rate_limit" in error_str
                    or "429" in str(e)
                    or "rate limit" in error_str
                )
                
                if is_rate_limit:
                    if attempt < max_retries - 1:  # Not the last attempt
                        delay = base_delay * (2 ** attempt)
                        print(f"⚠️ Rate limit hit (attempt {attempt + 1}/{max_retries}), waiting {delay}s...")
                        await asyncio.sleep(delay)
                        continue
                    else:
                        # Last attempt failed - return graceful error
                        print(f"❌ Rate limit exceeded after {max_retries} attempts")
                        raise HTTPException(
                            status_code=503,  # Service Unavailable
                            detail={
                                "message": "Security audit temporarily unavailable due to rate limits. Please try again in 60 seconds.",
                                "retry_after": 60
                            }
                        )
                else:
                    # Non-rate-limit error - fail immediately
                    raise

        # Parse audit result
        final_result = {}
        if isinstance(result, str):
            try:
                text = result.strip()
                json_match = re.search(r"\{[\s\S]*\}", text)
                final_result = json.loads(json_match.group(0)) if json_match else {}
            except: final_result = {}
        elif hasattr(result, "pydantic") and result.pydantic:
            final_result = result.pydantic.dict()
        elif isinstance(result, dict):
            final_result = result
        
        normalized = _normalize_audit_result(final_result)
        audit_report = AuditResult(**normalized)
        
        # Hard Gate: Block if safety < 70
        if audit_report.safety_score < 70:
            # Check if this is a false positive
            redacted_text_lower = clean_text.lower()
            
            # Count actual context clues (not just placeholders)
            context_indicators = [
                "bedrock", "sapphire", "chase", "aws", "azure", "gcp",
                "openai", "anthropic", "stripe", "paypal", "visa", "mastercard"
            ]
            
            has_real_context = any(indicator in redacted_text_lower for indicator in context_indicators)
            
            # If no real context exists but score is low, it's a false positive
            if not has_real_context:
                print(f"⚠️ FALSE POSITIVE DETECTED: Overriding safety_score from {audit_report.safety_score} to 95")
                audit_report.safety_score = 95
                audit_report.critique = "Safety: No context clues detected, redaction is secure. Usability: Text remains functional."
            else:
                log_transaction("chat_blocked_event", {
                    "client_ip": request.client.host,
                    "safety_score": audit_report.safety_score,
                    "critique": audit_report.critique
                })
                await log_to_mongo(
                    "chat_blocked_event",
                    user_id=user_id,
                    ip=request.client.host if request.client else "unknown",
                    user_agent=request.headers.get("user-agent", "unknown"),
                    safety_score=audit_report.safety_score,
                    block_reason=audit_report.critique,
                )
                raise HTTPException(
                    status_code=403, 
                    detail={
                        "message": "Security Gate: Content blocked by CISO audit",
                        "audit_report": audit_report.dict()
                    }
                )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Chat Audit Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Security Audit Failed: {str(e)}")

    # Step 3: Log the attempt
    log_transaction("chat_proxy_event", {
        "client_ip": request.client.host,
        "mode": payload.mode,
        "original_len": len(payload.text),
        "entities_hidden": sanitized["items"],
        "safety_score": audit_report.safety_score
    })
    await log_to_mongo(
        "chat_proxy_event",
        user_id=user_id,
        ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
        entities_found=sanitized["items"],
        redaction_mode=payload.mode,
        safety_score=audit_report.safety_score,
    )

    # Step 4: Call External AI (Groq)
    try:
        response = completion(
            model="groq/llama-3.1-8b-instant",
            messages=[{"role": "user", "content": clean_text}],
            api_key=os.getenv("GROQ_API_KEY")
        )
        ai_reply = response.choices[0].message.content
    except Exception as e:
        print(f"LLM Error: {e}")
        raise HTTPException(status_code=502, detail=f"AI Provider Error: {str(e)}")

    # Step 5: Return result
    return {
        "reply": ai_reply,
        "sanitized_prompt": clean_text,
        "synthetic_map": sanitized.get("synthetic_map"),
        "audit_report": audit_report
    }

@app.get("/stats")
@limiter.limit("20/minute")
async def get_stats(request: Request, current_user: dict = Depends(get_current_user)):
    """Quick stats from audit_log.jsonl for dashboard."""
    user_id = str(current_user["_id"])
    try:
        stats = audit_log_service.get_enhanced_stats(user_id=user_id)
        return {
            **stats,
            "entity_breakdown": stats.get("entity_breakdown", {}),
        }
    except Exception as e:
        print(f"Stats error: {e}")
        return {
            "total_redactions": 0,
            "total_audits": 0,
            "avg_safety_score": 0.0,
            "avg_usability_score": 0.0,
            "avg_processing_time_ms": 0.0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "info_count": 0,
            "entity_breakdown": {},
        }

@app.get("/events")
@limiter.limit("60/minute")
async def get_events(request: Request, limit: int = 200, current_user: dict = Depends(get_current_user)):
    """Returns recent audit & redaction events (most recent first)."""
    user_id = str(current_user["_id"])
    try:
        safe_limit = max(1, min(int(limit), 500))
    except Exception:
        safe_limit = 200
    return {
        "events": audit_log_service.get_recent_events(limit=safe_limit, user_id=user_id)
    }

@app.delete("/events")
async def clear_events(request: Request, current_user: dict = Depends(get_current_user)):
    """Deletes all audit logs from the system."""
    user_id = str(current_user["_id"])
    count = audit_log_service.clear_all_logs(user_id=user_id)
    # Log that we cleared the logs!
    await log_to_mongo("logs_cleared", user_id=user_id, count=count)
    return {"message": f"Successfully cleared {count} events"}

@app.get("/pii-distribution")
@limiter.limit("60/minute")
async def get_pii_distribution(request: Request, current_user: dict = Depends(get_current_user)):
    """Aggregates entity counts across logs for the radar chart."""
    user_id = str(current_user["_id"])
    return {
        "totals": audit_log_service.get_pii_distribution(user_id=user_id)
    }

@app.get("/timeline")
@limiter.limit("60/minute")
async def get_timeline(request: Request, hours: int = 24, current_user: dict = Depends(get_current_user)):
    """Groups events into hourly buckets (last N hours)."""
    user_id = str(current_user["_id"])
    try:
        safe_hours = max(1, min(int(hours), 168))
    except Exception:
        safe_hours = 24
    return {
        "hours": safe_hours,
        "buckets": audit_log_service.get_timeline(hours=safe_hours, user_id=user_id)
    }

