from pydantic import BaseModel, Field
from typing import List, Optional, Dict

# --- PHASE 1 MODELS: Redaction Engine ---
class SanitizeRequest(BaseModel):
    text: str
    mode: str = Field("strict", pattern=r"^(strict|synthetic|mask)$", description="Redaction mode")
    entities: Optional[List[str]] = None

class SanitizeResponse(BaseModel):
    clean_text: str
    items: List[str]
    processing_time_ms: float
    synthetic_map: Optional[Dict[str, str]] = None

# --- PHASE 2 MODELS: Audit Crew ---
class AuditRequest(BaseModel):
    redacted_text: str

class AuditResult(BaseModel):
    safety_score: int
    usability_score: int
    critique: str

# --- PHASE 3 MODELS: True Proxy (Chat) ---
class ChatRequest(BaseModel):
    text: str
    mode: str = Field("synthetic", pattern=r"^(strict|synthetic|mask)$", description="Redaction mode")
    entities: Optional[List[str]] = None

class ChatResponse(BaseModel):
    reply: Optional[str] = None
    sanitized_prompt: str
    synthetic_map: Optional[Dict[str, str]] = None
    audit_report: Optional[AuditResult] = None