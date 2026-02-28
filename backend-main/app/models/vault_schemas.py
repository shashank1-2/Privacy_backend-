from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr


class FileMetadataResponse(BaseModel):
    id: str
    filename: str
    display_name: str
    size_bytes: int
    mime_type: str
    file_hash: str
    uploaded_at: str
    is_deleted: bool = False
    pii_scan: dict = {}


class SecurityConfig(BaseModel):
    expiry_hours: int = Field(default=24, ge=1, le=168)
    max_views: int = Field(default=0, ge=0)
    burn_after_reading: bool = False
    allowed_countries: List[str] = Field(default_factory=list)
    allowed_cities: List[str] = Field(default_factory=list)
    block_vpn: bool = False
    require_device_lock: bool = False
    # SCREENSHOT-TOGGLE
    allow_screenshots: bool = True
    watermark_text: Optional[str] = None


class ShareLinkCreate(BaseModel):
    file_id: str
    recipient_email: EmailStr
    access_code: str = Field(..., min_length=4)
    security: SecurityConfig = Field(default_factory=SecurityConfig)


class ShareLinkResponse(BaseModel):
    id: str
    token: str
    file_id: str
    recipient_email: str
    status: str
    created_at: str
    security: dict
    share_url: str
    access_code: Optional[str] = None


class VerifyRequest(BaseModel):
    email: EmailStr
    access_code: str


class VerifyResponse(BaseModel):
    view_token: str
    expires_in_minutes: int = 15
    filename: str
    mime_type: str
    file_size: int
    # SCREENSHOT-TOGGLE
    allow_screenshots: bool = True
    watermark_text: Optional[str] = None


class KillSwitchResponse(BaseModel):
    revoked_count: int
    message: str


class RiskScoreResponse(BaseModel):
    token: str
    score: int = Field(ge=0, le=100)
    level: str
    factors: List[dict] = Field(default_factory=list)
    recommendation: str
