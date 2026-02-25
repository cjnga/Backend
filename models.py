from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class ScanRequest(BaseModel):
    content_type: str = Field(..., description="Type: text, link, email, sms, image")
    content: str = Field(..., description="Text content or base64 image data")
    title: Optional[str] = Field(None, description="Optional label for scan")


class ScamMatch(BaseModel):
    title: str
    similarity: float
    source: str
    date: Optional[str] = None


class ScanResult(BaseModel):
    id: Optional[str] = None
    content_type: str
    content_preview: str
    is_spam: bool
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: str  # "safe", "low", "medium", "high", "critical"
    verdict: str
    reasons: List[str]
    probable_source: str
    source_category: str
    matched_scams: List[ScamMatch]
    recommendations: List[str]
    confidence: float
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ScanHistory(BaseModel):
    scans: List[ScanResult]
    total: int
    page: int
    per_page: int


class AuthRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class UserInfo(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    created_at: str


class AuthResponse(BaseModel):
    token: str
    user: UserInfo
