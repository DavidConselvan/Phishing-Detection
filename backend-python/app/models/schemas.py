from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any

class URLRequest(BaseModel):
    url: str

class PhishTankResult(BaseModel):
    isPhishing: bool
    phishtank: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class WhoisResult(BaseModel):
    age_days: Optional[int]
    creation_date: Optional[str]
    is_suspicious: bool
    registrar: Optional[str]
    expiration_date: Optional[str]
    organization: Optional[str]
    country: Optional[str]
    error: Optional[str]

class DynamicDNSResult(BaseModel):
    is_dynamic_dns: bool
    domain: str

class SSLResult(BaseModel):
    is_valid: bool
    is_expired: bool
    is_not_valid_yet: bool
    issuer: str
    valid_from: str
    valid_until: str
    domain_match: bool
    is_suspicious: bool
    error: Optional[str]

class BrandSimilarityResult(BaseModel):
    is_suspicious: bool
    reasons: List[str]
    similar_brands: List[Dict[str, Any]]
    target_domain: str

class ContentAnalysisResult(BaseModel):
    is_suspicious: bool
    reasons: List[str]
    suspicious_text: List[str]
    suspicious_forms: List[str]

class MLModelResult(BaseModel):
    label: str
    score: float
    is_suspicious: bool
    error: Optional[str] = None


class PhishingCheckResult(BaseModel):
    url: str
    isPhishing: bool
    reasons: list[str]
    phishtank: Optional[dict] = None
    whois: dict
    ssl: dict
    redirects: dict
    dynamic_dns: Optional[DynamicDNSResult] = None
    brand_similarity: dict
    content_analysis: dict
    ml_model: Optional[MLModelResult] = None