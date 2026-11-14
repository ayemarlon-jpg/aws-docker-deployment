"""Shared data models for PhishGuard."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_POINTS = {
    Severity.info: 0,
    Severity.low: 5,
    Severity.medium: 15,
    Severity.high: 30,
    Severity.critical: 50,
}


class Finding(BaseModel):
    """A single signal raised by an analyzer."""

    analyzer: str
    rule: str
    severity: Severity
    description: str
    evidence: str | None = None

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


class Verdict(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    phishing = "phishing"


class LLMAssessment(BaseModel):
    """Structured verdict returned by Claude."""

    verdict: Verdict
    confidence: float = Field(description="Confidence from 0.0 to 1.0")
    attack_type: str = Field(
        description="e.g. credential_harvesting, bec, malware_delivery, "
        "invoice_fraud, gift_card_scam, none"
    )
    impersonated_brand: str = Field(description="Brand or person impersonated, or 'none'")
    reasons: list[str] = Field(description="Short, concrete reasons for the verdict")
    recommended_action: str


class AnalysisReport(BaseModel):
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    heuristic_score: int = Field(ge=0, le=100)
    findings: list[Finding]
    urls: list[str] = []
    llm: LLMAssessment | None = None
    llm_status: str = "disabled"
    summary: dict[str, str | None] = {}


class EmailRequest(BaseModel):
    """Either a raw RFC 822 message or individual fields."""

    raw: str | None = Field(default=None, description="Full raw email source (.eml)")
    sender: str | None = None
    reply_to: str | None = None
    subject: str | None = None
    body: str | None = None
    html: str | None = None
    use_llm: bool = True


class UrlRequest(BaseModel):
    url: str
    use_llm: bool = False
