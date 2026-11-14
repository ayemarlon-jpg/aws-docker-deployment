"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip().lower() for item in value.split(",") if item.strip()]


@dataclass
class Settings:
    # LLM
    llm_enabled: bool = field(default_factory=lambda: _bool("PHISHGUARD_LLM_ENABLED", True))
    llm_model: str = field(default_factory=lambda: os.getenv("PHISHGUARD_LLM_MODEL", "claude-opus-5-5"))
    llm_effort: str = field(default_factory=lambda: os.getenv("PHISHGUARD_LLM_EFFORT", "medium"))
    llm_weight: float = field(default_factory=lambda: float(os.getenv("PHISHGUARD_LLM_WEIGHT", "0.5")))
    max_body_chars: int = field(default_factory=lambda: int(os.getenv("PHISHGUARD_MAX_BODY_CHARS", "60000")))

    # Thresholds on the 0-100 risk score
    suspicious_threshold: int = field(default_factory=lambda: int(os.getenv("PHISHGUARD_SUSPICIOUS_THRESHOLD", "30")))
    phishing_threshold: int = field(default_factory=lambda: int(os.getenv("PHISHGUARD_PHISHING_THRESHOLD", "60")))

    # Organisation-specific
    trusted_domains: list[str] = field(default_factory=lambda: _list("PHISHGUARD_TRUSTED_DOMAINS"))
    protected_brands: list[str] = field(default_factory=lambda: _list("PHISHGUARD_PROTECTED_BRANDS"))

    # API protection (optional)
    api_key: str | None = field(default_factory=lambda: os.getenv("PHISHGUARD_API_KEY") or None)

    # Alerting
    webhook_url: str | None = field(default_factory=lambda: os.getenv("PHISHGUARD_WEBHOOK_URL") or None)

    # IMAP mailbox automation
    imap_host: str | None = field(default_factory=lambda: os.getenv("IMAP_HOST") or None)
    imap_port: int = field(default_factory=lambda: int(os.getenv("IMAP_PORT", "993")))
    imap_user: str | None = field(default_factory=lambda: os.getenv("IMAP_USER") or None)
    imap_password: str | None = field(default_factory=lambda: os.getenv("IMAP_PASSWORD") or None)
    imap_folder: str = field(default_factory=lambda: os.getenv("IMAP_FOLDER", "INBOX"))
    imap_quarantine_folder: str = field(default_factory=lambda: os.getenv("IMAP_QUARANTINE_FOLDER", "Phishing-Quarantine"))
    imap_poll_seconds: int = field(default_factory=lambda: int(os.getenv("IMAP_POLL_SECONDS", "60")))
    imap_quarantine: bool = field(default_factory=lambda: _bool("IMAP_QUARANTINE", False))


def get_settings() -> Settings:
    return Settings()
