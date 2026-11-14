"""Sender / authentication header analysis."""

from __future__ import annotations

import re

from phishguard.analyzers.url import DEFAULT_BRANDS, BRAND_OWNED_DOMAINS, brand_lookalike, registrable_domain
from phishguard.email_parser import ParsedEmail
from phishguard.models import Finding, Severity

NAME = "headers"

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com",
}


def _auth_result(results: str, mech: str) -> str | None:
    match = re.search(rf"\b{mech}\s*=\s*([a-z]+)", results, re.I)
    return match.group(1).lower() if match else None


def analyze_headers(parsed: ParsedEmail, protected_brands: list[str] | None = None, trusted_domains: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    brands = list(dict.fromkeys(DEFAULT_BRANDS + (protected_brands or [])))
    trusted = set(trusted_domains or [])

    def add(rule: str, severity: Severity, description: str, evidence: str | None = None) -> None:
        findings.append(Finding(analyzer=NAME, rule=rule, severity=severity, description=description, evidence=evidence))

    from_domain = parsed.from_domain
    from_reg = registrable_domain(from_domain) if from_domain else ""

    if not parsed.from_addr:
        add("missing_from", Severity.medium, "Message has no valid From address")

    # SPF / DKIM / DMARC from the receiving server's Authentication-Results
    auth = " ".join(parsed.header("authentication-results") + parsed.header("arc-authentication-results"))
    if auth:
        for mech, fail_sev in (("spf", Severity.high), ("dkim", Severity.high), ("dmarc", Severity.critical)):
            result = _auth_result(auth, mech)
            if result in {"fail", "permerror"}:
                add(f"{mech}_fail", fail_sev, f"{mech.upper()} check failed", f"{mech}={result}")
            elif result in {"softfail", "temperror"}:
                add(f"{mech}_softfail", Severity.medium, f"{mech.upper()} check returned {result}", f"{mech}={result}")
            elif result == "none" and mech == "dmarc" and from_reg not in FREE_MAIL:
                add("dmarc_none", Severity.low, "Sender domain publishes no DMARC policy", "dmarc=none")
    for spf in parsed.header("received-spf"):
        verdict = spf.split()[0].lower() if spf.split() else ""
        if verdict in {"fail", "softfail"} and not any(f.rule.startswith("spf_") for f in findings):
            add(f"spf_{verdict}", Severity.high if verdict == "fail" else Severity.medium, f"Received-SPF: {verdict}", spf[:120])

    if from_reg in trusted:
        # Internal/trusted senders still get authentication checks, but skip spoof heuristics.
        return findings

    # Reply-To diverts responses to a different domain (classic BEC)
    if parsed.reply_to and from_domain:
        reply_reg = registrable_domain(parsed.reply_to.rsplit("@", 1)[-1])
        if reply_reg != from_reg:
            sev = Severity.high if reply_reg in FREE_MAIL else Severity.medium
            add("reply_to_mismatch", sev, "Reply-To sends responses to a different domain than From", f"From: {parsed.from_addr} / Reply-To: {parsed.reply_to}")

    if parsed.return_path and from_domain:
        rp_reg = registrable_domain(parsed.return_path.rsplit("@", 1)[-1])
        if rp_reg != from_reg:
            add("return_path_mismatch", Severity.low, "Envelope sender (Return-Path) domain differs from From", f"{parsed.return_path} vs {parsed.from_addr}")

    if from_reg:
        brand = brand_lookalike(from_reg, brands)
        if brand:
            add("sender_domain_lookalike", Severity.critical, f"Sender domain '{from_reg}' imitates '{brand}'", parsed.from_addr)

    # Display name claims a brand, or contains an email address, that doesn't match the real sender
    name = parsed.from_name.lower()
    if name:
        embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
        if embedded and registrable_domain(embedded.group(1)) != from_reg:
            add("display_name_address_spoof", Severity.high, "Display name contains a different email address than the real sender", f"{parsed.from_name} <{parsed.from_addr}>")
        name_tokens = set(re.findall(r"[a-z0-9]+", name))
        for b in brands:
            if b in name_tokens and from_reg not in BRAND_OWNED_DOMAINS and b not in from_reg:
                sev = Severity.high if from_reg in FREE_MAIL else Severity.medium
                add("display_name_brand_spoof", sev, f"Display name claims '{b}' but mail comes from '{from_reg}'", f"{parsed.from_name} <{parsed.from_addr}>")
                break
        if re.search(r"\b(ceo|cfo|president|director|payroll|hr department|it support|helpdesk|admin)\b", name) and from_reg in FREE_MAIL:
            add("executive_freemail", Severity.medium, "Executive/department display name sent from a free webmail account", f"{parsed.from_name} <{parsed.from_addr}>")

    return findings
