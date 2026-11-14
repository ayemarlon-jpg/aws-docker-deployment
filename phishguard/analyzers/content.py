"""Body, link and attachment analysis."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from phishguard.analyzers.url import registrable_domain
from phishguard.email_parser import ParsedEmail
from phishguard.models import Finding, Severity

NAME = "content"

PATTERNS: list[tuple[str, Severity, str, re.Pattern[str]]] = [
    ("urgency", Severity.medium, "Pressure / urgency language",
     re.compile(r"(?i)\b(urgent(ly)?|immediately|within (24|48|12) hours|act now|final (notice|warning)|"
                r"expires? (today|soon)|last chance|as soon as possible|time[- ]sensitive)\b")),
    ("account_threat", Severity.medium, "Threatens account suspension or loss",
     re.compile(r"(?i)\b(account (will be |has been )?(suspended|locked|disabled|terminated|closed|restricted)|"
                r"unusual (sign[- ]in|activity)|suspicious activity|unauthori[sz]ed (access|login|transaction))\b")),
    ("credential_request", Severity.high, "Asks the recipient to enter or confirm credentials",
     re.compile(r"(?i)\b(verify your (account|identity|password|information)|confirm your (account|password|details|identity)|"
                r"(update|validate) your (payment|billing|account) (info|information|details)|re-?enter your password|"
                r"log ?in to (restore|unlock|verify)|reset your password)\b")),
    ("sensitive_data_request", Severity.high, "Requests sensitive personal or financial data",
     re.compile(r"(?i)\b(social security number|ssn|credit card (number|details)|cvv|bank account (number|details)|"
                r"one[- ]time (code|password)|otp|2fa code|security code|seed phrase|recovery phrase|private key)\b")),
    ("payment_request", Severity.medium, "Unusual payment or wire transfer request",
     re.compile(r"(?i)\b(wire transfer|bank transfer|change of (bank|banking|payment) details|new bank account|"
                r"outstanding invoice|overdue payment|remittance|swift code|iban)\b")),
    ("gift_card", Severity.high, "Gift card request (common BEC scam)",
     re.compile(r"(?i)\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|scratch (off )?the (back|code))\b")),
    ("secrecy", Severity.medium, "Asks for secrecy or to bypass normal process",
     re.compile(r"(?i)\b(keep this (confidential|between us)|don'?t (tell|discuss with) anyone|i'?m in a meeting|"
                r"can'?t talk (now|right now)|are you (available|at your desk))\b")),
    ("prize_lure", Severity.medium, "Prize, refund or lottery lure",
     re.compile(r"(?i)\b(you('ve| have) (won|been selected)|claim your (prize|reward|refund)|lottery|"
                r"tax refund|unclaimed (funds|package)|inheritance)\b")),
    ("crypto_lure", Severity.medium, "Cryptocurrency lure",
     re.compile(r"(?i)\b(bitcoin|btc|ethereum|usdt|crypto ?wallet|airdrop|double your)\b")),
    ("generic_greeting", Severity.low, "Generic greeting instead of your name",
     re.compile(r"(?i)^\s*(dear (customer|user|client|member|account holder|valued customer|sir/madam|sir or madam))", re.M)),
]

DANGEROUS_EXT = {
    "exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "ps1", "msi", "jar", "lnk", "iso", "img", "vhd", "apk", "dll", "cpl",
    "reg", "one", "xll",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
HTML_EXT = {"html", "htm", "shtml", "svg", "xhtml", "mht"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def analyze_content(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, severity: Severity, description: str, evidence: str | None = None) -> None:
        findings.append(Finding(analyzer=NAME, rule=rule, severity=severity, description=description, evidence=evidence))

    text = f"{parsed.subject}\n{parsed.combined_text}"
    for rule, severity, description, pattern in PATTERNS:
        match = pattern.search(text)
        if match:
            add(rule, severity, description, match.group(0)[:120])

    # Links whose visible text shows one domain but whose href goes elsewhere
    for link in parsed.html_links:
        shown = re.search(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", link.text or "")
        try:
            target_host = (urlsplit(link.href).hostname or "").lower()
        except ValueError:
            continue
        if shown and target_host:
            shown_reg = registrable_domain(shown.group(1))
            target_reg = registrable_domain(target_host)
            if shown_reg != target_reg:
                add("link_text_mismatch", Severity.high, f"Link text shows '{shown_reg}' but points to '{target_reg}'", f"{link.text} -> {link.href}"[:200])
        elif link.href.lower().startswith(("javascript:", "data:")):
            add("script_link", Severity.high, "Link uses a javascript:/data: URI", link.href[:120])

    if parsed.has_forms:
        add("embedded_form", Severity.high, "Email contains an HTML form or password field")

    for att in parsed.attachments:
        ext = _ext(att.filename)
        name_lower = att.filename.lower()
        if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(\w{2,4})$", name_lower) and ext in DANGEROUS_EXT | HTML_EXT:
            add("double_extension", Severity.critical, "Attachment uses a double extension to disguise its type", att.filename)
        elif ext in DANGEROUS_EXT:
            add("dangerous_attachment", Severity.critical, f"Executable/script attachment (.{ext})", att.filename)
        elif ext in MACRO_EXT:
            add("macro_attachment", Severity.high, f"Macro-enabled Office attachment (.{ext})", att.filename)
        elif ext in HTML_EXT:
            add("html_attachment", Severity.high, "HTML/SVG attachment (often a local credential-harvesting page)", att.filename)
        elif ext in ARCHIVE_EXT:
            add("archive_attachment", Severity.low, f"Archive attachment (.{ext}) may conceal malware", att.filename)

    return findings
