"""Heuristic URL analysis."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from phishguard.models import Finding, Severity

NAME = "url"

DEFAULT_BRANDS = [
    "paypal", "apple", "microsoft", "office365", "outlook", "google", "gmail",
    "amazon", "netflix", "facebook", "instagram", "linkedin", "dropbox",
    "docusign", "adobe", "chase", "wellsfargo", "bankofamerica", "citibank",
    "coinbase", "binance", "dhl", "fedex", "ups", "usps", "irs", "hmrc",
    "steam", "whatsapp", "icloud", "onedrive", "sharepoint", "stripe",
]

# Registrable domains legitimately owned by brands (avoids flagging the real thing).
BRAND_OWNED_DOMAINS = {
    "paypal.com", "apple.com", "icloud.com", "microsoft.com", "office.com",
    "office365.com", "outlook.com", "live.com", "microsoftonline.com",
    "sharepoint.com", "onedrive.com", "google.com", "gmail.com", "youtube.com",
    "amazon.com", "amazon.co.uk", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "docusign.com", "docusign.net", "adobe.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "citi.com",
    "coinbase.com", "binance.com", "dhl.com", "fedex.com", "ups.com", "usps.com",
    "irs.gov", "gov.uk", "steampowered.com", "whatsapp.com", "stripe.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "rest", "fit", "cam", "icu", "monster", "buzz", "live",
    "quest", "sbs", "cfd",
}

FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com",
    "web.app", "pages.dev", "netlify.app", "vercel.app", "glitch.me",
    "herokuapp.com", "blogspot.com", "github.io", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "workers.dev", "r2.dev", "ipfs.io", "duckdns.org",
}

PHISHY_PATH_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "wallet", "unlock",
    "suspend", "billing", "invoice", "webscr", "auth", "recover", "validate",
]

MULTI_PART_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "gov.uk", "ac.uk", "co.nz", "com.mx"}

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""")

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def extract_urls(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(".,;:!?'\"")
        if url.lower().startswith("www."):
            url = "http://" + url
        seen.setdefault(url, None)
    return list(seen)


def registrable_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Decimal / hex encoded IPv4 (e.g. http://3232235777 or 0xC0A80001)
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host, re.I))


def brand_lookalike(domain: str, brands: list[str]) -> str | None:
    """Return the brand a domain appears to imitate, or None."""
    if domain in BRAND_OWNED_DOMAINS:
        return None
    label = domain.split(".")[0]
    normalized = label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    tokens = [t for t in normalized.split("-") if t]
    for brand in brands:
        for token in tokens:
            # paypal.xyz, paypa1-security.com, micros0ft-support.net
            if token == brand:
                return brand
            # one typo away: paypai, amazom (short brands like "ups" are too collision-prone)
            if len(brand) >= 5 and len(token) >= 4 and _levenshtein(token, brand) == 1:
                return brand
            # brand glued to a word: appleid, paypalsecure
            if len(brand) >= 5 and token.startswith(brand):
                return brand
    return None


def analyze_url(url: str, protected_brands: list[str] | None = None, trusted_domains: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    brands = list(dict.fromkeys(DEFAULT_BRANDS + (protected_brands or [])))
    trusted = set(trusted_domains or [])

    def add(rule: str, severity: Severity, description: str) -> None:
        findings.append(Finding(analyzer=NAME, rule=rule, severity=severity, description=description, evidence=url))

    raw = url.strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", raw):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
    except ValueError:
        add("malformed_url", Severity.medium, "URL could not be parsed")
        return findings

    if not host:
        add("malformed_url", Severity.medium, "URL has no host")
        return findings

    domain = registrable_domain(host)
    if domain in trusted or host in trusted:
        return findings

    if parts.scheme.lower() == "data":
        add("data_uri", Severity.high, "data: URI can embed a full phishing page")
    if parts.scheme.lower() == "javascript":
        add("javascript_uri", Severity.critical, "javascript: URI executes code")

    if _is_ip(host):
        add("ip_host", Severity.high, "Link points to a raw IP address instead of a domain")

    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", Severity.high, "Internationalized (punycode) domain, often used for homograph attacks")

    if "@" in (parts.netloc or ""):
        add("userinfo_trick", Severity.high, "URL contains '@'; the real destination is after the '@'")

    if parts.scheme.lower() == "http":
        add("no_tls", Severity.low, "Link uses unencrypted HTTP")

    if parts.port and parts.port not in (80, 443):
        add("non_standard_port", Severity.medium, f"Non-standard port {parts.port}")

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", Severity.medium, f"Top-level domain .{tld} is heavily abused")

    if domain in SHORTENERS:
        add("url_shortener", Severity.medium, "URL shortener hides the real destination")

    if domain in FREE_HOSTING or any(host.endswith("." + h) for h in FREE_HOSTING):
        add("free_hosting", Severity.medium, "Hosted on a free/temporary hosting platform")

    if host.count(".") >= 4:
        add("many_subdomains", Severity.medium, "Unusually deep subdomain nesting")

    if host.count("-") >= 3:
        add("many_hyphens", Severity.low, "Domain contains many hyphens")

    if len(raw) > 120:
        add("long_url", Severity.low, "Very long URL, may hide the real destination")

    brand = brand_lookalike(domain, brands)
    if brand:
        add("brand_lookalike", Severity.critical, f"Domain '{domain}' imitates the brand '{brand}'")
    else:
        # Brand name buried in a subdomain: paypal.com.account-verify.ru
        sub = host[: -len(domain)].strip(".")
        for b in brands:
            if b in sub.split(".") or f"{b}.com" in sub:
                add("brand_in_subdomain", Severity.high, f"Brand '{b}' used in subdomain of unrelated domain '{domain}'")
                break

    path = unquote((parts.path or "") + "?" + (parts.query or "")).lower()
    hits = [w for w in PHISHY_PATH_WORDS if w in path]
    if len(hits) >= 2:
        add("phishy_path", Severity.medium, f"Path contains credential-related words: {', '.join(hits[:5])}")
    elif hits:
        add("phishy_path", Severity.low, f"Path contains credential-related word: {hits[0]}")

    if re.search(r"(?i)https?%3a%2f%2f|[?&](url|redirect|next|goto|dest|target)=https?", parts.query or ""):
        add("open_redirect", Severity.medium, "URL carries an embedded redirect target")

    if re.search(r"\.(exe|scr|js|vbs|hta|iso|img|msi|bat|cmd|ps1|apk)$", (parts.path or "").lower()):
        add("executable_download", Severity.high, "Link downloads an executable file")

    return findings
