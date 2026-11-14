"""Orchestrates the analyzers and produces a final risk score and verdict."""

from __future__ import annotations

from phishguard.analyzers.content import analyze_content
from phishguard.analyzers.headers import analyze_headers
from phishguard.analyzers.llm import ClaudeAnalyzer, build_email_prompt, build_url_prompt
from phishguard.analyzers.url import analyze_url, extract_urls
from phishguard.config import Settings
from phishguard.email_parser import ParsedEmail
from phishguard.models import AnalysisReport, Finding, LLMAssessment, Severity, Verdict

MAX_URLS = 50


def heuristic_score(findings: list[Finding]) -> int:
    """Sum finding points with diminishing returns per rule, capped at 100."""
    seen: dict[str, int] = {}
    total = 0.0
    for f in sorted(findings, key=lambda f: -f.points):
        count = seen.get(f.rule, 0)
        total += f.points / (2 ** count)  # repeated hits of the same rule count less
        seen[f.rule] = count + 1
    # Any critical finding puts the message at least in phishing territory.
    if any(f.severity == Severity.critical for f in findings):
        total = max(total, 65)
    return min(100, round(total))


def llm_score(assessment: LLMAssessment) -> int:
    base = {Verdict.safe: 5, Verdict.suspicious: 50, Verdict.phishing: 95}[assessment.verdict]
    # Low confidence pulls the score toward the uncertain middle.
    return round(base * assessment.confidence + 50 * (1 - assessment.confidence))


def verdict_for(score: int, settings: Settings) -> Verdict:
    if score >= settings.phishing_threshold:
        return Verdict.phishing
    if score >= settings.suspicious_threshold:
        return Verdict.suspicious
    return Verdict.safe


class PhishingEngine:
    def __init__(self, settings: Settings, llm: ClaudeAnalyzer | None = None) -> None:
        self.settings = settings
        self.llm = llm if llm is not None else ClaudeAnalyzer(settings)

    def _combine(self, findings: list[Finding], urls: list[str], prompt: str | None, use_llm: bool, summary: dict) -> AnalysisReport:
        h_score = heuristic_score(findings)
        assessment, status = None, "disabled"
        if use_llm and self.settings.llm_enabled and prompt is not None:
            assessment, status = self.llm.assess(prompt)

        if assessment is not None:
            w = self.settings.llm_weight
            score = round(h_score * (1 - w) + llm_score(assessment) * w)
            # Never let the model talk down hard technical evidence (e.g. a .exe attachment).
            if any(f.severity == Severity.critical for f in findings):
                score = max(score, self.settings.phishing_threshold)
            # A confident AI phishing verdict is enough on its own (catches clean-looking BEC).
            if assessment.verdict == Verdict.phishing and assessment.confidence >= 0.85:
                score = max(score, self.settings.phishing_threshold)
        else:
            score = h_score

        score = max(0, min(100, score))
        return AnalysisReport(
            verdict=verdict_for(score, self.settings),
            risk_score=score,
            heuristic_score=h_score,
            findings=sorted(findings, key=lambda f: -f.points),
            urls=urls,
            llm=assessment,
            llm_status=status,
            summary=summary,
        )

    def analyze_email(self, parsed: ParsedEmail, use_llm: bool = True) -> AnalysisReport:
        s = self.settings
        findings: list[Finding] = []
        findings += analyze_headers(parsed, s.protected_brands, s.trusted_domains)
        findings += analyze_content(parsed)

        urls = extract_urls(parsed.text + "\n" + parsed.html)
        for link in parsed.html_links:
            if link.href.lower().startswith(("http://", "https://")) and link.href not in urls:
                urls.append(link.href)
        urls = urls[:MAX_URLS]
        for url in urls:
            findings += analyze_url(url, s.protected_brands, s.trusted_domains)

        prompt = build_email_prompt(parsed, urls, findings, s.max_body_chars)
        summary = {"from": parsed.from_addr or None, "subject": parsed.subject or None, "reply_to": parsed.reply_to or None}
        return self._combine(findings, urls, prompt, use_llm, summary)

    def analyze_url(self, url: str, use_llm: bool = False) -> AnalysisReport:
        findings = analyze_url(url, self.settings.protected_brands, self.settings.trusted_domains)
        return self._combine(findings, [url], build_url_prompt(url, findings), use_llm, {"url": url})
