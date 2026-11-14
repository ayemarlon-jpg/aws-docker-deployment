"""Send alerts for detected phishing to a webhook (Slack, Teams, or any JSON endpoint)."""

from __future__ import annotations

import json
import logging
import urllib.request

from phishguard.models import AnalysisReport

log = logging.getLogger(__name__)


def format_alert(report: AnalysisReport, source: str) -> str:
    lines = [
        f":rotating_light: *PhishGuard: {report.verdict.value.upper()}* (risk {report.risk_score}/100) - {source}",
    ]
    for key, value in report.summary.items():
        if value:
            lines.append(f"*{key}:* {value}")
    if report.llm:
        lines.append(f"*AI:* {report.llm.attack_type}, impersonating {report.llm.impersonated_brand} "
                     f"(confidence {report.llm.confidence:.0%})")
        lines += [f"  - {r}" for r in report.llm.reasons[:5]]
    top = [f for f in report.findings if f.points > 0][:5]
    if top:
        lines.append("*Top signals:*")
        lines += [f"  - [{f.severity.value}] {f.description}" for f in top]
    return "\n".join(lines)


def send_webhook(url: str | None, report: AnalysisReport, source: str) -> bool:
    if not url:
        return False
    payload = {
        "text": format_alert(report, source),
        "verdict": report.verdict.value,
        "risk_score": report.risk_score,
        "summary": report.summary,
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        log.warning("Webhook delivery failed: %s", exc)
        return False
