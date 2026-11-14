"""Command-line scanner.

    python -m phishguard.cli message.eml [more.eml ...]
    python -m phishguard.cli --url "http://paypa1-login.xyz/verify"
    python -m phishguard.cli --no-llm message.eml

Exit code is 2 if any input is phishing, 1 if suspicious, 0 otherwise (handy in scripts/CI).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard.config import get_settings
from phishguard.email_parser import parse_raw
from phishguard.engine import PhishingEngine
from phishguard.models import AnalysisReport, Verdict

COLORS = {Verdict.safe: "\033[32m", Verdict.suspicious: "\033[33m", Verdict.phishing: "\033[31m"}


def _print(name: str, report: AnalysisReport) -> None:
    color = COLORS[report.verdict] if sys.stdout.isatty() else ""
    reset = "\033[0m" if color else ""
    print(f"{color}{report.verdict.value.upper():<11}{reset} risk={report.risk_score:>3}  {name}")
    if report.llm:
        print(f"    AI: {report.llm.attack_type} / {report.llm.impersonated_brand} ({report.llm.confidence:.0%})")
        for r in report.llm.reasons[:4]:
            print(f"      - {r}")
    elif report.llm_status != "disabled":
        print(f"    AI: {report.llm_status}")
    for f in report.findings[:8]:
        if f.points:
            print(f"    [{f.severity.value:<8}] {f.description}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PhishGuard phishing scanner")
    ap.add_argument("files", nargs="*", type=Path, help=".eml files to scan")
    ap.add_argument("--url", action="append", default=[], help="URL to scan (repeatable)")
    ap.add_argument("--no-llm", action="store_true", help="Heuristics only, don't call Claude")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args(argv)
    if not args.files and not args.url:
        ap.error("give at least one .eml file or --url")

    engine = PhishingEngine(get_settings())
    worst = Verdict.safe
    results = []
    for path in args.files:
        results.append((str(path), engine.analyze_email(parse_raw(path.read_bytes()), use_llm=not args.no_llm)))
    for url in args.url:
        results.append((url, engine.analyze_url(url, use_llm=not args.no_llm)))

    for name, report in results:
        if args.json:
            print(json.dumps({"input": name, **report.model_dump(mode="json")}))
        else:
            _print(name, report)
        if report.verdict == Verdict.phishing or (report.verdict == Verdict.suspicious and worst == Verdict.safe):
            worst = report.verdict
    return {Verdict.safe: 0, Verdict.suspicious: 1, Verdict.phishing: 2}[worst]


if __name__ == "__main__":
    sys.exit(main())
