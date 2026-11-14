"""PhishGuard HTTP API."""

from __future__ import annotations

import html
import logging
import os
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from phishguard.automation.alerts import send_webhook
from phishguard.config import get_settings
from phishguard.email_parser import from_fields, parse_raw
from phishguard.engine import PhishingEngine
from phishguard.models import AnalysisReport, EmailRequest, UrlRequest, Verdict

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
STATIC = Path(__file__).parent / "static"
ADDIN = Path(__file__).parent / "addin"
LEGAL = Path(__file__).parent / "legal"

settings = get_settings()
engine = PhishingEngine(settings)

app = FastAPI(
    title="PhishGuard",
    description="AI-assisted phishing detection for emails and URLs",
    version="1.0.0",
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def _alert(report: AnalysisReport, source: str) -> None:
    if report.verdict == Verdict.phishing:
        send_webhook(settings.webhook_url, report, source)


def _fill(template: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    return template


@lru_cache
def _manifest() -> str:
    base = settings.public_base_url
    return _fill((ADDIN / "manifest.xml").read_text(), {
        k: html.escape(v, quote=True) for k, v in {
            "BASE_URL": base,
            "ADDIN_ID": settings.addin_id,
            "VERSION": settings.addin_version,
            "PROVIDER": settings.provider_name,
            "SUPPORT_URL": f"{base}/support",
        }.items()
    })


@lru_cache
def _legal_page(name: str) -> str:
    return _fill((LEGAL / f"{name}.html").read_text(), {
        "STYLE": (LEGAL / "_style.css").read_text(),
        **{k: html.escape(v) for k, v in {
            "PROVIDER": settings.provider_name,
            "SUPPORT_EMAIL": settings.support_email,
            "HOSTING_REGION": settings.hosting_region,
            "EFFECTIVE_DATE": settings.legal_effective_date,
        }.items()},
    })


@app.get("/addin/manifest.xml", include_in_schema=False)
def addin_manifest() -> Response:
    """Outlook add-in manifest with this deployment's public URL filled in."""
    return Response(_manifest(), media_type="application/xml",
                    headers={"Content-Disposition": 'inline; filename="manifest.xml"'})


@app.get("/privacy", include_in_schema=False, response_class=HTMLResponse)
def privacy() -> str:
    return _legal_page("privacy")


@app.get("/terms", include_in_schema=False, response_class=HTMLResponse)
def terms() -> str:
    return _legal_page("terms")


@app.get("/support", include_in_schema=False, response_class=HTMLResponse)
def support() -> str:
    return _legal_page("support")


app.mount("/addin", StaticFiles(directory=ADDIN), name="addin")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_enabled": settings.llm_enabled, "model": settings.llm_model if settings.llm_enabled else None}


@app.post("/api/v1/analyze/email", response_model=AnalysisReport, dependencies=[Depends(require_api_key)])
async def analyze_email(req: EmailRequest) -> AnalysisReport:
    if req.raw:
        parsed = parse_raw(req.raw)
    elif any([req.sender, req.subject, req.body, req.html]):
        parsed = from_fields(req.sender, req.reply_to, req.subject, req.body, req.html)
    else:
        raise HTTPException(status_code=422, detail="Provide 'raw' or at least one of sender/subject/body/html")
    report = await run_in_threadpool(engine.analyze_email, parsed, req.use_llm)
    await run_in_threadpool(_alert, report, "api")
    return report


@app.post("/api/v1/analyze/eml", response_model=AnalysisReport, dependencies=[Depends(require_api_key)])
async def analyze_eml(file: UploadFile = File(...), use_llm: bool = True) -> AnalysisReport:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")
    report = await run_in_threadpool(engine.analyze_email, parse_raw(data), use_llm)
    await run_in_threadpool(_alert, report, f"upload {file.filename}")
    return report


@app.post("/api/v1/analyze/url", response_model=AnalysisReport, dependencies=[Depends(require_api_key)])
async def analyze_url(req: UrlRequest) -> AnalysisReport:
    return await run_in_threadpool(engine.analyze_url, req.url, req.use_llm)
