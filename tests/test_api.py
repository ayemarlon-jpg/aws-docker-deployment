import os
from pathlib import Path

os.environ["PHISHGUARD_LLM_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from phishguard import main  # noqa: E402

SAMPLES = Path(__file__).parent / "samples"
client = TestClient(main.app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_index():
    assert "PhishGuard" in client.get("/").text


def test_analyze_raw_email():
    r = client.post("/api/v1/analyze/email", json={"raw": (SAMPLES / "phishing_paypal.eml").read_text()})
    assert r.status_code == 200
    assert r.json()["verdict"] == "phishing"


def test_analyze_eml_upload():
    with open(SAMPLES / "legit_newsletter.eml", "rb") as fh:
        r = client.post("/api/v1/analyze/eml", files={"file": ("n.eml", fh, "message/rfc822")})
    assert r.status_code == 200 and r.json()["verdict"] == "safe"


def test_analyze_url():
    r = client.post("/api/v1/analyze/url", json={"url": "http://paypa1-login.xyz/verify/account"})
    assert r.status_code == 200 and r.json()["verdict"] == "phishing"


def test_empty_email_rejected():
    assert client.post("/api/v1/analyze/email", json={}).status_code == 422


def test_api_key_enforced(monkeypatch):
    monkeypatch.setattr(main.settings, "api_key", "secret")
    assert client.post("/api/v1/analyze/url", json={"url": "https://a.com"}).status_code == 401
    assert client.post("/api/v1/analyze/url", json={"url": "https://a.com"}, headers={"X-API-Key": "secret"}).status_code == 200
