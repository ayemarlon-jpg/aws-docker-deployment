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


def test_addin_manifest_rendered(monkeypatch):
    import xml.etree.ElementTree as ET
    main._manifest.cache_clear()
    monkeypatch.setattr(main.settings, "public_base_url", "https://phishguard.example.com")
    r = client.get("/addin/manifest.xml")
    main._manifest.cache_clear()
    assert r.status_code == 200 and "{{" not in r.text
    root = ET.fromstring(r.content)
    ns = {"o": "http://schemas.microsoft.com/office/appforoffice/1.1"}
    assert root.find("o:SourceLocation", ns) is None  # sanity: namespaced parse works
    assert "https://phishguard.example.com/addin/taskpane.html" in r.text
    assert "http://" not in r.text.replace("http://schemas", "").replace("http://www.w3.org", "")


def test_addin_static_files():
    for path in ["/addin/taskpane.html", "/addin/taskpane.js", "/addin/commands.html", "/addin/assets/icon-80.png"]:
        assert client.get(path).status_code == 200, path


def test_legal_pages():
    for path in ["/privacy", "/terms", "/support"]:
        r = client.get(path)
        assert r.status_code == 200 and "{{" not in r.text, path
