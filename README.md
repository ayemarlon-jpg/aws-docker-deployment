# PhishGuard: AI phishing detection

PhishGuard checks emails and URLs for phishing. It runs as a Python service in Docker and can be deployed to AWS. Every message goes through two layers:

1. **Rule-based detectors.** These are fast, free, and run offline:
   - **Headers:** SPF/DKIM/DMARC failures, Reply-To and Return-Path mismatches, lookalike sender domains, display-name spoofing ("PayPal" from `gmail.com`), executive names on free webmail.
   - **URLs:** raw IPs, punycode/homograph domains, brand lookalikes (`paypa1`, `micros0ft-support`), brands buried in subdomains (`paypal.com.verify.ru`), the `@` userinfo trick, shorteners, abused TLDs, free hosting, open redirects, executable downloads.
   - **Content:** urgency and threat language, requests for credentials, sensitive data or payment, gift-card BEC, secrecy requests, links whose visible text doesn't match where they go, embedded forms, and dangerous attachments (`.exe`, `.pdf.exe`, macro Office files, HTML/SVG attachments).
2. **AI analysis with Claude.** Claude reads the message together with the rule findings and returns a structured verdict: phishing, suspicious or safe, plus confidence, attack type, the brand being impersonated, reasons and a recommended action. It catches attacks that rules miss, such as well-written BEC or invoice fraud from a clean-looking domain, and it discounts false positives.

The two scores are combined into a **risk score from 0 to 100**. Hard technical evidence (for example an executable attachment) can't be outvoted by the AI. A confident AI phishing verdict can escalate a message that looks clean to the rules. If the AI call fails, PhishGuard falls back to the rule-based score.

## Automation

| Mode | What it does |
|---|---|
| **REST API** | `POST /api/v1/analyze/email`, `/analyze/eml` (file upload), `/analyze/url`. Hook it into your mail gateway, SOAR or ticketing system. |
| **Mailbox monitor** | Watches an IMAP inbox (for example a shared "report phishing" mailbox). It tags each new message, sends a webhook alert for anything suspicious, and can move phishing to a quarantine folder. |
| **Webhook alerts** | Sends JSON alerts to Slack, Teams or any endpoint you configure. |
| **CLI** | `python -m phishguard.cli *.eml`. The exit code is 0, 1 or 2 (safe, suspicious, phishing), so you can use it in scripts. |
| **Outlook add-in** | A **Check for phishing** button inside Outlook (desktop, web and mobile), ready to list on Microsoft AppSource. See [docs/microsoft-marketplace.md](docs/microsoft-marketplace.md). |
| **Web UI** | Open `http://localhost:8000/` and paste a message source, upload a `.eml` file, or enter a URL. |

## Quick start

```bash
cp .env.example .env        # set ANTHROPIC_API_KEY (and optionally the IMAP/webhook settings)
docker compose up -d --build
open http://localhost:8000  # UI; API docs at /docs
```

To also run the automated mailbox monitor:

```bash
docker compose --profile mailbox up -d
```

Running locally without Docker:

```bash
pip install -r requirements-dev.txt
pytest -q
uvicorn phishguard.main:app --reload
python -m phishguard.cli --no-llm tests/samples/*.eml
```

### API example

```bash
curl -s localhost:8000/api/v1/analyze/email \
  -H 'Content-Type: application/json' \
  -d '{"sender":"PayPal <service@paypa1-security.com>","subject":"Account suspended",
       "body":"Verify your account within 24 hours: http://paypa1-security.com.verify.xyz/login"}'
```

The response looks like this:

```json
{
  "verdict": "phishing",
  "risk_score": 92,
  "heuristic_score": 88,
  "findings": [{"analyzer": "url", "rule": "brand_lookalike", "severity": "critical", "...": "..."}],
  "llm": {"verdict": "phishing", "confidence": 0.97, "attack_type": "credential_harvesting",
          "impersonated_brand": "PayPal", "reasons": ["..."], "recommended_action": "..."},
  "llm_status": "ok (claude-opus-5-5)"
}
```

## Configuration

All settings are environment variables. See [`.env.example`](.env.example) for the full list. The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | – | Turns on the AI analysis |
| `PHISHGUARD_LLM_MODEL` | `claude-opus-5-5` | Claude model |
| `PHISHGUARD_LLM_EFFORT` | `medium` | `low` is faster and cheaper; `high` is more thorough |
| `PHISHGUARD_LLM_WEIGHT` | `0.5` | Share of the final score that comes from the AI verdict |
| `PHISHGUARD_TRUSTED_DOMAINS` | – | Your own domains; spoofing heuristics are skipped for them |
| `PHISHGUARD_PROTECTED_BRANDS` | – | Your company, vendors and bank, so lookalikes of them get flagged |
| `PHISHGUARD_API_KEY` | – | When set, requests must send an `X-API-Key` header |
| `PHISHGUARD_WEBHOOK_URL` | – | Where alerts are sent |
| `IMAP_*` | – | Mailbox monitor connection; `IMAP_QUARANTINE=true` moves phishing out of the inbox |

## Deploying to AWS

**To put it online for anyone to use**, follow [docs/deploy-aws.md](docs/deploy-aws.md). It takes about 15 minutes of one-time setup:
1. Upload [`infra/aws-lightsail.yml`](infra/aws-lightsail.yml) to CloudFormation. This creates a Lightsail container service with a public HTTPS address, plus a deploy role that only this repository can use.
2. Paste two values into the GitHub repository variables.
3. Add `ANTHROPIC_API_KEY` as a repository secret.
4. Run the **Deploy to AWS** workflow.

After that, every merge into `main` deploys automatically through [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). No AWS keys are stored in GitHub: the workflow uses GitHub's short-lived OIDC tokens.

A public deployment limits AI checks for anonymous visitors to `PHISHGUARD_AI_LIMIT_PER_IP_HOUR` (default 20) and `PHISHGUARD_AI_LIMIT_PER_DAY` (default 500), so the Claude bill stays bounded. Callers with the organization access key aren't limited, and rule checks are never limited.

The image is a standard container, so it also runs on ECS Fargate, App Runner, or any Docker host. For EC2, install Docker, copy the repo and `.env`, and run `docker compose --profile mailbox up -d`.

## Microsoft Outlook add-in

Once deployed, the server hosts an Outlook add-in at `/addin/manifest.xml`, with your domain filled in from `PHISHGUARD_PUBLIC_BASE_URL`. It also serves the privacy, terms and help pages Microsoft requires at `/privacy`, `/terms` and `/support`. For testing, sideloading and the AppSource submission, follow [docs/microsoft-marketplace.md](docs/microsoft-marketplace.md).

## Security notes

- Email content is treated as **untrusted**. It is passed to Claude inside delimiters, and the system prompt tells the model to ignore instructions inside it. Instructions aimed at the AI count as a phishing signal. The model can only classify; it cannot take actions.
- The mailbox monitor fetches with `BODY.PEEK[]`, so it never marks mail as read. It only moves mail when `IMAP_QUARANTINE=true`.
- The container runs as a non-root user. Set `PHISHGUARD_API_KEY` before exposing the API publicly.

## Project layout

```
phishguard/
  main.py               FastAPI app and web UI
  engine.py             runs the analyzers, scores, and gives the verdict
  email_parser.py       RFC 822 / HTML parsing
  analyzers/            headers.py, url.py, content.py, llm.py (Claude)
  automation/           mailbox.py (IMAP monitor), alerts.py (webhooks)
  addin/                Outlook add-in (manifest template, task pane, icons)
  legal/                privacy policy, terms and support page templates
  cli.py                command-line scanner
tests/                  offline tests and sample phishing/legit emails
```
