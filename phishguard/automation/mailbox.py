"""Automated mailbox monitor.

Polls an IMAP mailbox (e.g. a shared "report phishing" inbox, or a user's inbox),
analyzes each new message, tags it, optionally moves phishing to a quarantine folder,
and sends a webhook alert.

Run with:  python -m phishguard.automation.mailbox
"""

from __future__ import annotations

import imaplib
import json
import logging
import os
import re
import signal
import time
from pathlib import Path

from phishguard.automation.alerts import send_webhook
from phishguard.config import Settings, get_settings
from phishguard.email_parser import parse_raw
from phishguard.engine import PhishingEngine
from phishguard.models import AnalysisReport, Verdict

log = logging.getLogger("phishguard.mailbox")

STATE_FILE = Path(os.getenv("PHISHGUARD_STATE_FILE", "/tmp/phishguard_imap_state.json"))
KEYWORDS = {Verdict.phishing: "PhishGuard-Phishing", Verdict.suspicious: "PhishGuard-Suspicious", Verdict.safe: "PhishGuard-Clean"}


class MailboxMonitor:
    def __init__(self, settings: Settings, engine: PhishingEngine | None = None) -> None:
        if not (settings.imap_host and settings.imap_user and settings.imap_password):
            raise ValueError("IMAP_HOST, IMAP_USER and IMAP_PASSWORD must be set")
        self.settings = settings
        self.engine = engine or PhishingEngine(settings)
        self.running = True
        self.last_uid = self._load_state()

    def _load_state(self) -> int | None:
        try:
            return int(json.loads(STATE_FILE.read_text())["last_uid"])
        except Exception:
            return None

    def _save_state(self) -> None:
        try:
            STATE_FILE.write_text(json.dumps({"last_uid": self.last_uid}))
        except OSError as exc:
            log.warning("Could not persist state: %s", exc)

    def connect(self) -> imaplib.IMAP4_SSL:
        conn = imaplib.IMAP4_SSL(self.settings.imap_host, self.settings.imap_port)
        conn.login(self.settings.imap_user, self.settings.imap_password)
        conn.select(self.settings.imap_folder)
        return conn

    def _new_uids(self, conn: imaplib.IMAP4_SSL) -> list[int]:
        if self.last_uid is None:
            # First run: only watch mail that arrives from now on.
            typ, data = conn.uid("SEARCH", None, "ALL")
            uids = [int(u) for u in (data[0] or b"").split()]
            self.last_uid = max(uids) if uids else 0
            self._save_state()
            log.info("Starting after UID %s", self.last_uid)
            return []
        typ, data = conn.uid("SEARCH", None, f"UID {self.last_uid + 1}:*")
        # IMAP returns the highest existing UID for "N:*" even when it is < N.
        return sorted(u for u in (int(x) for x in (data[0] or b"").split()) if u > self.last_uid)

    def handle(self, conn: imaplib.IMAP4_SSL, uid: int) -> AnalysisReport | None:
        typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")  # PEEK: don't mark as read
        raw = next((part[1] for part in data if isinstance(part, tuple)), None)
        if not raw:
            return None
        parsed = parse_raw(raw)
        report = self.engine.analyze_email(parsed)
        log.info("UID %s verdict=%s score=%s subject=%r", uid, report.verdict.value, report.risk_score, parsed.subject[:80])

        try:
            conn.uid("STORE", str(uid), "+FLAGS", f"({KEYWORDS[report.verdict]})")
        except imaplib.IMAP4.error:
            pass  # some servers don't allow custom keywords

        if report.verdict != Verdict.safe:
            send_webhook(self.settings.webhook_url, report, f"mailbox {self.settings.imap_user}")

        if report.verdict == Verdict.phishing and self.settings.imap_quarantine:
            self._quarantine(conn, uid)
        return report

    def _quarantine(self, conn: imaplib.IMAP4_SSL, uid: int) -> None:
        folder = self.settings.imap_quarantine_folder
        conn.create(folder)  # no-op error if it exists
        typ, caps = conn.capability()
        if re.search(rb"\bMOVE\b", caps[0] or b""):
            conn.uid("MOVE", str(uid), folder)
        else:
            typ, _ = conn.uid("COPY", str(uid), folder)
            if typ == "OK":
                conn.uid("STORE", str(uid), "+FLAGS", r"(\Deleted)")
                conn.expunge()
        log.warning("UID %s moved to %s", uid, folder)

    def run_once(self, conn: imaplib.IMAP4_SSL) -> int:
        conn.noop()
        processed = 0
        for uid in self._new_uids(conn):
            try:
                self.handle(conn, uid)
            except Exception:
                log.exception("Failed to process UID %s", uid)
            self.last_uid = uid
            self._save_state()
            processed += 1
        return processed

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        backoff = 5
        while self.running:
            try:
                conn = self.connect()
                log.info("Watching %s/%s", self.settings.imap_host, self.settings.imap_folder)
                backoff = 5
                while self.running:
                    self.run_once(conn)
                    time.sleep(self.settings.imap_poll_seconds)
                conn.logout()
            except (imaplib.IMAP4.error, OSError) as exc:
                log.error("IMAP error: %s - reconnecting in %ss", exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    MailboxMonitor(get_settings()).run_forever()


if __name__ == "__main__":
    main()
