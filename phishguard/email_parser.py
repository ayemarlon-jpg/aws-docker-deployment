"""Parse raw RFC 822 messages (or loose fields) into a normalized structure."""

from __future__ import annotations

import email
import email.policy
import html as html_lib
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class HtmlLink:
    href: str
    text: str


@dataclass
class ParsedEmail:
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    subject: str = ""
    text: str = ""
    html: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)
    attachments: list[Attachment] = field(default_factory=list)
    html_links: list[HtmlLink] = field(default_factory=list)
    has_forms: bool = False

    def header(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    @property
    def combined_text(self) -> str:
        return "\n".join(filter(None, [self.text, html_to_text(self.html)]))


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[HtmlLink] = []
        self.has_forms = False
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"].strip()
            self._buf = []
        elif tag == "form":
            self.has_forms = True
        elif tag == "input" and (attrs.get("type") or "").lower() == "password":
            self.has_forms = True

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(HtmlLink(href=self._href, text=" ".join("".join(self._buf).split())))
            self._href = None


def html_to_text(html: str) -> str:
    if not html:
        return ""
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return " ".join(html_lib.unescape(text).split())


def _extract_html(parsed: ParsedEmail) -> None:
    if not parsed.html:
        return
    extractor = _LinkExtractor()
    try:
        extractor.feed(parsed.html)
    except Exception:  # malformed HTML should never break analysis
        pass
    parsed.html_links = extractor.links
    parsed.has_forms = extractor.has_forms


def parse_raw(raw: str | bytes) -> ParsedEmail:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)  # type: ignore[assignment]

    parsed = ParsedEmail()
    for key, value in msg.items():
        parsed.headers.setdefault(key.lower(), []).append(str(value))

    parsed.from_name, parsed.from_addr = parseaddr(str(msg.get("From", "")))
    parsed.from_addr = parsed.from_addr.lower()
    parsed.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1].lower()
    parsed.return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    parsed.to = [addr.lower() for _, addr in getaddresses([str(v) for v in msg.get_all("To", [])])]
    parsed.subject = str(msg.get("Subject", ""))

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(Attachment(filename=filename or "(unnamed)", content_type=ctype, size=len(payload)))
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            parsed.text += content
        elif ctype == "text/html":
            parsed.html += content

    _extract_html(parsed)
    return parsed


def from_fields(sender: str | None, reply_to: str | None, subject: str | None, body: str | None, html: str | None) -> ParsedEmail:
    parsed = ParsedEmail()
    parsed.from_name, parsed.from_addr = parseaddr(sender or "")
    parsed.from_addr = parsed.from_addr.lower()
    parsed.reply_to = parseaddr(reply_to or "")[1].lower()
    parsed.subject = subject or ""
    parsed.text = body or ""
    parsed.html = html or ""
    _extract_html(parsed)
    return parsed
