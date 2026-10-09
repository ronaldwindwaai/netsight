"""Channels, destinations, the notification payload and its renderers (NOTIFICATION-ENGINE.md).

Channels: email, push, webhook (in-app is the ``create_alert`` action, not a sender).

* Credentials (webhook URL and header values, push device references) are :class:`Secret`
  values: they never appear in ``repr``, ``str`` or a log line. A destination shows only a
  short label (a hash for email and push, the host for a webhook).
* The payload carries *untrusted* text (rule names, entity names, summaries derived from
  telemetry) as data. Renderers never interpret it: the webhook body is JSON-encoded, the
  email subject is stripped to one line of printable characters and the body is plain text
  (never HTML), the push title and body are length-bounded plain strings. Notifications carry
  enough context to act and a link to authenticated Netsight, not raw telemetry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Final, Literal
from urllib.parse import quote, unquote, urlsplit

from netsight_api.audit import fingerprint
from netsight_api.notifications.secret import Secret
from netsight_api.schemas import AlertSeverity

ChannelKind = Literal["email", "push", "webhook"]

MAX_TITLE_LENGTH: Final = 200
MAX_SUMMARY_LENGTH: Final = 1000
MAX_HEADERS: Final = 8
MAX_HEADER_VALUE_LENGTH: Final = 512
MAX_URL_LENGTH: Final = 2048
_ID: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_EMAIL: Final = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_HEADER_NAME: Final = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_HEADER_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_RESERVED_HEADERS: Final = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "user-agent",
        "proxy-authorization",
        "proxy-connection",
    }
)
# Keys the destination identity hash. Per process and never persisted or logged: the hash only
# has to be stable while one dispatcher runs, and an outsider who cannot read this process cannot
# test a guess ("is this the same webhook as that one?") against the hashes.
_IDENTITY_KEY: Final = secrets.token_bytes(32)
# Bidirectional overrides and isolates let a title visually reorder what follows it.
_BIDI: Final = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))


def sanitize_line(text: str, limit: int) -> str:
    """One printable line: control characters and bidi overrides become nothing or a space."""
    out: list[str] = []
    for char in text:
        if char in _BIDI:
            continue
        category = unicodedata.category(char)
        if char in "\r\n\t" or category == "Zl" or category == "Zp":
            out.append(" ")
        elif category == "Cc":
            continue
        else:
            out.append(char)
    return " ".join("".join(out).split())[:limit]


def sanitize_text(text: str, limit: int) -> str:
    """Multi-line plain text: newlines survive, other control characters and bidi do not."""
    lines = [sanitize_line(line, limit) for line in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines)[:limit]


@dataclass(frozen=True)
class NotificationPayload:
    notification_id: str
    alert_ref: str
    severity: AlertSeverity
    title: str
    summary: str
    link: str
    occurred_at: datetime
    incident_id: str | None = None

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.notification_id) or not _ID.fullmatch(self.alert_ref):
            raise ValueError("notification_id and alert_ref must be short identifiers")
        if len(self.title) > MAX_TITLE_LENGTH or len(self.summary) > MAX_SUMMARY_LENGTH:
            raise ValueError("title or summary is too long")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if len(self.link) > MAX_URL_LENGTH:
            raise ValueError("link is too long")
        if not link_is_under(self.link, None):
            raise ValueError("link must be an https URL without credentials")


def _https_parts(url: str) -> tuple[str, int, str] | None:
    """(lower-case host, port, path) of a plain https URL without credentials, else None."""
    if not url or url != url.strip() or "\\" in url or _HEADER_CONTROL.search(url):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port or 443
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        return None
    return parts.hostname, port, parts.path or "/"


def link_is_under(link: str, base_url: str | None) -> bool:
    """A notification link is https without credentials and, when ``base_url`` is configured,
    on the same host and port with a path at or below the base path.

    Dot segments (also percent-encoded) are refused when a base is set, so ``/app/../x`` cannot
    climb out of ``/app``. Anything unparseable is refused.
    """
    target = _https_parts(link)
    if target is None:
        return False
    if not base_url:
        return True
    base = _https_parts(base_url)
    if base is None or target[:2] != base[:2]:
        return False
    path = unquote(unquote(target[2]))
    if any(segment in (".", "..") for segment in path.split("/")):
        return False
    prefix = base[2].rstrip("/")
    return target[2] == prefix or target[2].startswith(prefix + "/") or prefix == ""


def build_link(public_base_url: str, alert_ref: str) -> str:
    """Link to the authenticated Netsight view; the base must be an https origin."""
    parts = urlsplit(public_base_url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("the public base URL must be an https URL without credentials")
    return f"{public_base_url.rstrip('/')}/alerts/{quote(alert_ref, safe='')}"


# --- destinations ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class EmailDestination:
    kind: ClassVar[ChannelKind] = "email"
    address: str

    def __post_init__(self) -> None:
        if len(self.address) > 254 or _EMAIL.fullmatch(self.address) is None:
            raise ValueError("invalid email address")

    @property
    def label(self) -> str:
        return f"email:{fingerprint(self.address.lower())[:12]}"

    @property
    def identity_key(self) -> str:
        return _identity("email", self.address.lower())

    def __repr__(self) -> str:
        return f"EmailDestination({self.label})"


@dataclass(frozen=True, repr=False)
class PushDestination:
    kind: ClassVar[ChannelKind] = "push"
    device_ref: Secret

    def __post_init__(self) -> None:
        if not 1 <= len(self.device_ref.reveal()) <= 512:
            raise ValueError("invalid push device reference")

    @property
    def label(self) -> str:
        return f"push:{fingerprint(self.device_ref.reveal())[:12]}"

    @property
    def identity_key(self) -> str:
        return _identity("push", self.device_ref.reveal())

    def __repr__(self) -> str:
        return f"PushDestination({self.label})"


@dataclass(frozen=True, repr=False)
class WebhookDestination:
    """The URL and header values are secrets; ``repr`` shows only the host.

    Only cheap structural checks run here. The authoritative URL policy, allow-list and
    address checks run at send time (``WebhookSender``), when the answer matters.
    """

    kind: ClassVar[ChannelKind] = "webhook"
    url: Secret
    headers: tuple[tuple[str, Secret], ...] = ()

    def __post_init__(self) -> None:
        if not 1 <= len(self.url.reveal()) <= MAX_URL_LENGTH:
            raise ValueError("invalid webhook URL length")
        if len(self.headers) > MAX_HEADERS:
            raise ValueError(f"at most {MAX_HEADERS} headers are allowed")
        for name, value in self.headers:
            lowered = name.lower()
            if _HEADER_NAME.fullmatch(name) is None or lowered in _RESERVED_HEADERS:
                raise ValueError("invalid header name")
            secret = value.reveal()
            if len(secret) > MAX_HEADER_VALUE_LENGTH or _HEADER_CONTROL.search(secret):
                raise ValueError("invalid header value")

    @property
    def host(self) -> str:
        try:
            return urlsplit(self.url.reveal()).hostname or "invalid"
        except ValueError:
            return "invalid"

    @property
    def label(self) -> str:
        """Display only (the host): two different webhooks on one host share it."""
        return f"webhook:{self.host}"

    @property
    def identity_key(self) -> str:
        """Keyed hash of the full URL and the header *names*, never of the display label."""
        names = ",".join(sorted(name.lower() for name, _ in self.headers))
        return _identity("webhook", self.url.reveal(), names)

    def __repr__(self) -> str:
        return f"WebhookDestination(host={self.host!r})"


Destination = EmailDestination | PushDestination | WebhookDestination


def _identity(kind: str, *parts: str) -> str:
    """HMAC-SHA256 (hex) over the channel and the identifying parts, NUL-separated."""
    message = "\0".join((kind, *parts)).encode("utf-8", "surrogatepass")
    return hmac.new(_IDENTITY_KEY, message, hashlib.sha256).hexdigest()


# --- results and rendering -------------------------------------------------------------------

SendStatus = Literal["sent", "retryable", "permanent"]


@dataclass(frozen=True)
class SendResult:
    """Outcome of one send attempt; ``code`` is a static identifier, never provider text."""

    status: SendStatus
    code: str


@dataclass(frozen=True)
class RenderedEmail:
    subject: str
    body: str


@dataclass(frozen=True)
class RenderedPush:
    title: str
    body: str
    link: str


def render_email(payload: NotificationPayload) -> RenderedEmail:
    """Plain text only; the subject is one line, so a title cannot inject a header."""
    subject = sanitize_line(f"[{payload.severity.upper()}] {payload.title}", MAX_TITLE_LENGTH)
    body = "\n".join(
        [
            f"Severity: {payload.severity}",
            f"Alert: {sanitize_line(payload.title, MAX_TITLE_LENGTH)}",
            f"Time: {payload.occurred_at.isoformat()}",
            "",
            sanitize_text(payload.summary, MAX_SUMMARY_LENGTH),
            "",
            f"Details (sign-in required): {sanitize_line(payload.link, MAX_URL_LENGTH)}",
        ]
    )
    return RenderedEmail(subject=subject, body=body)


def render_push(payload: NotificationPayload) -> RenderedPush:
    return RenderedPush(
        title=sanitize_line(f"[{payload.severity.upper()}] {payload.title}", 80),
        body=sanitize_line(payload.summary, 240),
        link=sanitize_line(payload.link, MAX_URL_LENGTH),
    )


def render_webhook_body(payload: NotificationPayload) -> bytes:
    """JSON with every untrusted string as an escaped JSON string (ASCII-only on the wire)."""
    document = {
        "notification_id": payload.notification_id,
        "alert_ref": payload.alert_ref,
        "severity": payload.severity,
        "title": payload.title,
        "summary": payload.summary,
        "link": payload.link,
        "occurred_at": payload.occurred_at.isoformat(),
        "incident_id": payload.incident_id,
    }
    return json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )


def unique_destinations(destinations: Sequence[Destination]) -> tuple[Destination, ...]:
    """Drop repeats, keeping the first occurrence order.

    Identity is the keyed ``identity_key`` (full URL and header names for a webhook), not the
    display label: two webhooks on one host with different paths are different destinations.
    """
    seen: set[tuple[str, str]] = set()
    out: list[Destination] = []
    for destination in destinations:
        key = (destination.kind, destination.identity_key)
        if key not in seen:
            seen.add(key)
            out.append(destination)
    return tuple(out)
