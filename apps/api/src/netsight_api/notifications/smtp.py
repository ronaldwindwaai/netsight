"""Production email sender: authenticated SMTP relay, TLS required (NOTIFICATION-ENGINE.md).

Configuration (read once by ``SmtpSettings.from_env``; an invalid value raises so a bad setting
fails start-up instead of weakening delivery):

* ``NETSIGHT_SMTP_HOST``: relay host name. Unset: no email sender exists (the dispatcher then
  records ``NO_SENDER``; nothing is fabricated as sent).
* ``NETSIGHT_SMTP_TLS``: ``starttls`` (default, port 587) or ``tls`` (implicit TLS, port 465).
  There is no value that turns TLS off, and a server that does not offer STARTTLS is refused:
  credentials and mail never cross the wire in clear text.
* ``NETSIGHT_SMTP_PORT``, ``NETSIGHT_SMTP_FROM`` (required, validated like a recipient),
  ``NETSIGHT_SMTP_USERNAME`` and ``NETSIGHT_SMTP_PASSWORD`` (both or neither; the password is a
  :class:`Secret`), ``NETSIGHT_SMTP_TIMEOUT_SECONDS`` (1-60, default 10) and
  ``NETSIGHT_SMTP_CA_BUNDLE`` (optional PEM file added to the trusted roots; certificate and
  host name verification stay on).

Mail is plain text rendered by ``render_email`` (one sanitised subject line, no HTML) to the one
validated recipient of the destination. Failures become static codes; provider replies,
addresses and credentials are never put in a result, a log line or an exception message.
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Final, Literal, Protocol, Self

from netsight_api.notifications.models import (
    ChannelKind,
    Destination,
    EmailDestination,
    NotificationPayload,
    SendResult,
    render_email,
)
from netsight_api.notifications.secret import Secret

_LOGGER: Final = logging.getLogger("netsight_api.notifications")
TlsMode = Literal["starttls", "tls"]
_DEFAULT_PORTS: Final = {"starttls": 587, "tls": 465}
_HOST: Final = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^\[[0-9A-Fa-f:.]{2,45}\]$"
)
_CREDENTIAL_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
MAX_CREDENTIAL_LENGTH: Final = 256


def _int_in(source: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = source.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _tls_mode(source: Mapping[str, str]) -> TlsMode:
    raw = source.get("NETSIGHT_SMTP_TLS", "").strip().lower() or "starttls"
    if raw == "starttls":
        return "starttls"
    if raw == "tls":
        return "tls"
    raise ValueError(
        "NETSIGHT_SMTP_TLS must be 'starttls' or 'tls' (plaintext SMTP is not supported)"
    )


def _credential(source: Mapping[str, str], name: str) -> str | None:
    raw = source.get(name, "")
    if not raw:
        return None
    if len(raw) > MAX_CREDENTIAL_LENGTH or _CREDENTIAL_CONTROL.search(raw):
        raise ValueError(f"{name} is invalid")
    return raw


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    tls: TlsMode
    sender: str
    username: str | None = None
    password: Secret | None = field(default=None, repr=False)
    timeout_seconds: float = 10.0
    ca_bundle: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SmtpSettings | None:
        source = os.environ if env is None else env
        host = source.get("NETSIGHT_SMTP_HOST", "").strip()
        if not host:
            return None
        if _HOST.fullmatch(host) is None:
            raise ValueError("NETSIGHT_SMTP_HOST is not a valid host name")
        mode = _tls_mode(source)
        sender = source.get("NETSIGHT_SMTP_FROM", "").strip()
        try:
            EmailDestination(sender)
        except ValueError:
            raise ValueError("NETSIGHT_SMTP_FROM must be a valid email address") from None
        username = _credential(source, "NETSIGHT_SMTP_USERNAME")
        password = _credential(source, "NETSIGHT_SMTP_PASSWORD")
        if (username is None) != (password is None):
            raise ValueError("NETSIGHT_SMTP_USERNAME and NETSIGHT_SMTP_PASSWORD go together")
        return cls(
            host=host,
            port=_int_in(source, "NETSIGHT_SMTP_PORT", _DEFAULT_PORTS[mode], 1, 65535),
            tls=mode,
            sender=sender,
            username=username,
            password=None if password is None else Secret(password),
            timeout_seconds=float(_int_in(source, "NETSIGHT_SMTP_TIMEOUT_SECONDS", 10, 1, 60)),
            ca_bundle=source.get("NETSIGHT_SMTP_CA_BUNDLE", "").strip() or None,
        )


class SmtpClient(Protocol):
    """The slice of ``smtplib.SMTP`` the sender uses (so tests can script it)."""

    def __enter__(self) -> Self: ...
    def __exit__(self, *exc: object) -> object: ...
    def ehlo(self) -> tuple[int, bytes]: ...
    def has_extn(self, name: str) -> bool: ...
    def starttls(self, *, context: ssl.SSLContext) -> tuple[int, bytes]: ...
    def login(self, user: str, password: str) -> tuple[int, bytes]: ...
    def send_message(self, msg: EmailMessage) -> dict[str, tuple[int, bytes]]: ...


ClientFactory = Callable[[SmtpSettings, ssl.SSLContext], SmtpClient]


def default_client_factory(settings: SmtpSettings, context: ssl.SSLContext) -> SmtpClient:
    """Open the connection (implicit TLS wraps it at once); bounded by the settings timeout."""
    if settings.tls == "tls":
        return smtplib.SMTP_SSL(  # type: ignore[return-value]
            settings.host, settings.port, timeout=settings.timeout_seconds, context=context
        )
    return smtplib.SMTP(  # type: ignore[return-value]
        settings.host, settings.port, timeout=settings.timeout_seconds
    )


def _classify(error: Exception) -> SendResult:
    """Static code per failure class; the exception text is never used."""
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return SendResult("permanent", "AUTH_FAILED")
    if isinstance(error, smtplib.SMTPNotSupportedError):
        return SendResult("permanent", "STARTTLS_UNSUPPORTED")
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return SendResult("permanent", "RECIPIENT_REFUSED")
    if isinstance(error, smtplib.SMTPSenderRefused):
        return SendResult("permanent", "SENDER_REFUSED")
    if isinstance(error, smtplib.SMTPResponseException):
        if 400 <= error.smtp_code < 500:
            return SendResult("retryable", "SMTP_4XX")
        return SendResult("permanent", "SMTP_5XX")
    if isinstance(error, ssl.SSLError):
        return SendResult("permanent", "TLS_FAILED")
    if isinstance(error, smtplib.SMTPServerDisconnected | smtplib.SMTPConnectError):
        return SendResult("retryable", "CONNECTION_FAILED")
    if isinstance(error, smtplib.SMTPException):
        return SendResult("retryable", "SMTP_ERROR")
    if isinstance(error, TimeoutError):
        return SendResult("retryable", "TIMEOUT")
    if isinstance(error, OSError):
        return SendResult("retryable", "CONNECTION_FAILED")
    _LOGGER.warning("email sender failed", extra={"error_type": type(error).__name__})
    return SendResult("retryable", "SENDER_ERROR")


def _build_message(settings: SmtpSettings, to: str, payload: NotificationPayload) -> EmailMessage:
    rendered = render_email(payload)
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = settings.sender
    message["To"] = to
    message["Subject"] = rendered.subject
    message["Date"] = format_datetime(payload.occurred_at)
    message["Message-ID"] = make_msgid(domain=settings.sender.rsplit("@", 1)[1])
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(rendered.body, charset="utf-8")
    return message


class SmtpEmailSender:
    channel: ChannelKind = "email"

    def __init__(
        self, settings: SmtpSettings, *, client_factory: ClientFactory = default_client_factory
    ) -> None:
        self._settings = settings
        self._client_factory = client_factory

    def __repr__(self) -> str:
        return f"SmtpEmailSender(host={self._settings.host!r}, tls={self._settings.tls!r})"

    def _context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()  # system roots ...
        if self._settings.ca_bundle is not None:  # ... plus the configured bundle, not instead
            context.load_verify_locations(cafile=self._settings.ca_bundle)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def send(self, destination: Destination, payload: NotificationPayload) -> SendResult:
        if not isinstance(destination, EmailDestination):
            return SendResult("permanent", "DESTINATION_MISMATCH")
        try:
            context = self._context()
        except (OSError, ssl.SSLError):
            return SendResult("permanent", "TLS_CONFIG")
        try:
            message = _build_message(self._settings, destination.address, payload)
            with self._client_factory(self._settings, context) as client:
                return self._transmit(client, context, message)
        except Exception as error:  # noqa: BLE001 - mapped to a static code, text never used
            return _classify(error)

    def _transmit(
        self, client: SmtpClient, context: ssl.SSLContext, message: EmailMessage
    ) -> SendResult:
        if self._settings.tls == "starttls":
            client.ehlo()
            if not client.has_extn("starttls"):
                return SendResult("permanent", "STARTTLS_UNSUPPORTED")
            client.starttls(context=context)
            client.ehlo()
        if self._settings.username is not None and self._settings.password is not None:
            client.login(self._settings.username, self._settings.password.reveal())
        if client.send_message(message):
            return SendResult("permanent", "RECIPIENT_REFUSED")
        return SendResult("sent", "OK")
