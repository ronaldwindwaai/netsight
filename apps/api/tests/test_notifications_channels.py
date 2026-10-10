"""Production senders (S6 step 2): SMTP email and the push gateway, plus the durable recorder.

Nothing here reaches the network: the SMTP client, the resolver and the HTTP transport are
fakes, and the ``no_network`` guard proves nothing slips past them.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from typing import Any, Self

import pytest
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.notifications.dispatcher import (
    DeliveryAttempt,
    InMemoryDeliveryRecorder,
    Notification,
    NotificationDispatcher,
    RetryPolicy,
)
from netsight_api.notifications.models import (
    EmailDestination,
    NotificationPayload,
    PushDestination,
    SendResult,
    WebhookDestination,
)
from netsight_api.notifications.push import PushGatewaySender, PushGatewaySettings
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.notifications.smtp import SmtpEmailSender, SmtpSettings
from netsight_api.notifications.store import DurableDeliveryRecorder
from netsight_api.notifications.webhook import PinnedRequest, TransportResponse

pytestmark = pytest.mark.usefixtures("no_network")

NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
PASSWORD = "smtp-p4ssw0rd-do-not-leak"
TOKEN = "gateway-t0ken-do-not-leak"
DEVICE = "device-token-do-not-leak"
PUBLIC_IP = "93.184.216.34"
BIDI = chr(0x202E)
XSS = f"<script>alert('x')</script> {BIDI} 🔥"


def payload(**overrides: Any) -> NotificationPayload:
    fields: dict[str, Any] = {
        "notification_id": "n-1",
        "alert_ref": "a" * 32,
        "severity": "high",
        "title": "Uplink down",
        "summary": "device-1 is offline",
        "link": "https://netsight.example.com/incidents/incident-1",
        "occurred_at": NOW,
        "incident_id": "incident-00000000-0000-4000-8000-000000000001",
    }
    fields.update(overrides)
    return NotificationPayload(**fields)


# --- SMTP settings -------------------------------------------------------------------------------------

BASE_ENV = {
    "NETSIGHT_SMTP_HOST": "smtp.example.com",
    "NETSIGHT_SMTP_FROM": "netsight@example.com",
}


def test_smtp_unset_means_no_email_sender() -> None:
    assert SmtpSettings.from_env({}) is None
    assert SmtpSettings.from_env({"NETSIGHT_SMTP_HOST": "  "}) is None


def test_smtp_defaults_are_starttls_on_587_with_a_bounded_timeout() -> None:
    settings = SmtpSettings.from_env(BASE_ENV)
    assert settings is not None
    assert (settings.host, settings.port, settings.tls) == ("smtp.example.com", 587, "starttls")
    assert settings.sender == "netsight@example.com"
    assert settings.username is None and settings.password is None
    assert settings.timeout_seconds == 10.0


def test_smtp_implicit_tls_defaults_to_465() -> None:
    settings = SmtpSettings.from_env({**BASE_ENV, "NETSIGHT_SMTP_TLS": "tls"})
    assert settings is not None and (settings.tls, settings.port) == ("tls", 465)


@pytest.mark.parametrize("mode", ["none", "off", "false", "plain", "disabled", "0", "no", "STARTTLS "])
def test_smtp_refuses_any_way_to_turn_tls_off(mode: str) -> None:
    env = {**BASE_ENV, "NETSIGHT_SMTP_TLS": mode}
    if mode.strip().lower() == "starttls":
        assert SmtpSettings.from_env(env) is not None  # surrounding space and case are tolerated
        return
    with pytest.raises(ValueError, match="NETSIGHT_SMTP_TLS"):
        SmtpSettings.from_env(env)


@pytest.mark.parametrize(
    "overrides",
    [
        {"NETSIGHT_SMTP_FROM": ""},
        {"NETSIGHT_SMTP_FROM": "not-an-address"},
        {"NETSIGHT_SMTP_FROM": "a@example.com\r\nBcc: x@y.z"},
        {"NETSIGHT_SMTP_HOST": "smtp.example.com/evil"},
        {"NETSIGHT_SMTP_HOST": "user@smtp.example.com"},
        {"NETSIGHT_SMTP_HOST": "smtp example.com"},
        {"NETSIGHT_SMTP_HOST": "smtp.example.com\nevil.example"},
        {"NETSIGHT_SMTP_PORT": "0"},
        {"NETSIGHT_SMTP_PORT": "70000"},
        {"NETSIGHT_SMTP_PORT": "abc"},
        {"NETSIGHT_SMTP_TIMEOUT_SECONDS": "0"},
        {"NETSIGHT_SMTP_TIMEOUT_SECONDS": "61"},
        {"NETSIGHT_SMTP_USERNAME": "only-a-user"},
        {"NETSIGHT_SMTP_PASSWORD": "only-a-password"},
        {"NETSIGHT_SMTP_USERNAME": "u\r\n", "NETSIGHT_SMTP_PASSWORD": "p"},
    ],
)
def test_smtp_rejects_invalid_configuration(overrides: Mapping[str, str]) -> None:
    with pytest.raises(ValueError):
        SmtpSettings.from_env({**BASE_ENV, **overrides})


def test_smtp_password_never_appears_in_repr_str_or_errors() -> None:
    env = {**BASE_ENV, "NETSIGHT_SMTP_USERNAME": "svc", "NETSIGHT_SMTP_PASSWORD": PASSWORD}
    settings = SmtpSettings.from_env(env)
    assert settings is not None and settings.password is not None
    assert settings.password.reveal() == PASSWORD
    for text in (repr(settings), str(settings), repr(SmtpEmailSender(settings))):
        assert PASSWORD not in text
    with pytest.raises(ValueError) as raised:
        SmtpSettings.from_env({**env, "NETSIGHT_SMTP_PORT": "abc"})
    assert PASSWORD not in str(raised.value)


# --- SMTP sender -----------------------------------------------------------------------------------------


class FakeSmtp:
    """Scripted SMTP client that records the order of calls (TLS must precede credentials)."""

    def __init__(
        self,
        *,
        starttls_supported: bool = True,
        fail_on: Mapping[str, Exception] | None = None,
        refused: Mapping[str, tuple[int, bytes]] | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.sent: list[EmailMessage] = []
        self.login_args: tuple[str, str] | None = None
        self._starttls_supported = starttls_supported
        self._fail_on = dict(fail_on or {})
        self._refused = dict(refused or {})

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if name in self._fail_on:
            raise self._fail_on[name]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append("close")

    def ehlo(self) -> tuple[int, bytes]:
        self._step("ehlo")
        return 250, b"ok"

    def has_extn(self, name: str) -> bool:
        return self._starttls_supported if name.lower() == "starttls" else False

    def starttls(self, *, context: ssl.SSLContext) -> tuple[int, bytes]:
        self._step("starttls")
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        return 220, b"ready"

    def login(self, user: str, password: str) -> tuple[int, bytes]:
        self._step("login")
        self.login_args = (user, password)
        return 235, b"ok"

    def send_message(self, message: EmailMessage) -> dict[str, tuple[int, bytes]]:
        self._step("send")
        self.sent.append(message)
        return self._refused


class SmtpFactory:
    def __init__(self, client: FakeSmtp, *, raises: Exception | None = None) -> None:
        self.client = client
        self.raises = raises
        self.opened: list[tuple[str, int, str]] = []

    def __call__(self, settings: SmtpSettings, context: ssl.SSLContext) -> FakeSmtp:
        self.opened.append((settings.host, settings.port, settings.tls))
        if self.raises is not None:
            raise self.raises
        return self.client


def smtp_sender(client: FakeSmtp | None = None, **env: str) -> tuple[SmtpEmailSender, SmtpFactory]:
    settings = SmtpSettings.from_env({**BASE_ENV, **env})
    assert settings is not None
    factory = SmtpFactory(client or FakeSmtp())
    return SmtpEmailSender(settings, client_factory=factory), factory


def test_email_is_sent_over_starttls_before_any_credentials() -> None:
    client = FakeSmtp()
    sender, factory = smtp_sender(
        client, NETSIGHT_SMTP_USERNAME="svc", NETSIGHT_SMTP_PASSWORD=PASSWORD
    )
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("sent", "OK")
    assert client.calls == ["ehlo", "starttls", "ehlo", "login", "send", "close"]
    assert client.login_args == ("svc", PASSWORD)
    assert factory.opened == [("smtp.example.com", 587, "starttls")]


def test_implicit_tls_skips_starttls_and_still_logs_in() -> None:
    client = FakeSmtp()
    sender, factory = smtp_sender(
        client,
        NETSIGHT_SMTP_TLS="tls",
        NETSIGHT_SMTP_USERNAME="svc",
        NETSIGHT_SMTP_PASSWORD=PASSWORD,
    )
    assert sender.send(EmailDestination("ops@example.com"), payload()).status == "sent"
    assert client.calls == ["login", "send", "close"]
    assert factory.opened == [("smtp.example.com", 465, "tls")]


def test_server_without_starttls_is_refused_and_nothing_is_sent_or_authenticated() -> None:
    client = FakeSmtp(starttls_supported=False)
    sender, _ = smtp_sender(client, NETSIGHT_SMTP_USERNAME="svc", NETSIGHT_SMTP_PASSWORD=PASSWORD)
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("permanent", "STARTTLS_UNSUPPORTED")
    assert "login" not in client.calls and "send" not in client.calls and not client.sent


def test_failed_starttls_never_falls_back_to_plaintext() -> None:
    client = FakeSmtp(fail_on={"starttls": smtplib.SMTPResponseException(454, b"TLS not available")})
    sender, _ = smtp_sender(client, NETSIGHT_SMTP_USERNAME="svc", NETSIGHT_SMTP_PASSWORD=PASSWORD)
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert result.status == "retryable"
    assert "login" not in client.calls and "send" not in client.calls


def test_certificate_failure_is_final_and_leaks_nothing() -> None:
    error = ssl.SSLCertVerificationError("hostname 'smtp.example.com' doesn't match")
    sender, _ = smtp_sender(FakeSmtp(fail_on={"starttls": error}))
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("permanent", "TLS_FAILED")


def test_message_is_plain_text_with_a_single_clean_subject_line() -> None:
    client = FakeSmtp()
    sender, _ = smtp_sender(client)
    hostile = "Disk full\r\nBcc: attacker@evil.example\r\n\r\n" + XSS
    sender.send(EmailDestination("ops@example.com"), payload(title=hostile[:200], summary=XSS))
    (message,) = client.sent
    raw = message_from_bytes(message.as_bytes(policy=policy.SMTP), policy=policy.SMTP)
    assert raw["From"] == "netsight@example.com" and raw["To"] == "ops@example.com"
    assert raw.get_all("Bcc") is None and raw.get_all("Subject") is not None
    assert len(raw.get_all("Subject") or []) == 1
    assert "\n" not in str(raw["Subject"]) and "\r" not in str(raw["Subject"])
    assert raw.get_content_type() == "text/plain"
    body = raw.get_content()
    assert "<script>" in body and BIDI not in body  # data, not markup; bidi stripped
    assert "https://netsight.example.com/incidents/incident-1" in body


def test_only_the_single_validated_recipient_is_addressed() -> None:
    client = FakeSmtp()
    sender, _ = smtp_sender(client)
    sender.send(EmailDestination("ops@example.com"), payload())
    assert [str(a) for a in client.sent[0].get_all("To", [])] == ["ops@example.com"]
    assert client.sent[0].get_all("Cc") is None and client.sent[0].get_all("Bcc") is None


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (smtplib.SMTPAuthenticationError(535, b"bad creds secret"), "permanent", "AUTH_FAILED"),
        (smtplib.SMTPRecipientsRefused({"x@y.z": (550, b"no")}), "permanent", "RECIPIENT_REFUSED"),
        (smtplib.SMTPSenderRefused(550, b"no", "a@b.c"), "permanent", "SENDER_REFUSED"),
        (smtplib.SMTPResponseException(451, b"try later"), "retryable", "SMTP_4XX"),
        (smtplib.SMTPResponseException(554, b"rejected"), "permanent", "SMTP_5XX"),
        (smtplib.SMTPServerDisconnected("gone"), "retryable", "CONNECTION_FAILED"),
        (smtplib.SMTPException("odd"), "retryable", "SMTP_ERROR"),
        (TimeoutError("slow"), "retryable", "TIMEOUT"),
        (ConnectionRefusedError("refused"), "retryable", "CONNECTION_FAILED"),
        (RuntimeError("bug with " + PASSWORD), "retryable", "SENDER_ERROR"),
    ],
)
def test_smtp_failures_map_to_static_codes(error: Exception, status: str, code: str) -> None:
    client = FakeSmtp(fail_on={"send": error})
    sender, _ = smtp_sender(client)
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == (status, code)
    assert PASSWORD not in repr(result)


def test_connection_failure_before_the_client_exists_is_retryable() -> None:
    settings = SmtpSettings.from_env(BASE_ENV)
    assert settings is not None
    factory = SmtpFactory(FakeSmtp(), raises=ConnectionRefusedError("boom"))
    result = SmtpEmailSender(settings, client_factory=factory).send(
        EmailDestination("ops@example.com"), payload()
    )
    assert (result.status, result.code) == ("retryable", "CONNECTION_FAILED")


def test_server_refusing_the_recipient_in_the_reply_is_permanent() -> None:
    client = FakeSmtp(refused={"ops@example.com": (550, b"unknown user")})
    sender, _ = smtp_sender(client)
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("permanent", "RECIPIENT_REFUSED")


def test_wrong_destination_kind_is_a_mismatch_and_opens_no_connection() -> None:
    sender, factory = smtp_sender()
    result = sender.send(PushDestination(Secret(DEVICE)), payload())
    assert (result.status, result.code) == ("permanent", "DESTINATION_MISMATCH")
    assert factory.opened == []
    assert sender.channel == "email"


def test_logs_carry_the_error_type_only(caplog: pytest.LogCaptureFixture) -> None:
    sender, _ = smtp_sender(FakeSmtp(fail_on={"send": RuntimeError("leak " + PASSWORD)}))
    with caplog.at_level(logging.DEBUG, logger="netsight_api.notifications"):
        sender.send(EmailDestination("ops@example.com"), payload())
    assert PASSWORD not in caplog.text and "ops@example.com" not in caplog.text
    assert any(getattr(r, "error_type", None) == "RuntimeError" for r in caplog.records)


def test_default_factory_builds_a_verifying_tls_context_and_bounded_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class RecordingSmtp:
        def __init__(self, host: str, port: int, **kw: Any) -> None:
            seen.update(kind="starttls", host=host, port=port, **kw)

    class RecordingSmtpSsl:
        def __init__(self, host: str, port: int, **kw: Any) -> None:
            seen.update(kind="tls", host=host, port=port, **kw)

    monkeypatch.setattr(smtplib, "SMTP", RecordingSmtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", RecordingSmtpSsl)
    from netsight_api.notifications.smtp import default_client_factory

    context = ssl.create_default_context()
    start = SmtpSettings.from_env({**BASE_ENV, "NETSIGHT_SMTP_TIMEOUT_SECONDS": "7"})
    assert start is not None
    default_client_factory(start, context)
    assert seen["kind"] == "starttls" and seen["timeout"] == 7.0 and seen["port"] == 587
    implicit = SmtpSettings.from_env({**BASE_ENV, "NETSIGHT_SMTP_TLS": "tls"})
    assert implicit is not None
    default_client_factory(implicit, context)
    assert seen["kind"] == "tls" and seen["context"] is context and seen["port"] == 465


def test_unreadable_ca_bundle_fails_the_send_closed(tmp_path: Any) -> None:
    sender, factory = smtp_sender(NETSIGHT_SMTP_CA_BUNDLE=str(tmp_path / "missing.pem"))
    result = sender.send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("permanent", "TLS_CONFIG")
    assert factory.opened == []


# --- push gateway ----------------------------------------------------------------------------------------

GATEWAY_URL = "https://push.example.com/v1/notify/s3cr3t-path"
PUSH_ENV = {"NETSIGHT_PUSH_GATEWAY_URL": GATEWAY_URL, "NETSIGHT_PUSH_GATEWAY_TOKEN": TOKEN}
ALLOW = NotificationSettings(webhook_allowed_hosts=frozenset({"push.example.com"}))


class RecordingTransport:
    def __init__(self, *responses: TransportResponse | Exception) -> None:
        self.responses = list(responses) or [TransportResponse(status=202, bytes_read=0)]
        self.requests: list[PinnedRequest] = []

    def post(self, request: PinnedRequest) -> TransportResponse:
        self.requests.append(request)
        outcome = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def gateway(
    transport: RecordingTransport, settings: NotificationSettings = ALLOW, **env: str
) -> PushGatewaySender:
    config = PushGatewaySettings.from_env({**PUSH_ENV, **env})
    assert config is not None
    return PushGatewaySender(
        config, settings, resolver=lambda host, port: [PUBLIC_IP], transport=transport
    )


def test_push_gateway_unset_means_no_push_sender() -> None:
    assert PushGatewaySettings.from_env({}) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"NETSIGHT_PUSH_GATEWAY_URL": "http://push.example.com/x"},
        {"NETSIGHT_PUSH_GATEWAY_URL": "https://user:pw@push.example.com/x"},
        {"NETSIGHT_PUSH_GATEWAY_URL": "ftp://push.example.com/x"},
        {"NETSIGHT_PUSH_GATEWAY_URL": "https://push.example.com/x\r\nHost: evil"},
        {"NETSIGHT_PUSH_GATEWAY_TOKEN": "tok\r\nX-Evil: 1"},
        {"NETSIGHT_PUSH_GATEWAY_TOKEN": "t" * 513},
    ],
)
def test_push_gateway_rejects_unsafe_configuration(overrides: Mapping[str, str]) -> None:
    with pytest.raises(ValueError) as raised:
        PushGatewaySettings.from_env({**PUSH_ENV, **overrides})
    assert TOKEN not in str(raised.value) and "s3cr3t-path" not in str(raised.value)


def test_push_gateway_secrets_stay_out_of_repr() -> None:
    config = PushGatewaySettings.from_env(PUSH_ENV)
    sender = gateway(RecordingTransport())
    for text in (repr(config), str(config), repr(sender)):
        assert TOKEN not in text and "s3cr3t-path" not in text


def test_push_is_posted_to_the_pinned_gateway_with_a_bearer_token() -> None:
    transport = RecordingTransport()
    result = gateway(transport).send(PushDestination(Secret(DEVICE)), payload(title=XSS))
    assert (result.status, result.code) == ("sent", "OK")
    (request,) = transport.requests
    assert (request.ip, request.host, request.port) == (PUBLIC_IP, "push.example.com", 443)
    assert request.path_and_query == "/v1/notify/s3cr3t-path"
    authorisation = request.headers["Authorization"]
    assert isinstance(authorisation, Secret) and authorisation.reveal() == f"Bearer {TOKEN}"
    assert TOKEN not in repr(request) and DEVICE not in repr(request)
    body = json.loads(request.body)
    assert body["device"] == DEVICE and body["notification_id"] == "n-1"
    assert len(body["title"]) <= 80 and len(body["body"]) <= 240
    assert BIDI not in body["title"] and "\n" not in body["title"]
    assert body["link"] == "https://netsight.example.com/incidents/incident-1"


def test_push_without_a_token_sends_no_authorisation_header() -> None:
    transport = RecordingTransport()
    config = PushGatewaySettings.from_env({"NETSIGHT_PUSH_GATEWAY_URL": GATEWAY_URL})
    assert config is not None
    sender = PushGatewaySender(
        config, ALLOW, resolver=lambda host, port: [PUBLIC_IP], transport=transport
    )
    assert sender.send(PushDestination(Secret(DEVICE)), payload()).status == "sent"
    assert "Authorization" not in transport.requests[0].headers


def test_push_gateway_host_must_be_on_the_ssrf_allow_list() -> None:
    transport = RecordingTransport()
    result = gateway(transport, NotificationSettings()).send(
        PushDestination(Secret(DEVICE)), payload()
    )
    assert result.status == "permanent"
    assert transport.requests == []


def test_push_gateway_refuses_a_private_resolution() -> None:
    transport = RecordingTransport()
    config = PushGatewaySettings.from_env(PUSH_ENV)
    assert config is not None
    sender = PushGatewaySender(
        config, ALLOW, resolver=lambda host, port: ["10.0.0.5"], transport=transport
    )
    result = sender.send(PushDestination(Secret(DEVICE)), payload())
    assert (result.status, result.code) == ("permanent", "ADDRESS_BLOCKED")
    assert transport.requests == []


@pytest.mark.parametrize(
    ("outcome", "status", "code"),
    [
        (TransportResponse(401, 0), "permanent", "HTTP_4XX"),
        (TransportResponse(429, 0), "retryable", "HTTP_RETRYABLE"),
        (TransportResponse(503, 0), "retryable", "HTTP_5XX"),
        (TransportResponse(302, 0), "permanent", "REDIRECT_REFUSED"),
        (TimeoutError("slow"), "retryable", "TIMEOUT"),
        (ConnectionError("down"), "retryable", "CONNECTION_FAILED"),
    ],
)
def test_push_gateway_outcomes_map_to_static_codes(
    outcome: TransportResponse | Exception, status: str, code: str
) -> None:
    result = gateway(RecordingTransport(outcome)).send(PushDestination(Secret(DEVICE)), payload())
    assert (result.status, result.code) == (status, code)


def test_push_sender_rejects_other_destination_kinds() -> None:
    transport = RecordingTransport()
    sender = gateway(transport)
    for destination in (
        EmailDestination("ops@example.com"),
        WebhookDestination(Secret("https://push.example.com/x")),
    ):
        result = sender.send(destination, payload())
        assert (result.status, result.code) == ("permanent", "DESTINATION_MISMATCH")
    assert transport.requests == [] and sender.channel == "push"


# --- durable recorder ------------------------------------------------------------------------------------


def attempt(**overrides: Any) -> DeliveryAttempt:
    fields: dict[str, Any] = {
        "notification_id": "n-1",
        "alert_ref": "a" * 32,
        "channel": "email",
        "destination": "email:abc",
        "attempt": 1,
        "status": "sent",
        "code": "OK",
        "at": NOW,
    }
    fields.update(overrides)
    return DeliveryAttempt(**fields)


class BrokenStore(InMemoryDeliveryRecorder):
    def record(self, attempt: DeliveryAttempt) -> None:
        raise RuntimeError("db down: postgresql://user:pw@host/db")


def test_attempts_go_to_the_ring_and_the_durable_store() -> None:
    ring, durable = InMemoryDeliveryRecorder(), InMemoryDeliveryRecorder()
    DurableDeliveryRecorder(ring, durable).record(attempt())
    assert ring.attempts == durable.attempts == (attempt(),)


def test_a_failing_durable_store_keeps_the_ring_and_is_counted_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ring = InMemoryDeliveryRecorder()
    recorder = DurableDeliveryRecorder(ring, BrokenStore())
    with caplog.at_level(logging.WARNING, logger="netsight_api.notifications"):
        recorder.record(attempt())
        recorder.record(attempt(notification_id="n-2"))
    assert len(ring.attempts) == 2
    assert recorder.durable_failures == 2
    assert "pw@host" not in caplog.text and "postgresql://" not in caplog.text


def test_invalid_attempts_are_not_stored_anywhere_but_never_stop_the_dispatcher() -> None:
    ring, durable = InMemoryDeliveryRecorder(), InMemoryDeliveryRecorder()
    recorder = DurableDeliveryRecorder(ring, durable)
    with pytest.raises(ValueError):
        recorder.record(attempt(code="not a code"))
    assert ring.attempts == () and durable.attempts == ()


class _Sender:
    channel = "email"

    def send(self, destination: Any, payload: NotificationPayload) -> SendResult:
        return SendResult("sent", "OK")


def test_dispatcher_delivers_even_when_every_recorder_write_fails() -> None:
    recorder = DurableDeliveryRecorder(BrokenStore(), BrokenStore())
    dispatcher = NotificationDispatcher(
        {"email": _Sender()},  # type: ignore[dict-item]
        recorder,
        clock=lambda: NOW,
        sleep=lambda seconds: None,
        policy=RetryPolicy(max_attempts=1),
    )
    outcome = dispatcher.deliver(Notification("n-1", payload(), EmailDestination("ops@example.com")))
    assert (outcome.status, outcome.attempts) == ("sent", 1)
