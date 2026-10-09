"""Webhook target validation (SSRF) and the pinned, bounded webhook sender.

Layers under test, in the order a send meets them: URL syntax (https only, no userinfo, no
IP literals or numeric hosts, port policy), the settings allow-list, name resolution through an
injected resolver (every answer must be globally routable; IPv4-mapped / NAT64 / 6to4 forms are
unwrapped), connection pinning to the validated address (so DNS rebinding cannot swap it),
no redirects, timeouts and a response size cap. Nothing here touches the real network: the
``no_network`` fixture fails the test if anything tries — the single exception is the loopback
TLS server used to prove certificate verification, which the guard allows and which never
leaves the host.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.notifications.models import NotificationPayload, WebhookDestination
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.notifications.ssrf import (
    WebhookTargetError,
    is_blocked_address,
    parse_webhook_url,
    resolve_and_pin,
)
from netsight_api.notifications.webhook import (
    HttpxWebhookTransport,
    PinnedRequest,
    TransportResponse,
    WebhookSender,
)

pytestmark = pytest.mark.usefixtures("no_network")

PUBLIC_IP = "93.184.216.34"
SECRET_PATH = "/services/T000/B000/s3cr3t-token-value"
URL = f"https://hooks.example.com{SECRET_PATH}"
NOW = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)


def settings(hosts: Sequence[str] = ("hooks.example.com",), **kw: Any) -> NotificationSettings:
    return NotificationSettings(webhook_allowed_hosts=frozenset(hosts), **kw)


def payload(**overrides: Any) -> NotificationPayload:
    fields: dict[str, Any] = {
        "notification_id": "n-1",
        "alert_ref": "a" * 32,
        "severity": "high",
        "title": "Large upload",
        "summary": "device-1 exceeded the threshold",
        "link": "https://netsight.example.com/alerts/aaaa",
        "occurred_at": NOW,
    }
    fields.update(overrides)
    return NotificationPayload(**fields)


# --- address classification ------------------------------------------------------------------

BLOCKED = [
    # IPv4: loopback, private, link-local / metadata, CGNAT, special purpose, multicast, reserved
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "169.254.0.1",
    "0.0.0.0",
    "0.1.2.3",
    "100.64.0.1",
    "100.100.100.200",
    "192.0.0.1",
    "192.0.2.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "255.255.255.255",
    # IPv6
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd00:ec2::254",
    "ff02::1",
    "2001:db8::1",
    "2001::1",  # Teredo
    "::7f00:1",  # deprecated IPv4-compatible forms
    "::a00:1",
    "::808:808",
    # IPv4-mapped, NAT64 and 6to4 forms of blocked IPv4 addresses
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:10.0.0.1",
    "::ffff:8.8.8.8",
    "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
    "2002:7f00:1::1",
    "2002:a9fe:a9fe::1",
    # Not an address at all, or an alternative numeric spelling: refuse rather than guess
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "127.1",
    "localhost",
    "",
    "not an ip",
    " 127.0.0.1",
    "127.0.0.1%eth0",
    "fe80::1%eth0",
]
# "::ffff:8.8.8.8" moved to BLOCKED: every embedded-IPv4 form is refused outright (S6-3 M1).
ALLOWED = [PUBLIC_IP, "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]


@pytest.mark.parametrize("address", BLOCKED)
def test_non_public_or_ambiguous_addresses_are_blocked(address: str) -> None:
    assert is_blocked_address(address) is True


@pytest.mark.parametrize("address", ALLOWED)
def test_global_unicast_addresses_are_allowed(address: str) -> None:
    assert is_blocked_address(address) is False


# --- URL syntax ----------------------------------------------------------------------------------

BAD_URLS = [
    ("http://hooks.example.com/x", "SCHEME_NOT_HTTPS"),
    ("HTTP://hooks.example.com/x", "SCHEME_NOT_HTTPS"),
    ("ftp://hooks.example.com/x", "SCHEME_NOT_HTTPS"),
    ("file:///etc/passwd", "SCHEME_NOT_HTTPS"),
    ("gopher://hooks.example.com/", "SCHEME_NOT_HTTPS"),
    ("//hooks.example.com/x", "SCHEME_NOT_HTTPS"),
    ("hooks.example.com/x", "SCHEME_NOT_HTTPS"),
    ("javascript:alert(1)", "SCHEME_NOT_HTTPS"),
    ("https://user@hooks.example.com/x", "USERINFO_PRESENT"),
    ("https://user:pw@hooks.example.com/x", "USERINFO_PRESENT"),
    ("https://@hooks.example.com/x", "USERINFO_PRESENT"),
    ("https://hooks.example.com@evil.example/x", "USERINFO_PRESENT"),
    ("https://hooks.example.com\\@evil.example/x", "URL_INVALID"),
    ("https://hooks.example.com/x y", "URL_INVALID"),
    ("https://hooks.example.com/x\r\nHost: evil", "URL_INVALID"),
    ("https://hooks.example.com/\x00", "URL_INVALID"),
    ("https://hooks.example.com:abc/x", "URL_INVALID"),
    ("https://hooks.example.com:99999/x", "URL_INVALID"),
    ("https:///x", "URL_INVALID"),
    ("https://", "URL_INVALID"),
    ("", "URL_INVALID"),
    ("https://hooks.example.com:8443/x", "PORT_NOT_ALLOWED"),
    ("https://hooks.example.com:80/x", "PORT_NOT_ALLOWED"),
    ("https://127.0.0.1/x", "HOST_IS_IP_LITERAL"),
    ("https://10.0.0.1/x", "HOST_IS_IP_LITERAL"),
    ("https://169.254.169.254/latest/meta-data", "HOST_IS_IP_LITERAL"),
    ("https://[::1]/x", "HOST_IS_IP_LITERAL"),
    ("https://[::ffff:127.0.0.1]/x", "HOST_IS_IP_LITERAL"),
    ("https://[fe80::1%25eth0]/x", "HOST_IS_IP_LITERAL"),
    ("https://2130706433/x", "HOST_IS_IP_LITERAL"),
    ("https://0x7f000001/x", "HOST_IS_IP_LITERAL"),
    ("https://0177.0.0.1/x", "HOST_IS_IP_LITERAL"),
    ("https://127.1/x", "HOST_IS_IP_LITERAL"),
    ("https://localhost/x", "HOST_NOT_ALLOWED"),
    ("https://evil.example/x", "HOST_NOT_ALLOWED"),
    ("https://hooks.example.com.evil.example/x", "HOST_NOT_ALLOWED"),
    ("https://evilhooks.example.com/x", "HOST_NOT_ALLOWED"),
    ("https://example.com/x", "HOST_NOT_ALLOWED"),
    ("https://hooks.example.com/" + "a" * 2100, "URL_INVALID"),
]


@pytest.mark.parametrize(("url", "code"), BAD_URLS)
def test_url_policy_refuses_with_a_static_code(url: str, code: str) -> None:
    with pytest.raises(WebhookTargetError) as caught:
        parse_webhook_url(url, settings())
    assert caught.value.code == code
    # The message is the code only: a webhook URL can embed a secret token.
    assert str(caught.value) == code
    assert "s3cr3t" not in repr(caught.value)


def test_valid_url_is_normalised() -> None:
    target = parse_webhook_url("HTTPS://Hooks.Example.COM./services/a?x=1#frag", settings())
    assert target.host == "hooks.example.com"
    assert target.port == 443
    assert target.path_and_query == "/services/a?x=1"  # the fragment is never sent
    assert parse_webhook_url("https://hooks.example.com", settings()).path_and_query == "/"


def test_allow_list_is_deny_by_default() -> None:
    with pytest.raises(WebhookTargetError) as caught:
        parse_webhook_url(URL, NotificationSettings())
    assert caught.value.code == "HOST_NOT_ALLOWED"


def test_wildcard_entries_match_exactly_one_subdomain_label() -> None:
    wild = settings(("*.example.com",))
    assert parse_webhook_url("https://a.example.com/x", wild).host == "a.example.com"
    for host in ("a.b.example.com", "example.com", "evilexample.com", "example.com.evil.example"):
        with pytest.raises(WebhookTargetError):
            parse_webhook_url(f"https://{host}/x", wild)


def test_internationalised_hosts_compare_in_punycode() -> None:
    allowed = settings(("xn--exmple-cua.com",))
    assert parse_webhook_url("https://exämple.com/x", allowed).host == "xn--exmple-cua.com"
    with pytest.raises(WebhookTargetError):
        parse_webhook_url("https://exämple.com/x", settings())


def test_configured_extra_port_is_honoured() -> None:
    wide = settings(webhook_allowed_ports=frozenset({443, 8443}))
    assert parse_webhook_url("https://hooks.example.com:8443/x", wide).port == 8443


# --- resolution, rebinding, mixed answers ------------------------------------------------------------


def resolver_returning(*answers: str) -> Any:
    calls: list[tuple[str, int]] = []

    def resolve(host: str, port: int) -> list[str]:
        calls.append((host, port))
        return list(answers)

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


def target() -> Any:
    return parse_webhook_url(URL, settings())


def test_public_answer_is_pinned() -> None:
    resolver = resolver_returning(PUBLIC_IP)
    assert resolve_and_pin(target(), resolver).ip == PUBLIC_IP
    assert resolver.calls == [("hooks.example.com", 443)]


@pytest.mark.parametrize(
    "bad", ["127.0.0.1", "10.0.0.5", "::1", "169.254.169.254", "::ffff:127.0.0.1"]
)
def test_a_name_that_resolves_to_a_blocked_address_is_refused(bad: str) -> None:
    with pytest.raises(WebhookTargetError) as caught:
        resolve_and_pin(target(), resolver_returning(bad))
    assert caught.value.code == "ADDRESS_BLOCKED"


def test_one_blocked_answer_among_public_ones_refuses_the_whole_name() -> None:
    # An attacker-controlled name returning a public and a private A record.
    with pytest.raises(WebhookTargetError) as caught:
        resolve_and_pin(target(), resolver_returning(PUBLIC_IP, "10.0.0.5"))
    assert caught.value.code == "ADDRESS_BLOCKED"
    with pytest.raises(WebhookTargetError):
        resolve_and_pin(target(), resolver_returning("10.0.0.5", PUBLIC_IP))


def test_empty_failed_or_oversized_resolution_fails_closed() -> None:
    with pytest.raises(WebhookTargetError) as empty:
        resolve_and_pin(target(), resolver_returning())
    assert empty.value.code == "RESOLUTION_FAILED"

    def explode(host: str, port: int) -> list[str]:
        raise OSError("SERVFAIL for hooks.example.com with token s3cr3t")

    with pytest.raises(WebhookTargetError) as failed:
        resolve_and_pin(target(), explode)
    assert failed.value.code == "RESOLUTION_FAILED"
    assert "SERVFAIL" not in str(failed.value) and "s3cr3t" not in str(failed.value)

    with pytest.raises(WebhookTargetError) as many:
        resolve_and_pin(target(), resolver_returning(*([PUBLIC_IP] * 40)))
    assert many.value.code == "RESOLUTION_FAILED"


# --- the sender: pinning, redirects, status mapping, timeouts, size cap -------------------------------


class RecordingTransport:
    def __init__(self, *responses: TransportResponse | Exception) -> None:
        self.responses = list(responses) or [TransportResponse(status=200, bytes_read=0)]
        self.requests: list[PinnedRequest] = []

    def post(self, request: PinnedRequest) -> TransportResponse:
        self.requests.append(request)
        outcome = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def destination(**kw: Any) -> WebhookDestination:
    return WebhookDestination(url=Secret(kw.pop("url", URL)), **kw)


def sender(transport: RecordingTransport, resolver: Any | None = None, **kw: Any) -> WebhookSender:
    return WebhookSender(
        settings(**kw),
        resolver=resolver or resolver_returning(PUBLIC_IP),
        transport=transport,
    )


def test_sender_posts_json_to_the_pinned_address_with_the_original_host() -> None:
    transport = RecordingTransport()
    result = sender(transport).send(destination(), payload())
    assert (result.status, result.code) == ("sent", "OK")
    (request,) = transport.requests
    assert request.ip == PUBLIC_IP
    assert request.host == "hooks.example.com"
    assert request.port == 443
    assert request.path_and_query == SECRET_PATH
    assert request.headers["Content-Type"] == "application/json"
    assert request.timeout_seconds == settings().webhook_timeout_seconds
    assert request.max_response_bytes == settings().webhook_max_response_bytes
    body = json.loads(request.body)
    assert body["notification_id"] == "n-1" and body["severity"] == "high"


def test_dns_rebinding_cannot_swap_the_address_between_check_and_connect() -> None:
    answers = iter([[PUBLIC_IP], ["127.0.0.1"]])
    calls: list[str] = []

    def rebinding(host: str, port: int) -> list[str]:
        calls.append(host)
        return next(answers)

    transport = RecordingTransport()
    s = sender(transport, rebinding)
    assert s.send(destination(), payload()).status == "sent"
    # Resolved exactly once per send and the connection used that very answer.
    assert calls == ["hooks.example.com"]
    assert [r.ip for r in transport.requests] == [PUBLIC_IP]
    # The next send resolves afresh, sees the rebound private answer and refuses.
    blocked = s.send(destination(), payload())
    assert (blocked.status, blocked.code) == ("permanent", "ADDRESS_BLOCKED")
    assert len(transport.requests) == 1


def test_sender_enforces_the_allow_list_and_url_policy_itself() -> None:
    transport = RecordingTransport()
    s = sender(transport)
    for url, code in [
        ("https://evil.example/x", "HOST_NOT_ALLOWED"),
        ("http://hooks.example.com/x", "SCHEME_NOT_HTTPS"),
        ("https://127.0.0.1/x", "HOST_IS_IP_LITERAL"),
        ("https://u:p@hooks.example.com/x", "USERINFO_PRESENT"),
    ]:
        result = s.send(destination(url=url), payload())
        assert (result.status, result.code) == ("permanent", code)
    assert transport.requests == []


def test_a_redirect_is_never_followed() -> None:
    transport = RecordingTransport(TransportResponse(status=302, bytes_read=0))
    result = sender(transport).send(destination(), payload())
    assert (result.status, result.code) == ("permanent", "REDIRECT_REFUSED")
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    ("status", "expected", "code"),
    [
        (200, "sent", "OK"),
        (204, "sent", "OK"),
        (301, "permanent", "REDIRECT_REFUSED"),
        (307, "permanent", "REDIRECT_REFUSED"),
        (400, "permanent", "HTTP_4XX"),
        (401, "permanent", "HTTP_4XX"),
        (404, "permanent", "HTTP_4XX"),
        (408, "retryable", "HTTP_RETRYABLE"),
        (429, "retryable", "HTTP_RETRYABLE"),
        (500, "retryable", "HTTP_5XX"),
        (503, "retryable", "HTTP_5XX"),
        (100, "permanent", "HTTP_UNEXPECTED"),
    ],
)
def test_status_mapping(status: int, expected: str, code: str) -> None:
    transport = RecordingTransport(TransportResponse(status=status, bytes_read=0))
    result = sender(transport).send(destination(), payload())
    assert (result.status, result.code) == (expected, code)


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (TimeoutError("read timed out for /services/T000/B000/s3cr3t"), "TIMEOUT"),
        (ConnectionRefusedError("refused"), "CONNECTION_FAILED"),
        (OSError("boom s3cr3t"), "CONNECTION_FAILED"),
    ],
)
def test_timeouts_and_connection_errors_are_retryable_and_never_echo_details(
    error: Exception, code: str, caplog: pytest.LogCaptureFixture
) -> None:
    transport = RecordingTransport(error)
    with caplog.at_level(logging.DEBUG):
        result = sender(transport).send(destination(), payload())
    assert (result.status, result.code) == ("retryable", code)
    assert "s3cr3t" not in repr(result) and "s3cr3t" not in caplog.text


def test_unexpected_transport_failure_is_contained() -> None:
    result = sender(RecordingTransport(RuntimeError("secret s3cr3t"))).send(
        destination(), payload()
    )
    assert (result.status, result.code) == ("retryable", "TRANSPORT_ERROR")
    assert "s3cr3t" not in repr(result)


def test_a_destination_for_another_channel_is_refused() -> None:
    from netsight_api.notifications.models import EmailDestination

    result = sender(RecordingTransport()).send(EmailDestination("ops@example.com"), payload())
    assert (result.status, result.code) == ("permanent", "DESTINATION_MISMATCH")


# --- the real httpx transport, driven by httpx.MockTransport (no network) ------------------------------


def streamed(status: int, content: bytes = b"", **kw: Any) -> httpx.Response:
    """A response whose body is still an unread stream, as a real connection delivers it."""
    return httpx.Response(status, stream=httpx.ByteStream(content), **kw)


def pinned(**kw: Any) -> PinnedRequest:
    fields: dict[str, Any] = {
        "ip": PUBLIC_IP,
        "host": "hooks.example.com",
        "port": 443,
        "path_and_query": SECRET_PATH + "?a=1",
        "headers": {"Content-Type": "application/json", "Authorization": Secret("Bearer s3cr3t")},
        "body": b'{"a":1}',
        "timeout_seconds": 5.0,
        "max_response_bytes": 1024,
    }
    fields.update(kw)
    return PinnedRequest(**fields)


def test_httpx_transport_connects_to_the_ip_but_names_the_host_for_tls_and_http() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return streamed(200, b"ok")

    transport = HttpxWebhookTransport(httpx.MockTransport(handler))
    response = transport.post(pinned())
    assert response.status == 200
    (request,) = seen
    assert request.url.host == PUBLIC_IP  # the socket goes to the validated address
    assert request.url.scheme == "https"
    assert request.url.path == SECRET_PATH and request.url.query == b"a=1"
    assert request.headers["host"] == "hooks.example.com"
    assert (
        request.extensions["sni_hostname"] == "hooks.example.com"
    )  # certificate is checked against the name
    assert request.headers["authorization"] == "Bearer s3cr3t"  # secret revealed only on the wire
    assert request.content == b'{"a":1}'


def test_httpx_transport_brackets_ipv6_pins() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return streamed(200)

    HttpxWebhookTransport(httpx.MockTransport(handler)).post(pinned(ip="2606:4700:4700::1111"))
    assert seen[0].url.host == "2606:4700:4700::1111"


def test_httpx_transport_does_not_follow_redirects() -> None:
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url.host))
        return streamed(302, headers={"Location": "https://169.254.169.254/latest/meta-data"})

    response = HttpxWebhookTransport(httpx.MockTransport(handler)).post(pinned())
    assert response.status == 302
    assert hits == [PUBLIC_IP]


def test_httpx_transport_reads_at_most_the_response_cap() -> None:
    big = b"x" * 1_000_000

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed(200, big)

    response = HttpxWebhookTransport(httpx.MockTransport(handler)).post(
        pinned(max_response_bytes=2048)
    )
    assert response.status == 200
    assert response.bytes_read <= 2048 + 8192  # at most one read chunk beyond the cap
    assert response.bytes_read < len(big)


def test_httpx_transport_maps_timeouts_to_timeout_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(TimeoutError):
        HttpxWebhookTransport(httpx.MockTransport(handler)).post(pinned())


def test_httpx_transport_maps_connect_errors_to_oserror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(OSError):
        HttpxWebhookTransport(httpx.MockTransport(handler)).post(pinned())


# --- the upstream certificate is verified (loopback TLS server, no real network) -----------------------


def untrusted_server_context(directory: Path) -> ssl.SSLContext:
    """A TLS server context carrying a self-signed certificate no client trust store accepts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    valid_from = datetime.now(UTC) - timedelta(days=1)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_from + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile = directory / "cert.pem"
    keyfile = directory / "key.pem"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certfile), str(keyfile))
    return context


def test_a_certificate_the_client_does_not_trust_stops_the_send_before_a_byte_is_written(
    tmp_path: Path,
) -> None:
    """Mandatory attack path: the pinned upstream answers with a certificate we cannot verify.

    The handshake must fail before any request byte reaches it, and the failure must surface
    as the transport's static connection error (never the URL, the pinned address or the SSL
    message, which can quote them), which the sender reports as a retryable failure.
    """
    server_context = untrusted_server_context(tmp_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.5)  # so the accept loop can notice the stop event
    port = listener.getsockname()[1]
    received: list[bytes] = []
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(10)
                try:
                    tls = server_context.wrap_socket(connection, server_side=True)
                except OSError:
                    continue  # the client refused the certificate: the point of the test
                with tls:
                    try:
                        data = tls.recv(4096)
                    except OSError:
                        data = b""
                    if data:
                        received.append(data)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        # The premise: this certificate really fails verification for a stock client.
        with pytest.raises(ssl.SSLCertVerificationError):
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                with ssl.create_default_context().wrap_socket(raw, server_hostname="localhost"):
                    pass  # unreachable: the handshake fails inside wrap_socket
            finally:
                raw.close()

        # The transport meets the same failure and reports it without any detail.
        with pytest.raises(ConnectionError) as caught:
            HttpxWebhookTransport().post(
                pinned(ip="127.0.0.1", host="localhost", port=port, path_and_query=SECRET_PATH)
            )
        assert str(caught.value) == "webhook connection failed"
        assert "s3cr3t" not in repr(caught.value) and SECRET_PATH not in repr(caught.value)

        # The sender classifies exactly this outcome: a retryable failure, never a status.
        result = sender(RecordingTransport(caught.value)).send(destination(), payload())
        assert (result.status, result.code) == ("retryable", "CONNECTION_FAILED")
    finally:
        stop.set()
        thread.join(timeout=5)
        listener.close()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert received == []  # not one byte of either request was written to the upstream


def test_default_transport_is_constructed_without_touching_the_network() -> None:
    # no_network is active: constructing the real transport must not connect or resolve.
    HttpxWebhookTransport()


# --- secrets stay out of repr, str and logs --------------------------------------------------------------


def test_destination_repr_shows_only_the_host() -> None:
    dest = destination(headers=(("Authorization", Secret("Bearer s3cr3t-header")),))
    for text in (repr(dest), str(dest), f"{dest!r}", f"{dest}"):
        assert "s3cr3t" not in text
        assert "hooks.example.com" in text


def test_pinned_request_repr_hides_headers_and_body() -> None:
    text = repr(pinned())
    assert "s3cr3t" not in text and "Bearer" not in text
    assert SECRET_PATH not in text


def test_secret_wrapper_never_renders_its_value() -> None:
    secret = Secret("s3cr3t")
    assert "s3cr3t" not in repr(secret) and "s3cr3t" not in str(secret)
    assert f"{secret}" == "***"
    assert secret.reveal() == "s3cr3t"
    assert secret == Secret("s3cr3t") and secret != Secret("other")
    with pytest.raises(TypeError):
        hash(secret)
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(secret)


def test_full_send_failure_flow_logs_no_secret(caplog: pytest.LogCaptureFixture) -> None:
    transport = RecordingTransport(TransportResponse(status=500, bytes_read=0))
    dest = destination(headers=(("Authorization", Secret("Bearer s3cr3t-header")),))
    with caplog.at_level(logging.DEBUG):
        sender(transport).send(dest, payload())
        sender(RecordingTransport()).send(destination(url="https://evil.example/s3cr3t"), payload())
    assert "s3cr3t" not in caplog.text
    assert "Bearer" not in caplog.text


@pytest.mark.parametrize(
    "name",
    ["Host", "host", "Content-Length", "Transfer-Encoding", "Connection", "X Bad", "X:Bad", ""],
)
def test_reserved_or_malformed_header_names_are_refused(name: str) -> None:
    with pytest.raises(ValueError, match="header"):
        destination(headers=((name, Secret("v")),))


@pytest.mark.parametrize("value", ["a\r\nX-Evil: 1", "a\nb", "a\x00b", "x" * 600])
def test_header_values_cannot_inject_or_overflow(value: str) -> None:
    with pytest.raises(ValueError, match="header"):
        destination(headers=(("X-Token", Secret(value)),))


def test_at_most_eight_headers() -> None:
    many = tuple((f"X-H{i}", Secret("v")) for i in range(9))
    with pytest.raises(ValueError, match="header"):
        destination(headers=many)


# --- payloads carry untrusted text as data only ------------------------------------------------------------


XSS = "<script>alert('xss')</script> \" ' ; DROP TABLE alerts; -- \u202e \U0001f525 {{7*7}} ${jndi:ldap://x}"


def test_untrusted_text_is_json_data_in_the_webhook_body() -> None:
    transport = RecordingTransport()
    sender(transport).send(destination(), payload(title=XSS, summary=XSS))
    raw = transport.requests[0].body
    body = json.loads(raw)
    assert body["title"] == XSS  # data, not interpreted, not altered by the webhook layer
    assert body["summary"] == XSS
    assert raw.decode("ascii")  # ensure_ascii: no raw bidi override or emoji on the wire
    assert set(body) == {
        "notification_id",
        "alert_ref",
        "severity",
        "title",
        "summary",
        "link",
        "occurred_at",
        "incident_id",
    }


# --- the guard itself ------------------------------------------------------------------------------------


def test_the_network_guard_really_refuses_outbound_connections_and_lookups() -> None:
    import socket

    from net_guard import RealNetworkAttempt

    with pytest.raises(RealNetworkAttempt):
        socket.getaddrinfo("hooks.example.com", 443)
    with pytest.raises(RealNetworkAttempt):
        socket.create_connection((PUBLIC_IP, 443), timeout=1)
    with pytest.raises(RealNetworkAttempt):
        socket.gethostbyname("hooks.example.com")
