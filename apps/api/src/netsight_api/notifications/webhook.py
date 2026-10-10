"""The webhook sender: validated, pinned, bounded.

``WebhookSender.send`` applies the layered SSRF checks (``ssrf.py``) at *send* time, resolves
the name exactly once, and hands the transport the pinned address. The transport connects to
that IP while presenting the original host name for TLS server-name indication and the HTTP
``Host`` header, so the certificate is still verified against the name but DNS cannot change
where the bytes go. Redirects are never followed (a 3xx is a final, refused outcome), every
phase has a timeout plus a total deadline, and at most ``max_response_bytes`` of the response
are read and then discarded: the response body is untrusted and is never logged or stored.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol

import httpx

from netsight_api.notifications.models import (
    Destination,
    NotificationPayload,
    SendResult,
    WebhookDestination,
    render_webhook_body,
)
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.notifications.ssrf import (
    Resolver,
    WebhookTargetError,
    parse_webhook_url,
    resolve_and_pin,
    system_resolver,
)

_LOGGER: Final = logging.getLogger("netsight_api.notifications")
_READ_CHUNK: Final = 8192
USER_AGENT: Final = "Netsight-Notifier/1"


@dataclass(frozen=True, repr=False)
class PinnedRequest:
    """Everything the transport needs; ``repr`` shows neither headers, body nor path."""

    ip: str
    host: str
    port: int
    path_and_query: str
    headers: Mapping[str, str | Secret]
    body: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int

    def __repr__(self) -> str:
        return f"PinnedRequest(ip={self.ip!r}, host={self.host!r}, port={self.port})"


@dataclass(frozen=True)
class TransportResponse:
    status: int
    bytes_read: int


class WebhookTransport(Protocol):
    """Raises ``TimeoutError`` on a timeout and ``OSError`` on connection failure."""

    def post(self, request: PinnedRequest) -> TransportResponse: ...


class HttpxWebhookTransport:
    """The production transport. Constructing it opens nothing; ``post`` opens one connection.

    ``trust_env=False`` keeps proxy environment variables from rerouting the pinned
    connection; ``verify`` stays on; redirects are off.
    """

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def post(self, request: PinnedRequest) -> TransportResponse:
        shown_ip = f"[{request.ip}]" if ":" in request.ip else request.ip
        url = f"https://{shown_ip}:{request.port}{request.path_and_query}"
        headers = {
            name: value.reveal() if isinstance(value, Secret) else value
            for name, value in request.headers.items()
        }
        headers["Host"] = request.host if request.port == 443 else f"{request.host}:{request.port}"
        deadline = time.monotonic() + request.timeout_seconds
        read = 0
        try:
            with (
                httpx.Client(
                    transport=self._transport,
                    timeout=httpx.Timeout(request.timeout_seconds),
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                ) as client,
                client.stream(
                    "POST",
                    url,
                    content=request.body,
                    headers=headers,
                    extensions={"sni_hostname": request.host},
                ) as response,
            ):
                for chunk in response.iter_raw(_READ_CHUNK):
                    read += len(chunk)
                    if read >= request.max_response_bytes:
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError("response deadline exceeded")
                return TransportResponse(status=response.status_code, bytes_read=read)
        except httpx.TimeoutException:
            raise TimeoutError("webhook timed out") from None
        except httpx.HTTPError:
            raise ConnectionError("webhook connection failed") from None


def classify_status(status: int) -> SendResult:
    """Static outcome for an HTTP status (shared by the webhook and push senders)."""
    if 200 <= status < 300:
        return SendResult("sent", "OK")
    if 300 <= status < 400:
        return SendResult("permanent", "REDIRECT_REFUSED")
    if status in (408, 429):
        return SendResult("retryable", "HTTP_RETRYABLE")
    if 400 <= status < 500:
        return SendResult("permanent", "HTTP_4XX")
    if 500 <= status < 600:
        return SendResult("retryable", "HTTP_5XX")
    return SendResult("permanent", "HTTP_UNEXPECTED")


class WebhookSender:
    channel = "webhook"

    def __init__(
        self,
        settings: NotificationSettings,
        *,
        resolver: Resolver = system_resolver,
        transport: WebhookTransport | None = None,
    ) -> None:
        self._settings = settings
        self._resolver = resolver
        self._transport: WebhookTransport = transport or HttpxWebhookTransport()

    def send(self, destination: Destination, payload: NotificationPayload) -> SendResult:
        if not isinstance(destination, WebhookDestination):
            return SendResult("permanent", "DESTINATION_MISMATCH")
        try:
            target = parse_webhook_url(destination.url.reveal(), self._settings)
            pinned = resolve_and_pin(target, self._resolver)
        except WebhookTargetError as refusal:
            return SendResult("retryable" if refusal.retryable else "permanent", refusal.code)
        headers: dict[str, str | Secret] = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            **dict(destination.headers),
        }
        request = PinnedRequest(
            ip=pinned.ip,
            host=pinned.host,
            port=pinned.port,
            path_and_query=target.path_and_query,
            headers=headers,
            body=render_webhook_body(payload),
            timeout_seconds=self._settings.webhook_timeout_seconds,
            max_response_bytes=self._settings.webhook_max_response_bytes,
        )
        try:
            response = self._transport.post(request)
        except TimeoutError:
            return SendResult("retryable", "TIMEOUT")
        except OSError:
            return SendResult("retryable", "CONNECTION_FAILED")
        except Exception as exc:  # noqa: BLE001 - contained: only the type is logged
            _LOGGER.warning("webhook transport failed", extra={"error_type": type(exc).__name__})
            return SendResult("retryable", "TRANSPORT_ERROR")
        return classify_status(response.status)
