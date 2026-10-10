"""Push sender behind ``NotificationSender``: an HTTPS push gateway (provider-agnostic).

The provider decision (FCM, APNs, Web Push, ntfy, UnifiedPush...) is deliberately outside this
code: Netsight posts one JSON document per notification to a gateway the operator runs or
contracts, and the gateway talks to the provider. This keeps provider credentials out of
Netsight and the sender small.

* ``NETSIGHT_PUSH_GATEWAY_URL``: https URL without userinfo (a :class:`Secret`: gateway URLs
  routinely carry a token). Unset: no push sender exists (``NO_SENDER`` is recorded).
* ``NETSIGHT_PUSH_GATEWAY_TOKEN`` (optional :class:`Secret`): sent as ``Authorization: Bearer``.

The request goes through exactly the webhook defences (``ssrf.py`` and the pinned transport):
the gateway host must be on ``NETSIGHT_WEBHOOK_ALLOWED_HOSTS`` and resolve to public addresses
only, redirects are refused, timeouts and the response size are bounded, the response is
discarded. Body: ``{"device", "title", "body", "link", "notification_id", "severity"}`` where
the strings are the length-bounded plain text of ``render_push`` (untrusted text as data).
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from netsight_api.notifications.models import (
    ChannelKind,
    Destination,
    NotificationPayload,
    PushDestination,
    SendResult,
    render_push,
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
from netsight_api.notifications.webhook import (
    USER_AGENT,
    HttpxWebhookTransport,
    PinnedRequest,
    WebhookTransport,
    classify_status,
)

_LOGGER: Final = logging.getLogger("netsight_api.notifications")
_URL_FORBIDDEN: Final = re.compile(r"[\x00-\x20\x7f\\]")
_TOKEN_FORBIDDEN: Final = re.compile(r"[\x00-\x1f\x7f]")
MAX_TOKEN_LENGTH: Final = 512
_URL_ERROR: Final = "NETSIGHT_PUSH_GATEWAY_URL must be an https URL without credentials"


@dataclass(frozen=True, repr=False)
class PushGatewaySettings:
    url: Secret
    token: Secret | None = None

    def __repr__(self) -> str:
        return "PushGatewaySettings(url=***, token=***)"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> PushGatewaySettings | None:
        source = os.environ if env is None else env
        url = source.get("NETSIGHT_PUSH_GATEWAY_URL", "").strip()
        if not url:
            return None
        if _URL_FORBIDDEN.search(url):
            raise ValueError(_URL_ERROR)
        try:
            parts = urlsplit(url)
            valid = parts.scheme == "https" and bool(parts.hostname) and "@" not in parts.netloc
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(_URL_ERROR)
        token = source.get("NETSIGHT_PUSH_GATEWAY_TOKEN", "")
        if token and (len(token) > MAX_TOKEN_LENGTH or _TOKEN_FORBIDDEN.search(token)):
            raise ValueError("NETSIGHT_PUSH_GATEWAY_TOKEN is invalid")
        return cls(url=Secret(url), token=Secret(token) if token else None)


def _body(destination: PushDestination, payload: NotificationPayload) -> bytes:
    rendered = render_push(payload)
    document = {
        "device": destination.device_ref.reveal(),
        "title": rendered.title,
        "body": rendered.body,
        "link": rendered.link,
        "notification_id": payload.notification_id,
        "severity": payload.severity,
    }
    return json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )


class PushGatewaySender:
    channel: ChannelKind = "push"

    def __init__(
        self,
        settings: PushGatewaySettings,
        network: NotificationSettings,
        *,
        resolver: Resolver = system_resolver,
        transport: WebhookTransport | None = None,
    ) -> None:
        self._settings = settings
        self._network = network
        self._resolver = resolver
        self._transport: WebhookTransport = transport or HttpxWebhookTransport()

    def __repr__(self) -> str:
        return "PushGatewaySender(***)"

    def send(self, destination: Destination, payload: NotificationPayload) -> SendResult:
        if not isinstance(destination, PushDestination):
            return SendResult("permanent", "DESTINATION_MISMATCH")
        try:
            target = parse_webhook_url(self._settings.url.reveal(), self._network)
            pinned = resolve_and_pin(target, self._resolver)
        except WebhookTargetError as refusal:
            return SendResult("retryable" if refusal.retryable else "permanent", refusal.code)
        headers: dict[str, str | Secret] = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        if self._settings.token is not None:
            headers["Authorization"] = Secret(f"Bearer {self._settings.token.reveal()}")
        request = PinnedRequest(
            ip=pinned.ip,
            host=pinned.host,
            port=pinned.port,
            path_and_query=target.path_and_query,
            headers=headers,
            body=_body(destination, payload),
            timeout_seconds=self._network.webhook_timeout_seconds,
            max_response_bytes=self._network.webhook_max_response_bytes,
        )
        try:
            response = self._transport.post(request)
        except TimeoutError:
            return SendResult("retryable", "TIMEOUT")
        except OSError:
            return SendResult("retryable", "CONNECTION_FAILED")
        except Exception as exc:  # noqa: BLE001 - contained: only the type is logged
            _LOGGER.warning("push transport failed", extra={"error_type": type(exc).__name__})
            return SendResult("retryable", "TRANSPORT_ERROR")
        return classify_status(response.status)
