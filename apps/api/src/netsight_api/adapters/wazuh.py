"""Read-only Wazuh indexer adapter for bounded security-event reads.

Wazuh alerts (including Suricata EVE alerts forwarded through the Wazuh
agent/decoder pipeline) are stored in the Wazuh indexer (OpenSearch), not the
manager API, so this adapter issues bounded ``_search`` reads against the
alerts index with a least-privilege read-only indexer identity. It never
calls the manager API and has no active-response or agent-management path.

Every text field of an alert is untrusted telemetry. Fields are length
bounded and passed through as data; the adapter never interprets them.
``device_id`` is always ``None``: mapping a Wazuh agent to a canonical
device needs the identity-correlation layer, and an IP-based guess is
forbidden.

Source failures raise typed errors and are never converted into an empty
successful result; the API degrades them to the explicit ``unknown`` state.
"""

from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from netsight_api.schemas import AlertSeverity, SecurityEvent

ADAPTER_VERSION = "wazuh-indexer/1"
SOURCE_NAME = "wazuh"

# Only Wazuh indices: an operator typo must not widen reads to other indexer data.
_INDEX_PATTERN = re.compile(r"wazuh-[a-z0-9_*.-]{0,121}")
_MAX_LIMIT = 500
# 500 hits of the bounded field set are well under 1 MiB; this leaves ample headroom.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_SOURCE_FIELDS = [
    "timestamp",
    "rule.description",
    "rule.level",
    "rule.groups",
    "data.srcip",
    "data.dstip",
    "data.src_ip",
    "data.dest_ip",
    "data.alert.signature",
    "data.alert.severity",
    "data.alert.category",
    "data.event_type",
]


class AdapterStatus(StrEnum):
    """Typed source outcomes (same vocabulary as the other adapters)."""

    UNAVAILABLE = "unavailable"
    FORBIDDEN = "forbidden"
    INVALID_SOURCE_DATA = "invalid-source-data"


class AdapterError(Exception):
    """Source failure with a stable status; detail never contains secrets."""

    def __init__(self, status: AdapterStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _invalid(detail: str) -> AdapterError:
    return AdapterError(AdapterStatus.INVALID_SOURCE_DATA, detail)


def _wazuh_severity(level: Any) -> AlertSeverity:
    """Wazuh rule level 0-15 -> canonical severity (documented bands)."""
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 15:
        raise _invalid("invalid rule level")
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _suricata_severity(value: Any) -> AlertSeverity:
    """Suricata alert severity: 1 is the most severe, 3 the least."""
    mapping: dict[int, AlertSeverity] = {1: "high", 2: "medium", 3: "low"}
    if isinstance(value, bool) or not isinstance(value, int) or value not in mapping:
        raise _invalid("invalid suricata severity")
    return mapping[value]


def _optional_text(value: Any, field_name: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid(f"invalid {field_name}")
    text = value.strip()
    return text[:maximum] if text else None


def _parse_timestamp(value: Any) -> datetime:
    """Wazuh timestamps look like ``2026-10-06T07:55:00.123+0000``."""
    if not isinstance(value, str):
        raise _invalid("missing timestamp")
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _invalid("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise _invalid("timestamp without timezone")
    return parsed.astimezone(UTC)


def _dig(document: Any, *path: str) -> Any:
    node: Any = document
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _field(source: dict[str, Any], *path: str) -> Any:
    """Read a nested value, also accepting the flattened dotted key."""
    nested = _dig(source, *path)
    return nested if nested is not None else source.get(".".join(path))


def _category(groups: Any) -> str | None:
    if isinstance(groups, list) and groups and isinstance(groups[0], str):
        return groups[0][:128] or None
    return None


def parse_hit(hit: Any) -> SecurityEvent:
    """Convert one indexer hit into a canonical event or raise invalid data."""
    if not isinstance(hit, dict):
        raise _invalid("hit is not an object")
    source = hit.get("_source")
    event_id = hit.get("_id")
    if not isinstance(source, dict) or not isinstance(event_id, str) or not event_id:
        raise _invalid("hit is missing _id or _source")

    groups = _field(source, "rule", "groups")
    is_suricata = (
        _field(source, "data", "event_type") == "alert"
        and _field(source, "data", "alert", "signature") is not None
    ) or (isinstance(groups, list) and "suricata" in groups)

    origin: Literal["wazuh", "suricata"]
    if is_suricata:
        origin = "suricata"
        severity = _suricata_severity(_field(source, "data", "alert", "severity"))
        signature = _optional_text(
            _field(source, "data", "alert", "signature"), "signature", 512
        ) or _optional_text(_field(source, "rule", "description"), "signature", 512)
        category = _optional_text(
            _field(source, "data", "alert", "category"), "category", 128
        ) or _category(groups)
        source_ip = _optional_text(_field(source, "data", "src_ip"), "source_ip", 45)
        destination_ip = _optional_text(_field(source, "data", "dest_ip"), "destination_ip", 45)
    else:
        origin = "wazuh"
        severity = _wazuh_severity(_field(source, "rule", "level"))
        signature = _optional_text(_field(source, "rule", "description"), "signature", 512)
        category = _category(groups)
        source_ip = _optional_text(_field(source, "data", "srcip"), "source_ip", 45)
        destination_ip = _optional_text(_field(source, "data", "dstip"), "destination_ip", 45)
    if signature is None:
        raise _invalid("alert has no signature")
    try:
        return SecurityEvent(
            id=event_id[:128],
            observed_at=_parse_timestamp(source.get("timestamp")),
            source=origin,
            severity=severity,
            category=category,
            signature=signature,
            source_ip=source_ip,
            destination_ip=destination_ip,
            device_id=None,
        )
    except ValidationError as exc:
        raise _invalid("invalid security event row") from exc


@dataclass
class WazuhIndexerClient:
    """Read-only alert-search client for one configured Wazuh indexer.

    ``base_url``, ``user`` and ``password`` are excluded from ``repr`` so
    credentials can never leak through logging or test output. TLS
    verification is on; a CA bundle path in ``verify`` adds a private trust
    root. Credentials are only sent over https unless ``allow_insecure_http``
    (a development-only flag) is set.
    """

    base_url: str = field(repr=False)
    user: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    index_pattern: str = "wazuh-alerts-*"
    timeout_seconds: float = 10.0
    verify: bool | str = True
    allow_insecure_http: bool = False
    max_response_bytes: int = _MAX_RESPONSE_BYTES
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _connection(self) -> tuple[str, str]:
        try:
            parsed = urlsplit(self.base_url)
            port = parsed.port
        except ValueError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh indexer URL is invalid") from exc
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or not _INDEX_PATTERN.fullmatch(self.index_pattern)
        ):
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh indexer is misconfigured")
        if parsed.scheme == "http" and self.user and not self.allow_insecure_http:
            raise AdapterError(
                AdapterStatus.UNAVAILABLE, "wazuh indexer credentials require an https URL"
            )
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        return f"{parsed.scheme}://{host}{f':{port}' if port else ''}", self.index_pattern

    def _tls_verify(self) -> bool | ssl.SSLContext:
        """Verification setting for httpx; a CA bundle path becomes an ``SSLContext``."""
        if not isinstance(self.verify, str):
            return self.verify
        try:
            return ssl.create_default_context(cafile=self.verify)
        except (OSError, ssl.SSLError) as exc:
            raise AdapterError(
                AdapterStatus.UNAVAILABLE, "wazuh indexer CA bundle is unusable"
            ) from exc

    async def _read_body(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_response_bytes:
            raise _invalid("wazuh response is too large")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > self.max_response_bytes:
                raise _invalid("wazuh response is too large")
        return bytes(body)

    @staticmethod
    def _query(start: datetime, end: datetime, limit: int) -> dict[str, Any]:
        return {
            "size": max(1, min(int(limit), _MAX_LIMIT)),
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": {"includes": _SOURCE_FIELDS},
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start.astimezone(UTC).isoformat(),
                                    "lt": end.astimezone(UTC).isoformat(),
                                }
                            }
                        }
                    ]
                }
            },
        }

    async def events(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[SecurityEvent], datetime | None]:
        """Newest alerts in a bounded window and the newest timestamp seen."""
        if start >= end:
            raise ValueError("security window must be ordered")
        base_url, index = self._connection()
        verify = self._tls_verify()
        timeout = httpx.Timeout(self.timeout_seconds, connect=5.0)
        try:
            async with (
                httpx.AsyncClient(
                    base_url=base_url,
                    timeout=timeout,
                    auth=(self.user, self.password) if self.user else None,
                    transport=self._transport,
                    verify=verify,
                    # A redirect could resend the Authorization header elsewhere.
                    follow_redirects=False,
                    # The size cap counts decoded bytes, so refuse compressed bodies outright.
                    headers={"Accept-Encoding": "identity"},
                ) as client,
                client.stream(
                    "POST", f"/{index}/_search", json=self._query(start, end, limit)
                ) as response,
            ):
                status_code = response.status_code
                body = await self._read_body(response) if status_code < 300 else b""
        except httpx.TimeoutException as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh request timed out") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh request failed") from exc

        if 300 <= status_code < 400:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh returned an unexpected redirect")
        if status_code in (401, 403):
            raise AdapterError(AdapterStatus.FORBIDDEN, "wazuh rejected the configured credentials")
        if status_code >= 400:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "wazuh query failed")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise _invalid("wazuh returned invalid JSON") from exc
        hits = _dig(payload, "hits", "hits")
        if not isinstance(hits, list):
            raise _invalid("wazuh returned an unexpected response")

        events = [parse_hit(hit) for hit in hits[:_MAX_LIMIT]]
        newest = max((event.observed_at for event in events), default=None)
        return events, newest
