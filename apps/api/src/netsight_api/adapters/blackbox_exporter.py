"""Blackbox exporter probe sources (S7 Step 4b).

A *probe source* is one Prometheus Blackbox exporter deployed at a known location (cloud/external,
user LAN, server VLAN, branch, Wi-Fi, remote site). Netsight asks it to run a check with a plain
``GET /probe`` and reads the three metrics it needs; the result carries the source's configured
location, so a check is never attributed to a place nobody configured.

Security posture (SSRF is the primary risk of a diagnostic feature):

* The exporter URL is operator configuration (``BLACKBOX_EXPORTER_SOURCES``), validated at start-up
  of the request: http(s) only, a host, no credentials, query, fragment or path, a valid port. The
  request target can never steer *which server is contacted*.
* Only targets on the shared ``BLACKBOX_ALLOWED_TARGETS`` allow-list, and only well-formed host
  names/addresses, are ever sent; the module is chosen from a fixed table, never from input.
* Read-only (``GET``), no redirects, no environment proxies, identity encoding, a hard response
  size cap, per-request timeouts and an overall wall-clock deadline per probe.
* Redirects are also an *exporter-side* risk: the exporter, not Netsight, follows them while
  probing, so every exporter's ``http_2xx`` module must set ``no_follow_redirects: true``
  (``infrastructure/blackbox/blackbox.yml`` is the reference and a test pins it).
* The allow-list is validated when it is loaded (``adapters.blackbox.parse_allowed_targets``): plain
  operator-chosen names and addresses only; anything else is dropped and counted, never repaired.
* A plain ``http://`` exporter URL is honoured but warned about: prefer ``https``.
* An exporter that cannot answer (error status, timeout, oversize, malformed) is ``unknown``, never
  a failed target; nothing the exporter returns is echoed into a result.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from netsight_api.adapters.blackbox import (
    ALLOWED_TARGETS_ENV,
    TARGET_PATTERN,
    parse_allowed_targets,
)
from netsight_api.diagnostics import Observation
from netsight_api.schemas_diagnostics import PROBE_LOCATIONS, DiagnosticCheckKind, ProbeLocation

_LOGGER = logging.getLogger("netsight_api")

SOURCES_ENV = "BLACKBOX_EXPORTER_SOURCES"
TIMEOUT_ENV = "BLACKBOX_TIMEOUT_SECONDS"

_MIN_TIMEOUT_SECONDS = 0.1
_MAX_TIMEOUT_SECONDS = 30.0
_DEFAULT_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_LATENCY_MS = 3_600_000.0
_METRIC = re.compile(
    r"^(probe_success|probe_duration_seconds|probe_http_status_code)(?:\{[^}]*\})?[ \t]+(\S+)",
)

# The only checks an exporter is asked for, each with a fixed module (never taken from input).
_MODULES: Mapping[str, str] = {
    "icmp": "icmp",
    "tcp": "tcp_connect",
    "http": "http_2xx",
    "https": "http_2xx",
}
_PORTS: Mapping[str, int] = {"tcp": 443, "http": 80, "https": 443}
PROBE_KINDS = frozenset(_MODULES)
# Modules every configured exporter must define (infrastructure/blackbox/blackbox.yml is the
# reference). http_2xx in particular must set ``no_follow_redirects: true``: the exporter follows
# redirects, not Netsight, so a redirect would otherwise steer the probe past the allow-list.
REQUIRED_EXPORTER_MODULES: frozenset[str] = frozenset(_MODULES.values())


@dataclass(frozen=True)
class ExporterSource:
    """One configured exporter. The URL is excluded from ``repr`` so it never reaches a log."""

    location: ProbeLocation
    base_url: str = field(repr=False)


@dataclass(frozen=True)
class _Verdict:
    status: str
    latency_ms: float | None
    detail: str


def _unknown(detail: str) -> _Verdict:
    return _Verdict("unknown", None, detail)


def _number(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _metrics(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = _METRIC.match(line)
        if match is not None:
            found.setdefault(match.group(1), match.group(2))
    return found


def _verdict(text: str) -> _Verdict:
    metrics = _metrics(text)
    success = _number(metrics.get("probe_success", ""))
    if success not in (0.0, 1.0):
        return _unknown("the probe source returned no usable result")
    seconds = _number(metrics.get("probe_duration_seconds", ""))
    latency = None if seconds is None else round(seconds * 1000, 3)
    if latency is not None and not 0 <= latency <= _MAX_LATENCY_MS:
        latency = None
    code = _number(metrics.get("probe_http_status_code", ""))
    if success == 1.0:
        detail = (
            f"HTTP {int(code)}"
            if code is not None and 100 <= code <= 599
            else ("the probe source reported success")
        )
        return _Verdict("pass", latency, detail)
    return _Verdict("fail", latency, "the probe source reported a failed probe")


def _host(target: str) -> str:
    return f"[{target}]" if ":" in target else target


def _probe_target(kind: str, target: str) -> str:
    host = _host(target)
    if kind == "icmp":
        return target
    if kind == "tcp":
        return f"{host}:{_PORTS['tcp']}"
    return f"{kind}://{host}/"


class ExporterBlackboxClient:
    """A bounded, read-only probe client for one exporter at one location."""

    probe_kinds = PROBE_KINDS

    def __init__(
        self,
        *,
        source: ExporterSource,
        allowed: Sequence[str],
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._source = source
        self._allowed = frozenset(item.strip().lower() for item in allowed if item.strip())
        self._timeout = min(max(timeout, _MIN_TIMEOUT_SECONDS), _MAX_TIMEOUT_SECONDS)
        self._max_bytes = max_response_bytes
        self._transport = transport

    @property
    def location(self) -> ProbeLocation:
        return self._source.location

    async def probe(
        self, *, kind: DiagnosticCheckKind, target: str, vantage: str | None
    ) -> Observation:
        return self._observation(kind, target, await self._verdict(kind, target, vantage))

    async def _verdict(self, kind: str, target: str, vantage: str | None) -> _Verdict:
        if vantage is not None and vantage != self._source.location:
            return _unknown("no prober is connected for the requested vantage")
        host = target.strip()
        if host.lower() not in self._allowed:
            return _unknown("the target is not in the configured probe allow-list")
        if TARGET_PATTERN.fullmatch(host) is None:
            return _unknown("the target is not a valid probe target")
        if kind not in _MODULES:
            return _unknown("this probe source cannot run the check")
        return await self._request(_MODULES[kind], _probe_target(kind, host))

    async def _request(self, module: str, probe_target: str) -> _Verdict:
        """One probe request under an overall wall-clock deadline.

        The httpx timeouts bound each phase (connect, each read), not the total: a source that
        keeps trickling bytes would never trip a read timeout. The deadline caps the whole exchange.
        """
        try:
            async with asyncio.timeout(self._timeout):
                return await self._fetch(module, probe_target)
        except TimeoutError:
            return _unknown("the probe source did not answer in time")

    async def _fetch(self, module: str, probe_target: str) -> _Verdict:
        try:
            async with (
                httpx.AsyncClient(
                    base_url=self._source.base_url,
                    timeout=httpx.Timeout(self._timeout, connect=min(5.0, self._timeout)),
                    transport=self._transport,
                    follow_redirects=False,
                    trust_env=False,
                    headers={"Accept-Encoding": "identity", "User-Agent": "netsight-diagnostic"},
                ) as client,
                client.stream(
                    "GET", "/probe", params={"module": module, "target": probe_target}
                ) as response,
            ):
                if response.status_code != 200:
                    return _unknown("the probe source answered with an error")
                body = await self._read(response)
        except httpx.TimeoutException:
            return _unknown("the probe source did not answer in time")
        except httpx.HTTPError:
            return _unknown("the probe source could not be reached")
        if body is None:
            return _unknown("the probe source response was too large")
        return _verdict(body.decode("utf-8", errors="replace"))

    async def _read(self, response: httpx.Response) -> bytes | None:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_bytes:
            return None
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > self._max_bytes:
                return None
        return bytes(body)

    def _observation(
        self, kind: DiagnosticCheckKind, target: str, verdict: _Verdict
    ) -> Observation:
        location = self._source.location
        return Observation(
            kind=kind,
            label=f"{kind.upper()} check of {target.strip()} from {location}"[:255],
            status=verdict.status,  # type: ignore[arg-type]
            vantage=location,
            location=location,
            port=_PORTS.get(kind),
            latency_ms=verdict.latency_ms,
            detail=verdict.detail,
            observed_at=datetime.now(UTC),
            evidence_id=None,
        )


# --- configuration ----------------------------------------------------------------------------


def _base_url(raw: str) -> str | None:
    try:
        parsed = urlsplit(raw.strip())
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        return None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}{f':{port}' if port is not None else ''}"


def parse_exporter_sources(raw: str) -> list[ExporterSource]:
    """``location=url`` pairs, comma separated; an invalid pair is dropped, never repaired.

    One source per location (the first wins); the result follows the canonical location order.
    Dropped entries are counted in the log without their content (a URL may carry a secret).
    """
    chosen: dict[ProbeLocation, ExporterSource] = {}
    invalid = 0
    plain = 0
    for entry in raw.split(","):
        if not entry.strip():
            continue
        name, separator, url = entry.partition("=")
        location = name.strip()
        base = _base_url(url) if separator else None
        if location not in PROBE_LOCATIONS or base is None:
            invalid += 1
            continue
        if location not in chosen:
            chosen[location] = ExporterSource(location=location, base_url=base)
            plain += base.startswith("http://")
    if invalid:
        _LOGGER.warning("ignored invalid probe source entries", extra={"count": invalid})
    if plain:
        _LOGGER.warning(
            "probe sources use unencrypted http; prefer https between Netsight and the exporter",
            extra={"count": plain},
        )
    return [chosen[location] for location in PROBE_LOCATIONS if location in chosen]


def _timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    try:
        return float(raw) if raw else _DEFAULT_TIMEOUT_SECONDS
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS


def get_exporter_clients() -> list[ExporterBlackboxClient]:
    """One client per configured source; none without an allow-list (no probing at all)."""
    allowed = parse_allowed_targets(os.environ.get(ALLOWED_TARGETS_ENV, ""))
    if not allowed:
        return []
    timeout = _timeout()
    return [
        ExporterBlackboxClient(source=source, allowed=allowed, timeout=timeout)
        for source in parse_exporter_sources(os.environ.get(SOURCES_ENV, ""))
    ]
