"""Read-only blackbox probe adapter (S7-2).

Bounded, allowlisted, read-only network checks: name resolution, TCP connect and an HTTP/HTTPS
request. SSRF is the primary risk of a diagnostic endpoint, so the client probes only targets on
an operator-configured allow-list (``BLACKBOX_ALLOWED_TARGETS``); anything else answers an
explicit ``unknown`` without opening a connection. ICMP is reported ``unknown`` because there is
no portable unprivileged implementation — a check that did not run is an unknown, never a guess.
Checks that need a monitoring source Netsight does not have connected also answer ``unknown``.

No response, detail text or log line carries the allow-list, a connection string or a driver
message. Every network operation is bounded by a timeout so one run cannot pin the worker.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import ssl
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from netsight_api.diagnostics import Observation
from netsight_api.schemas_diagnostics import (
    PROBE_LOCATIONS,
    DiagnosticCheckKind,
    DiagnosticCheckStatus,
    ProbeLocation,
)

_LOGGER = logging.getLogger("netsight_api")

# An allow-list entry is an operator-chosen host name or address: letters, digits and . _ : -
# only, starting and ending with a letter or digit, no empty label. Wildcards, CIDR blocks, URLs,
# userinfo, paths, whitespace and non-ASCII are all invalid (they could widen or steer the probe).
TARGET_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?")
MAX_ALLOWED_TARGETS = 256
ALLOWED_TARGETS_ENV = "BLACKBOX_ALLOWED_TARGETS"

DEFAULT_PORTS: dict[str, int] = {"tcp": 443, "http": 80, "https": 443}
_PORT_KINDS = ("tcp", "http", "https")
_MIN_TIMEOUT_SECONDS = 0.1
_MAX_TIMEOUT_SECONDS = 30.0
_DEFAULT_TIMEOUT_SECONDS = 5.0


class BlackboxClient(Protocol):
    """A bounded, read-only probe source. Implementations never raise on a probe outcome.

    A source may declare ``probe_kinds`` (the checks it can run); ``run_checks`` then asks it for
    those only, so a source that can probe four things does not add a pile of "cannot" unknowns.
    """

    async def probe(
        self, *, kind: DiagnosticCheckKind, target: str, vantage: str | None
    ) -> Observation: ...


@dataclass(frozen=True)
class _Outcome:
    status: DiagnosticCheckStatus
    latency_ms: float | None
    detail: str | None


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _status_code(line: bytes) -> int | None:
    text = line.decode("latin-1").strip()
    parts = text.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


class AllowlistedBlackboxClient:
    """Real probe client. Deny by default: only allow-listed targets are ever contacted."""

    def __init__(
        self,
        *,
        allowed: list[str],
        vantage: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        location: ProbeLocation | None = None,
    ) -> None:
        self._allowed = frozenset(item.strip().lower() for item in allowed if item.strip())
        self._vantage = vantage
        self._location = location
        self._timeout = min(max(timeout, _MIN_TIMEOUT_SECONDS), _MAX_TIMEOUT_SECONDS)

    @property
    def location(self) -> ProbeLocation | None:
        """Where this prober is deployed (``BLACKBOX_LOCATION``), or ``None`` when unlocated."""
        return self._location

    async def probe(
        self, *, kind: DiagnosticCheckKind, target: str, vantage: str | None
    ) -> Observation:
        # The vantage is provenance, not a label the caller may choose: a probe only ever ran at the
        # point this prober is deployed. A request for a vantage this prober does not serve is an
        # explicit unknown; the check is never relabelled as if it ran somewhere else.
        if vantage is not None and vantage != self._vantage:
            return self._observation(
                kind,
                target,
                self._vantage,
                _Outcome("unknown", None, "no prober is connected for the requested vantage"),
            )
        if target.strip().lower() not in self._allowed:
            return self._observation(
                kind,
                target,
                self._vantage,
                _Outcome("unknown", None, "the target is not in the configured probe allow-list"),
            )
        if kind == "dns":
            outcome = await self._dns(target)
        elif kind == "icmp":
            outcome = _Outcome("unknown", None, "ICMP probing is not available in this deployment")
        elif kind in _PORT_KINDS:
            outcome = await self._connect(target, kind)
        else:
            outcome = _Outcome("unknown", None, "the check needs a source that is not connected")
        return self._observation(kind, target, self._vantage, outcome)

    def _observation(
        self,
        kind: DiagnosticCheckKind,
        target: str,
        vantage: str | None,
        outcome: _Outcome,
    ) -> Observation:
        port = DEFAULT_PORTS.get(kind) if kind in _PORT_KINDS else None
        return Observation(
            kind=kind,
            label=f"{kind.upper()} check of {target}"[:255],
            status=outcome.status,
            vantage=vantage,
            location=self._location,
            port=port,
            latency_ms=outcome.latency_ms,
            detail=outcome.detail,
            observed_at=datetime.now(UTC),
            evidence_id=None,
        )

    async def _dns(self, target: str) -> _Outcome:
        loop = asyncio.get_running_loop()
        start = time.monotonic()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(target, None), timeout=self._timeout)
        except (TimeoutError, OSError):
            return _Outcome("fail", _elapsed_ms(start), "name resolution failed")
        if not infos:
            return _Outcome("fail", _elapsed_ms(start), "name resolution returned no addresses")
        return _Outcome("pass", _elapsed_ms(start), f"resolved to {infos[0][4][0]}")

    async def _connect(self, target: str, kind: str) -> _Outcome:
        port = DEFAULT_PORTS[kind]
        if kind == "tcp":
            return await self._tcp(target, port)
        return await self._http(target, kind, port)

    async def _tcp(self, target: str, port: int) -> _Outcome:
        start = time.monotonic()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=self._timeout
            )
        except (TimeoutError, OSError):
            return _Outcome("fail", _elapsed_ms(start), "the port did not accept a connection")
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return _Outcome("pass", _elapsed_ms(start), "the port accepted a connection")

    async def _http(self, target: str, scheme: str, port: int) -> _Outcome:
        context = ssl.create_default_context() if scheme == "https" else None
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target,
                    port,
                    ssl=context,
                    server_hostname=target if context is not None else None,
                ),
                timeout=self._timeout,
            )
        except (TimeoutError, OSError):
            return _Outcome("fail", _elapsed_ms(start), "the request did not complete")
        try:
            request = (
                f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: netsight-diagnostic\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", "ignore"))
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            line = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
        except (TimeoutError, OSError):
            return _Outcome("fail", _elapsed_ms(start), "the request did not complete")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        code = _status_code(line)
        if code is None:
            return _Outcome("fail", _elapsed_ms(start), "no HTTP status line was returned")
        # Any HTTP status below 500 proves the endpoint answered; a 5xx reports itself unhealthy.
        return _Outcome("fail" if code >= 500 else "pass", _elapsed_ms(start), f"HTTP {code}")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _valid_target(entry: str) -> bool:
    return TARGET_PATTERN.fullmatch(entry) is not None and ".." not in entry


def parse_allowed_targets(raw: str) -> list[str]:
    """The validated, lower-cased, de-duplicated allow-list from its comma-separated form.

    Fail closed: an entry that is not a plain operator-chosen name or address is dropped (never
    repaired) and so can never be probed; entries beyond ``MAX_ALLOWED_TARGETS`` are dropped too.
    Dropped entries are counted in the log without their content. Empty means no probing at all.
    """
    valid: list[str] = []
    invalid = 0
    for entry in raw.split(","):
        item = entry.strip()
        if not item:
            continue
        if not _valid_target(item):
            invalid += 1
        elif item.lower() not in valid:
            if len(valid) >= MAX_ALLOWED_TARGETS:
                invalid += 1
            else:
                valid.append(item.lower())
    if invalid:
        _LOGGER.warning("ignored invalid probe allow-list entries", extra={"count": invalid})
    return valid


def get_optional_blackbox_client() -> BlackboxClient | None:
    """Probe client when at least one target is allow-listed; ``None`` means not-connected.

    A deployment with no allow-list has no probe capability, so the endpoint answers an explicit
    ``not-connected`` state rather than pretending a check ran.
    """
    allowed = parse_allowed_targets(os.environ.get(ALLOWED_TARGETS_ENV, ""))
    if not allowed:
        return None
    vantage = os.environ.get("BLACKBOX_VANTAGE", "").strip() or None
    timeout = _env_float("BLACKBOX_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS)
    return AllowlistedBlackboxClient(
        allowed=allowed, vantage=vantage, timeout=timeout, location=_env_location()
    )


def _env_location() -> ProbeLocation | None:
    """The location this prober is deployed at; an unrecognised value is ignored, never trusted."""
    raw = os.environ.get("BLACKBOX_LOCATION", "").strip()
    if not raw:
        return None
    for location in PROBE_LOCATIONS:
        if raw == location:
            return location
    _LOGGER.warning("ignored unrecognised BLACKBOX_LOCATION")
    return None


async def run_checks(
    clients: BlackboxClient | Sequence[BlackboxClient],
    *,
    target: str,
    vantage: str | None,
    checks: Sequence[DiagnosticCheckKind],
) -> list[Observation]:
    """Run the requested checks against each probe source in order, bounded by their timeouts.

    Sequential on purpose: a run is capped at twelve checks per source and must not burst a target
    with concurrent connections. A source that declares ``probe_kinds`` is asked only for those, so
    a run holds at most twelve checks from the local prober plus four per exporter location. The
    caller bounds the whole sequence with ``asyncio.wait_for``.
    """
    sources = [clients] if not isinstance(clients, Sequence) else list(clients)
    observations: list[Observation] = []
    for client in sources:
        kinds = getattr(client, "probe_kinds", None)
        for kind in checks:
            if kinds is not None and kind not in kinds:
                continue
            observations.append(await client.probe(kind=kind, target=target, vantage=vantage))
    return observations
