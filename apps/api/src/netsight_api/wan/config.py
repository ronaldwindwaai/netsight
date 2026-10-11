"""WAN link declaration and sampling settings from the environment (Step 5).

Which interface is a WAN link, who the ISP is, what the gateway is and which hosts to probe are
*operator declarations* (``NETSIGHT_WAN_LINKS``, a JSON array): Netsight never infers a WAN from
an interface name. Declared values are labelled "configured" in the API and never presented as
telemetry.

Fail closed: an unset (or empty) declaration is ``not-connected``; any invalid entry makes the
*whole* declaration ``unknown`` (a half-parsed list could mislead the failover reading), logged
by count only, never with the configured content. Links are frozen.

Sampling is a separate, off-by-default switch (``NETSIGHT_WAN_SAMPLING_ENABLED``) with a bounded
interval; an invalid value is a start-up error, never a silent default.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

from netsight_api.adapters.blackbox import TARGET_PATTERN
from netsight_api.schemas_diagnostics import PROBE_LOCATIONS, ProbeLocation

_LOGGER: Final = logging.getLogger("netsight_api")

LINKS_ENV: Final = "NETSIGHT_WAN_LINKS"
SAMPLING_ENABLED_ENV: Final = "NETSIGHT_WAN_SAMPLING_ENABLED"
SAMPLE_INTERVAL_ENV: Final = "NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS"
MAX_LINKS: Final = 8
MAX_PROBE_TARGETS: Final = 8
MIN_INTERVAL_SECONDS: Final = 30
MAX_INTERVAL_SECONDS: Final = 300
DEFAULT_INTERVAL_SECONDS: Final = 60

LinkRole = Literal["primary", "backup"]
ConfigState = Literal["not-connected", "unknown", "ok"]

_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,47}", re.ASCII)
_NATIVE_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
_ROLES: Final = ("primary", "backup")
_KEYS: Final = frozenset(
    {
        "id",
        "name",
        "role",
        "isp",
        "gateway",
        "librenms_device",
        "librenms_port",
        "probe_targets",
        "probe_location",
        "dns_target",
        "uptime_target_pct",
    }
)
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"", "0", "false", "no", "off"})


@dataclass(frozen=True)
class WanLinkConfig:
    id: str
    name: str
    role: LinkRole
    isp: str | None
    gateway: str | None
    librenms_device: str | None
    librenms_port: str | None
    probe_targets: tuple[str, ...]
    probe_location: ProbeLocation | None
    dns_target: str | None
    uptime_target_pct: float | None


@dataclass(frozen=True)
class WanConfig:
    state: ConfigState
    links: tuple[WanLinkConfig, ...] = ()


class _Invalid(ValueError):
    """An entry that cannot be used; carries no content so nothing configured is logged."""


def _text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise _Invalid
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise _Invalid
    return value.strip()


def _optional_text(entry: Mapping[str, Any], key: str, maximum: int) -> str | None:
    value = entry.get(key)
    return None if value is None else _text(value, maximum)


def _gateway(entry: Mapping[str, Any]) -> str | None:
    value = entry.get("gateway")
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(_text(value, 45)))
    except ValueError:
        raise _Invalid from None


def _native(entry: Mapping[str, Any], key: str) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or _NATIVE_ID.fullmatch(value) is None or ".." in value:
        raise _Invalid
    return value


def _host(value: object) -> str:
    if not isinstance(value, str) or TARGET_PATTERN.fullmatch(value) is None or ".." in value:
        raise _Invalid
    return value.lower()


def _targets(entry: Mapping[str, Any]) -> tuple[str, ...]:
    value = entry.get("probe_targets", [])
    if not isinstance(value, list) or len(value) > MAX_PROBE_TARGETS:
        raise _Invalid
    return tuple(dict.fromkeys(_host(item) for item in value))


def _location(entry: Mapping[str, Any]) -> ProbeLocation | None:
    value = entry.get("probe_location")
    if value is None:
        return None
    for location in PROBE_LOCATIONS:
        if value == location:
            return location
    raise _Invalid


def _target_pct(entry: Mapping[str, Any]) -> float | None:
    value = entry.get("uptime_target_pct")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _Invalid
    if not math.isfinite(value) or not 0 < value <= 100:
        raise _Invalid
    return float(value)


def _link(entry: object) -> WanLinkConfig:
    if not isinstance(entry, dict) or not set(entry) <= _KEYS:
        raise _Invalid
    identifier = entry.get("id")
    role = entry.get("role")
    if not isinstance(identifier, str) or _ID.fullmatch(identifier) is None or role not in _ROLES:
        raise _Invalid
    device, port = _native(entry, "librenms_device"), _native(entry, "librenms_port")
    if (device is None) != (port is None):
        raise _Invalid
    dns = entry.get("dns_target")
    return WanLinkConfig(
        id=identifier,
        name=_text(entry.get("name"), 128),
        role=role,
        isp=_optional_text(entry, "isp", 128),
        gateway=_gateway(entry),
        librenms_device=device,
        librenms_port=port,
        probe_targets=_targets(entry),
        probe_location=_location(entry),
        dns_target=None if dns is None else _host(dns),
        uptime_target_pct=_target_pct(entry),
    )


def _parse(raw: str) -> tuple[WanLinkConfig, ...]:
    try:
        decoded = json.loads(raw)
    except (ValueError, RecursionError):
        raise _Invalid from None
    if not isinstance(decoded, list) or len(decoded) > MAX_LINKS:
        raise _Invalid
    links = tuple(_link(entry) for entry in decoded)
    if len({link.id for link in links}) != len(links):
        raise _Invalid
    if sum(1 for link in links if link.role == "primary") > 1:
        raise _Invalid
    return links


def load_wan_links(env: Mapping[str, str]) -> WanConfig:
    """The declared links: ``not-connected`` when unset, ``unknown`` when unusable."""
    raw = env.get(LINKS_ENV, "").strip()
    if not raw:
        return WanConfig("not-connected")
    try:
        links = _parse(raw)
    except _Invalid:
        _LOGGER.warning("ignored an invalid WAN link declaration")
        return WanConfig("unknown")
    return WanConfig("ok", links) if links else WanConfig("not-connected")


@dataclass(frozen=True)
class SamplingSettings:
    enabled: bool = False
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> SamplingSettings:
        flag = env.get(SAMPLING_ENABLED_ENV, "").strip().lower()
        if flag not in _TRUE and flag not in _FALSE:
            raise ValueError(f"{SAMPLING_ENABLED_ENV} must be true or false")
        raw = env.get(SAMPLE_INTERVAL_ENV, "").strip()
        interval = DEFAULT_INTERVAL_SECONDS
        if raw:
            if re.fullmatch(r"[0-9]+", raw, re.ASCII) is None:
                raise ValueError(f"{SAMPLE_INTERVAL_ENV} must be an integer")
            interval = int(raw)
            if not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS:
                raise ValueError(
                    f"{SAMPLE_INTERVAL_ENV} must be between "
                    f"{MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}"
                )
        return cls(enabled=flag in _TRUE, interval_seconds=interval)
