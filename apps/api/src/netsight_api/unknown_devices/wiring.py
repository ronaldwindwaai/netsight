"""Building the unknown-device store, scanner and scheduler from the environment (Step 8c).

The store is the PostgreSQL application-role connection from ``DATABASE_URL`` (the same least-
privilege role as incidents; no new credential): without it the findings surface answers
``not-connected`` and a scan is refused. The scanner uses the clients the platform already has
(NetBox, LibreNMS, Wazuh), read-only.

A scheduled scan is **off by default** (``NETSIGHT_UNKNOWN_DEVICE_SCAN_ENABLED``, ``1|true|yes|on``;
``0|false|no|off`` or unset keep it off; anything else fails start-up). Enabled, it needs
``DATABASE_URL`` and runs only while this process holds a PostgreSQL advisory lock of its own, so
several API workers never scan at once. ``NETSIGHT_UNKNOWN_DEVICE_SCAN_INTERVAL_SECONDS`` is 300 to
86400 (default 900). An operator can always scan on demand from the findings page. The scheduled
and the on-demand scan share one ``ScanGuard``: one at a time, at most one a minute.

``NETSIGHT_UNKNOWN_DEVICE_FP_TTL_DAYS`` (1 to 3650, default 90) is how long a "false positive"
dismissal suppresses an endpoint before the next sighting opens a new finding for review; an
invalid value fails start-up.

The severity policy (``NETSIGHT_UNKNOWN_DEVICE_POLICY[_FILE]``), the identity classification
variables and the inventory class map are read once per process and cached: **changing them needs a
restart** of the API to take effect (a reload endpoint would be a second way to change what the
scan concludes, and has none).
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from typing import Final, cast

from netsight_api.evaluation.leader import LeaderLock, PostgresLeaderLock
from netsight_api.evaluation.wiring import run_scheduler, stop_evaluation
from netsight_api.identity.model import CorrelationPolicy
from netsight_api.identity.netbox_source import AGENT_FIELD_ENV, agent_key_field_from_env
from netsight_api.inventory.wiring import configured_wazuh, utc_now
from netsight_api.storage import StorageConfigurationError, StorageError
from netsight_api.storage.unknown_devices import UnknownDeviceRepository, fp_ttl_from_env
from netsight_api.unknown_devices.policy import (
    POLICY_ENV,
    POLICY_FILE_ENV,
    SeverityPolicy,
    load_policy,
)
from netsight_api.unknown_devices.scanner import ScanGuard, UnknownDeviceScanner

_LOGGER: Final = logging.getLogger("netsight_api")

ENABLED_ENV: Final = "NETSIGHT_UNKNOWN_DEVICE_SCAN_ENABLED"
INTERVAL_ENV: Final = "NETSIGHT_UNKNOWN_DEVICE_SCAN_INTERVAL_SECONDS"
DEFAULT_INTERVAL_SECONDS: Final = 900
MIN_INTERVAL_SECONDS: Final = 300
MAX_INTERVAL_SECONDS: Final = 86400
# Arbitrary, fixed 64-bit key for "the Netsight unknown-device scanner" (advisory locks are per database).
SCAN_LOCK_KEY: Final = 0x4E53_5544_5300_0001
SCAN_GUARD = ScanGuard()  # shared by the scheduled scan and the API in this process
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"0", "false", "no", "off", ""})
_CORRELATION_VARIABLES: Final = (
    "NETSIGHT_IDENTITY_SHARED_CIDRS",
    "NETSIGHT_IDENTITY_INTERNAL_CIDRS",
    "NETSIGHT_IDENTITY_VPN_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_CIDRS",
    "NETSIGHT_IDENTITY_GUEST_VLANS",
    "NETSIGHT_IDENTITY_STATIC_CIDRS",
)


class _UnavailableStore:
    """Stands in when ``DATABASE_URL`` is set but unusable: every call fails as unavailable."""

    def __getattr__(self, name: str) -> object:
        def unavailable(*_args: object, **_kwargs: object) -> object:
            raise StorageError("the finding store is not usable")

        return unavailable


def get_optional_store() -> UnknownDeviceRepository | None:
    """PostgreSQL store for the app role (``DATABASE_URL``); ``None`` means not-connected."""
    if not os.environ.get("DATABASE_URL", "").strip():
        return None
    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres_unknown_devices import PostgresUnknownDeviceRepository

    try:
        settings = PostgresSettings.from_env()
        fp_ttl = fp_ttl_from_env(os.environ)
    except (StorageConfigurationError, ValueError):
        return cast(UnknownDeviceRepository, _UnavailableStore())
    return PostgresUnknownDeviceRepository(settings, fp_ttl=fp_ttl)


@cache
def _policy_for(inline: str, path: str) -> SeverityPolicy:
    return load_policy({POLICY_ENV: inline, POLICY_FILE_ENV: path})


@cache
def _correlation_for(environment: tuple[tuple[str, str], ...]) -> CorrelationPolicy:
    try:
        return CorrelationPolicy.from_env(dict(environment))
    except ValueError:
        # The shared network classification is unusable: treat every address as shared, so no
        # endpoint is judged (fail closed) rather than judged against a guessed classification.
        _LOGGER.warning("identity correlation policy is invalid; the scan will judge no address")
        return CorrelationPolicy(shared_cidrs=("0.0.0.0/0", "::/0"))


def build_scanner(store: UnknownDeviceRepository) -> UnknownDeviceScanner:
    from netsight_api import main  # lazy: main owns the NetBox and LibreNMS factories

    return UnknownDeviceScanner(
        netbox=main.get_optional_netbox_client(),
        librenms=main.get_optional_librenms_client(),
        wazuh=configured_wazuh(),
        agent_field=agent_key_field_from_env(os.environ.get(AGENT_FIELD_ENV, "")),
        evidence_sources=[],  # DHCP, switch MAC table and Wi-Fi adapters are not built yet
        store=store,
        policy=_policy_for(os.environ.get(POLICY_ENV, ""), os.environ.get(POLICY_FILE_ENV, "")),
        correlation=_correlation_for(
            tuple((n, os.environ.get(n, "")) for n in _CORRELATION_VARIABLES)
        ),
        clock=utc_now,
        guard=SCAN_GUARD,
    )


def reset_for_tests() -> None:
    global SCAN_GUARD
    _policy_for.cache_clear()
    _correlation_for.cache_clear()
    SCAN_GUARD = ScanGuard()


# --- the scheduled scan -------------------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class ScanService:
    scanner: UnknownDeviceScanner
    interval_seconds: int
    lock: LeaderLock

    def __repr__(self) -> str:
        return f"ScanService(interval={self.interval_seconds})"


def scan_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get(ENABLED_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{ENABLED_ENV} must be 1/true/yes/on or 0/false/no/off")


def scan_interval(env: Mapping[str, str]) -> int:
    raw = env.get(INTERVAL_ENV, "").strip()
    if not raw:
        return DEFAULT_INTERVAL_SECONDS
    if (
        not raw.isascii()
        or not raw.isdigit()
        or not MIN_INTERVAL_SECONDS <= int(raw) <= MAX_INTERVAL_SECONDS
    ):
        raise ValueError(f"{INTERVAL_ENV} must be {MIN_INTERVAL_SECONDS} to {MAX_INTERVAL_SECONDS}")
    return int(raw)


def build_scan_service(env: Mapping[str, str] | None = None) -> ScanService | None:
    """The scheduled scan, or ``None`` when it is not enabled. Invalid configuration raises."""
    source = os.environ if env is None else env
    fp_ttl_from_env(source)  # the dismissal lifetime is validated at start-up, scan or no scan
    if not scan_enabled(source):
        return None
    interval = scan_interval(source)
    from netsight_api.storage.connection import PostgresSettings

    if not source.get("DATABASE_URL", "").strip():
        raise ValueError(f"{ENABLED_ENV} requires DATABASE_URL")
    try:
        settings = PostgresSettings.from_env(source)
    except StorageConfigurationError:
        raise ValueError("DATABASE_URL must be a postgresql:// URL") from None
    store = get_optional_store()
    assert store is not None  # DATABASE_URL was just checked
    return ScanService(
        build_scanner(store), interval, PostgresLeaderLock(settings, key=SCAN_LOCK_KEY)
    )


@dataclass
class ScanRuntime:
    task: asyncio.Task[None] | None
    stop: asyncio.Event

    async def shutdown(self) -> None:
        await stop_evaluation(self.task, self.stop)


def start_scan(service: ScanService | None) -> ScanRuntime:
    stop = asyncio.Event()
    if service is None:
        return ScanRuntime(None, stop)
    task = asyncio.create_task(
        run_scheduler(service.scanner, service.interval_seconds, stop, lock=service.lock),
        name="netsight-unknown-device-scan",
    )
    return ScanRuntime(task, stop)
