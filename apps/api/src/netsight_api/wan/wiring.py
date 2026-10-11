"""Assembly and scheduling of the WAN collector from the environment.

Off by default: nothing is probed or stored unless ``NETSIGHT_WAN_SAMPLING_ENABLED`` is set
explicitly (``1|true|yes|on``; ``0|false|no|off`` or unset keep it off; anything else fails
start-up). Enabled, it needs its **own** database credential and a usable ``NETSIGHT_WAN_LINKS``
declaration, and fails start-up without them: a collector that cannot record, or has nothing to
sample, must not run.

* ``NETSIGHT_WAN_COLLECTOR_DATABASE_URL``: a role that may INSERT into the WAN evidence tables and
  nothing else (``storage/grants/wan_collector_role.sql``). It must not be the API's role
  (``DATABASE_URL``, SELECT only on those tables) and is checked at start-up: a superuser, a
  row-security bypass or an owner of the tables is refused, and so is a role that cannot be
  checked. The collector never needs ``DATABASE_URL``.
* Month partitions are created by the migrator (``... migrate partitions``), not here: the
  collector has no DDL right, and a write into a month with no partition is refused and logged.

* ``NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS``: 30 to 300, default 60 (stored with every cycle, so the
  SLA arithmetic stays deterministic across a later change of the setting).
* Probes use the existing allow-listed clients (``BLACKBOX_ALLOWED_TARGETS``,
  ``BLACKBOX_EXPORTER_SOURCES``, ``BLACKBOX_LOCATION``); no allow-list means no probing.
* Exactly one collector may run per database: the scheduler (``evaluation.wiring.run_scheduler``)
  runs rounds only while it holds a PostgreSQL advisory lock on a dedicated connection, under a key
  of its own (``WAN_COLLECTOR_LOCK_KEY``), so it does not contend with the alert evaluator.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlsplit

from netsight_api.adapters.blackbox import get_optional_blackbox_client
from netsight_api.adapters.blackbox_exporter import get_exporter_clients
from netsight_api.evaluation.leader import LeaderLock, PostgresLeaderLock
from netsight_api.evaluation.wiring import CycleRunner, run_scheduler, stop_evaluation
from netsight_api.storage import StorageConfigurationError
from netsight_api.wan.collector import LocatedProbe, WanCollector
from netsight_api.wan.config import SamplingSettings, load_wan_links

_LOGGER: Final = logging.getLogger("netsight_api")
# Arbitrary, fixed 64-bit key for "the Netsight WAN collector" (advisory locks are per database).
WAN_COLLECTOR_LOCK_KEY: Final = 0x4E53_5741_4E00_0001
ENABLED_ENV: Final = "NETSIGHT_WAN_SAMPLING_ENABLED"
COLLECTOR_DSN_ENV: Final = "NETSIGHT_WAN_COLLECTOR_DATABASE_URL"


@dataclass(frozen=True, repr=False)
class WanCollectorService:
    runner: CycleRunner
    interval_seconds: int
    lock: LeaderLock | None = None

    def __repr__(self) -> str:
        return f"WanCollectorService(interval={self.interval_seconds})"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _same_credential(first: Any, second: Any) -> bool:
    """True when two settings name the same database role (or the very same DSN)."""
    user_a, user_b = urlsplit(first.dsn).username, urlsplit(second.dsn).username
    return first.dsn == second.dsn or (user_a is not None and user_a == user_b)


def _collector_database(env: Mapping[str, str]) -> Any:
    from netsight_api.storage.connection import PostgresSettings

    if not env.get(COLLECTOR_DSN_ENV, "").strip():
        raise ValueError(f"{ENABLED_ENV} requires {COLLECTOR_DSN_ENV}")
    try:
        settings = PostgresSettings.from_env(env, variable=COLLECTOR_DSN_ENV)
    except StorageConfigurationError:
        raise ValueError(f"{COLLECTOR_DSN_ENV} must be a postgresql:// URL") from None
    if env.get("DATABASE_URL", "").strip():
        try:
            api = PostgresSettings.from_env(env)
        except StorageConfigurationError:
            return settings  # the API's own configuration is reported where it is used
        if _same_credential(settings, api):
            raise ValueError(f"{COLLECTOR_DSN_ENV} must name a different role than DATABASE_URL")
    return settings


def build_wan_collector(
    env: Mapping[str, str] | None = None,
    *,
    local_factory: Callable[[], LocatedProbe | None] = get_optional_blackbox_client,  # type: ignore[assignment]
    exporter_factory: Callable[[], Sequence[LocatedProbe]] = get_exporter_clients,
    role_guard: Callable[[Any], None] | None = None,
) -> WanCollectorService | None:
    """The configured service, or ``None`` when sampling is not enabled.

    Raises ``ValueError`` for any invalid or incomplete configuration, and for a collector database
    role that fails ``role_guard`` (default: no superuser, no row-security bypass, not the table
    owner), a start-up failure.
    """
    source = os.environ if env is None else env
    settings = SamplingSettings.from_env(source)
    if not settings.enabled:
        return None
    database = _collector_database(source)
    declared = load_wan_links(source)
    if declared.state != "ok":
        raise ValueError(f"{ENABLED_ENV} requires a usable NETSIGHT_WAN_LINKS declaration")
    # Imported here: the PostgreSQL store pulls in the database driver, which the disabled
    # configuration (the default) never needs.
    from netsight_api.storage.postgres_wan import (
        PostgresWanSampleRepository,
        check_collector_role,
    )

    (role_guard or check_collector_role)(database)
    local, exporters = local_factory(), list(exporter_factory())
    if local is None and not exporters:
        _LOGGER.warning("WAN sampling is enabled but no probe source is configured")
    lock = PostgresLeaderLock(database, key=WAN_COLLECTOR_LOCK_KEY)
    collector = WanCollector(
        links=declared.links,
        store=PostgresWanSampleRepository(database),
        local=local,
        exporters=exporters,
        interval_seconds=settings.interval_seconds,
        clock=_utc_now,
    )
    return WanCollectorService(collector, settings.interval_seconds, lock)


@dataclass
class WanSamplingRuntime:
    """The running scheduler task and its stop event (``task`` is None when sampling is off)."""

    task: asyncio.Task[None] | None
    stop: asyncio.Event

    async def shutdown(self) -> None:
        await stop_evaluation(self.task, self.stop)


def start_wan_sampling(service: WanCollectorService | None) -> WanSamplingRuntime:
    stop = asyncio.Event()
    if service is None:
        return WanSamplingRuntime(None, stop)
    task = asyncio.create_task(
        run_scheduler(service.runner, service.interval_seconds, stop, lock=service.lock),
        name="netsight-wan-sampling",
    )
    return WanSamplingRuntime(task, stop)
