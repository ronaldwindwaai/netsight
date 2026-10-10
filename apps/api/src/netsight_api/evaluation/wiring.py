"""Assembly and scheduling of the evaluation service from the environment.

Off by default: nothing reads a source, a database or sends a message unless
``NETSIGHT_EVALUATION_ENABLED`` is set explicitly (``1|true|yes|on``; ``0|false|no|off`` or
unset keep it off; anything else fails start-up instead of guessing). Enabled, it needs the
application database (``DATABASE_URL``, the least-privilege role) and fails start-up without it:
an evaluator that cannot record incidents or deliveries must not run at all.

* ``NETSIGHT_EVALUATION_INTERVAL_SECONDS``: 30 to 3600, default 60.
* Channels: SMTP email (``smtp.py``), push gateway (``push.py``), destinations from
  ``routing_config.py``, base URL and bounds from ``NotificationSettings``.
* Exactly one evaluator may run against a database (a hard requirement, enforced by
  ``leader.py``): the scheduler runs cycles only while it holds a PostgreSQL advisory lock on a
  dedicated connection; every other process idles and retries each interval, and a process that
  loses the lock stops evaluating and drops its in-memory engine state.

``run_scheduler`` is the only loop: it runs one bounded cycle, then waits for the interval or the
stop event, and ends when the event is set. A failing cycle is logged by type and the next one
still runs. ``start_evaluation`` / ``stop_evaluation`` are the application-lifespan helpers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from netsight_api.adapters.librenms import LibrenmsClient
from netsight_api.evaluation.incidents import AlertIncidentService
from netsight_api.evaluation.leader import LeaderLock, PostgresLeaderLock
from netsight_api.evaluation.librenms_source import LibrenmsObservationSource
from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.evaluation.runner import EvaluationRunner
from netsight_api.notifications.dispatcher import (
    InMemoryDeliveryRecorder,
    NotificationDispatcher,
    RetryPolicy,
)
from netsight_api.notifications.models import ChannelKind
from netsight_api.notifications.push import PushGatewaySender, PushGatewaySettings
from netsight_api.notifications.routing_config import routing_rules_from_env
from netsight_api.notifications.senders import NotificationSender
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.notifications.smtp import SmtpEmailSender, SmtpSettings
from netsight_api.notifications.store import DurableDeliveryRecorder
from netsight_api.storage import StorageConfigurationError

_LOGGER: Final = logging.getLogger("netsight_api.evaluation")
MIN_INTERVAL_SECONDS: Final = 30
MAX_INTERVAL_SECONDS: Final = 3600
EVALUATION_STOP_TIMEOUT_SECONDS: Final = 10.0
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"", "0", "false", "no", "off"})


@dataclass(frozen=True)
class EvaluationSettings:
    enabled: bool = False
    interval_seconds: int = 60

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EvaluationSettings:
        source = os.environ if env is None else env
        flag = source.get("NETSIGHT_EVALUATION_ENABLED", "").strip().lower()
        if flag not in _TRUE and flag not in _FALSE:
            raise ValueError("NETSIGHT_EVALUATION_ENABLED must be true or false")
        raw = source.get("NETSIGHT_EVALUATION_INTERVAL_SECONDS", "").strip()
        interval = 60
        if raw:
            try:
                interval = int(raw)
            except ValueError:
                raise ValueError(
                    "NETSIGHT_EVALUATION_INTERVAL_SECONDS must be an integer"
                ) from None
            if not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS:
                raise ValueError(
                    "NETSIGHT_EVALUATION_INTERVAL_SECONDS must be between "
                    f"{MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}"
                )
        return cls(enabled=flag in _TRUE, interval_seconds=interval)


class CycleRunner(Protocol):
    async def run_cycle(self) -> Any: ...


@dataclass(frozen=True, repr=False)
class EvaluationService:
    runner: CycleRunner
    interval_seconds: int
    channels: tuple[str, ...]
    lock: LeaderLock | None = None
    # Delivery attempts the durable store did not accept (still in the in-memory ring).
    durable_failures: Callable[[], int] = field(default=lambda: 0)

    def __repr__(self) -> str:
        return f"EvaluationService(interval={self.interval_seconds}, channels={self.channels})"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _senders(
    env: Mapping[str, str], network: NotificationSettings
) -> dict[ChannelKind, NotificationSender]:
    senders: dict[ChannelKind, NotificationSender] = {}
    smtp = SmtpSettings.from_env(env)
    if smtp is not None:
        senders["email"] = SmtpEmailSender(smtp)
    gateway = PushGatewaySettings.from_env(env)
    if gateway is not None:
        senders["push"] = PushGatewaySender(gateway, network)
    return senders


def build_evaluation_service(
    env: Mapping[str, str] | None = None,
    *,
    librenms_client: Callable[[], LibrenmsClient | None],
) -> EvaluationService | None:
    """The configured service, or ``None`` when evaluation is not enabled.

    Raises ``ValueError`` for any invalid or incomplete configuration (start-up failure).
    """
    source = os.environ if env is None else env
    settings = EvaluationSettings.from_env(source)
    if not settings.enabled:
        return None
    if not source.get("DATABASE_URL", "").strip():
        raise ValueError("NETSIGHT_EVALUATION_ENABLED requires DATABASE_URL")
    database = _database_settings(source)
    network = NotificationSettings.from_env(source)
    senders = _senders(source, network)
    lock = PostgresLeaderLock(database)
    notifier, recorder = _notifier(source, network, senders, database)
    return EvaluationService(
        runner=_runner(database, librenms_client, notifier, lock),
        interval_seconds=settings.interval_seconds,
        channels=tuple(sorted(senders)),
        lock=lock,
        durable_failures=lambda: recorder.durable_failures,
    )


def _database_settings(source: Mapping[str, str]) -> Any:
    from netsight_api.storage.connection import PostgresSettings

    try:
        return PostgresSettings.from_env(source)
    except StorageConfigurationError:
        raise ValueError("DATABASE_URL must be a postgresql:// URL") from None


def _notifier(
    source: Mapping[str, str],
    network: NotificationSettings,
    senders: Mapping[ChannelKind, NotificationSender],
    database: Any,
) -> tuple[AlertNotifier, DurableDeliveryRecorder]:
    # Imported here: importing the PostgreSQL stores pulls in the database driver, which the
    # disabled configuration (the default) never needs.
    from netsight_api.notifications.store_postgres import PostgresDeliveryAttemptRepository

    attempts = PostgresDeliveryAttemptRepository(database)
    recorder = DurableDeliveryRecorder(InMemoryDeliveryRecorder(), attempts)
    dispatcher = NotificationDispatcher(
        senders,
        recorder,
        clock=_utc_now,
        sleep=time.sleep,
        policy=RetryPolicy(max_attempts=network.max_attempts),
        queue_limit=network.queue_limit,
        public_base_url=network.public_base_url,
    )
    notifier = AlertNotifier(
        dispatcher,
        routing_rules_from_env(source),
        attempts,
        public_base_url=network.public_base_url,
    )
    return notifier, recorder


def _runner(
    database: Any,
    librenms_client: Callable[[], LibrenmsClient | None],
    notifier: AlertNotifier,
    lock: LeaderLock,
) -> EvaluationRunner:
    from netsight_api.storage.postgres import (
        PostgresAlertRuleRepository,
        PostgresIncidentRepository,
    )
    from netsight_api.storage.postgres_links import PostgresAlertIncidentLinkRepository

    return EvaluationRunner(
        rules=PostgresAlertRuleRepository(database),
        source=LibrenmsObservationSource(librenms_client),
        incidents=AlertIncidentService(
            PostgresIncidentRepository(database), PostgresAlertIncidentLinkRepository(database)
        ),
        notifier=notifier,
        clock=_utc_now,
        lease=lock.still_held,
    )


# -- scheduling ---------------------------------------------------------------------------------


async def run_scheduler(
    runner: CycleRunner,
    interval_seconds: float,
    stop: asyncio.Event,
    *,
    lock: LeaderLock | None = None,
    durable_failures: Callable[[], int] | None = None,
) -> None:
    """Run cycles, ``interval_seconds`` apart, until ``stop`` is set.

    With a ``lock`` a cycle runs only while this process is the leader; otherwise it retries to
    become the leader each interval. ``durable_failures`` (a counter) is logged when it grows.
    """
    holding = False
    reported = 0
    try:
        while not stop.is_set():
            if lock is not None:
                holding = await _leadership(lock, runner, holding)
            if lock is None or holding:
                await _run_one(runner)
                reported = _report_failures(durable_failures, reported)
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
            except TimeoutError:
                continue
    finally:
        if lock is not None:
            _release(lock)


async def _run_one(runner: CycleRunner) -> None:
    try:
        await runner.run_cycle()
    except Exception as error:  # noqa: BLE001 - one failed cycle must not end evaluation
        _LOGGER.warning("evaluation cycle failed", extra={"error_type": type(error).__name__})


async def _leadership(lock: LeaderLock, runner: CycleRunner, holding: bool) -> bool:
    """Whether this process may evaluate now; a backend failure means no."""
    try:
        if not holding:
            return bool(await asyncio.to_thread(lock.try_acquire))
        if await asyncio.to_thread(lock.still_held):
            return True
    except Exception as error:  # noqa: BLE001 - not provably the leader, so not the leader
        _LOGGER.warning("evaluation lock unavailable", extra={"error_type": type(error).__name__})
    if holding:
        _LOGGER.warning("evaluation leadership lost; evaluation paused")
        _release(lock)
        reset = getattr(runner, "reset_state", None)
        if callable(reset):
            reset()
    return False


def _release(lock: LeaderLock) -> None:
    try:
        lock.release()
    except Exception as error:  # noqa: BLE001 - shutting down; the session end frees it anyway
        _LOGGER.warning(
            "evaluation lock release failed", extra={"error_type": type(error).__name__}
        )


def _report_failures(counter: Callable[[], int] | None, reported: int) -> int:
    if counter is None:
        return reported
    total = counter()
    if total > reported:
        _LOGGER.warning("delivery attempts not stored durably", extra={"failures_total": total})
    return total


# -- application lifespan -----------------------------------------------------------------------


@dataclass
class EvaluationRuntime:
    """The running scheduler task and its stop event (``task`` is None when evaluation is off)."""

    task: asyncio.Task[None] | None
    stop: asyncio.Event

    async def shutdown(self) -> None:
        await stop_evaluation(self.task, self.stop)


def start_evaluation(service: EvaluationService | None) -> EvaluationRuntime:
    stop = asyncio.Event()
    if service is None:
        return EvaluationRuntime(None, stop)
    task = asyncio.create_task(
        run_scheduler(
            service.runner,
            service.interval_seconds,
            stop,
            lock=service.lock,
            durable_failures=service.durable_failures,
        ),
        name="netsight-evaluation",
    )
    return EvaluationRuntime(task, stop)


async def stop_evaluation(
    task: asyncio.Task[None] | None,
    stop: asyncio.Event,
    *,
    timeout: float = EVALUATION_STOP_TIMEOUT_SECONDS,
) -> None:
    """Ask the scheduler to finish its cycle, then cancel it if it does not in time.

    A cancellation of the *caller* is never swallowed: it cancels the scheduler and propagates.
    """
    if task is None:
        return
    stop.set()
    try:
        await asyncio.wait({task}, timeout=timeout)
        if not task.done():
            task.cancel()
            await asyncio.wait({task})
    except asyncio.CancelledError:
        task.cancel()
        raise
    if not task.cancelled() and task.exception() is not None:
        _LOGGER.warning("evaluation scheduler ended with an error")
