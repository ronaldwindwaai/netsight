"""Building the action engine from the environment (Step 12).

* ``NETSIGHT_ACTIONS_ENABLED`` (``1|true|yes|on``; ``0|false|no|off`` or unset keep it **off**; anything
  else fails start-up): without it the surface answers ``not-connected`` and nothing is stored,
  approved or executed. The default is off because no live executor exists and an operator should
  choose to turn the framework on.
* ``DATABASE_URL`` (the application-role PostgreSQL connection every durable store uses): when it is set,
  requests, approvals and history live in PostgreSQL (migration 0007), survive a restart and are shared
  between workers. When it is unset the store is process-local memory and says so (``store.durable:
  false``). A ``DATABASE_URL`` that is not a ``postgresql://`` URL fails start-up when the engine is
  enabled. When the runtime is built the store is probed once (``check()``): a deployment error (a
  missing table, grant or trigger of migration 0007) fails start-up with what to apply; an unreachable
  or failing database does NOT (it may be a transient outage during a restart): it is logged at ERROR
  and every call answers 503 until the database returns. Nothing ever falls back to memory.
* ``NETSIGHT_ACTIONS_REQUIRE_DURABLE`` (same syntax; fails start-up if garbled; default off): with the
  engine enabled, refuse to start without ``DATABASE_URL`` instead of running on volatile memory.
* ``NETSIGHT_ACTIONS_KILL_SWITCH`` (same syntax; an unreadable value counts as *engaged*).
* ``NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE`` (same syntax; fails start-up if garbled): policy flag, **off**
  by default. Off, the person who requested an action cannot execute it (approval is separate and is
  always refused to the requester). On, a requester who is also permitted to execute may run their own
  approved request; the approval(s) are still required.
* ``NETSIGHT_ACTIONS_LIVE_EXECUTION`` (same syntax; fails start-up if garbled): reported as ``disabled``
  when off and ``not-connected`` when on, because no live connector ships.

The kill switch stays per process whatever the store: engaging it on one worker does not engage the
others (the environment variable and a restart are the hard stop across workers; see ``killswitch.py``).
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from netsight_api.actions.engine import ExecutionEngine, FindingReader, finding_pre_check
from netsight_api.actions.errors import StoreMisconfigured, StoreUnavailable
from netsight_api.actions.executors import Executor, build_executors
from netsight_api.actions.killswitch import KillSwitch, env_engaged
from netsight_api.actions.store import ActionStore, InMemoryActionStore
from netsight_api.audit import record_audit
from netsight_api.storage.connection import APP_DSN_VARIABLE, PostgresSettings
from netsight_api.storage.errors import StorageConfigurationError

ENABLED_ENV: Final = "NETSIGHT_ACTIONS_ENABLED"
SELF_EXECUTE_ENV: Final = "NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE"
REQUIRE_DURABLE_ENV: Final = "NETSIGHT_ACTIONS_REQUIRE_DURABLE"
_LOGGER: Final = logging.getLogger("netsight_api")
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"0", "false", "no", "off", ""})


@dataclass(frozen=True)
class ActionRuntime:
    store: ActionStore
    kill_switch: KillSwitch
    executors: list[Executor]
    engine: ExecutionEngine


def actions_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get(ENABLED_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{ENABLED_ENV} must be 1/true/yes/on or 0/false/no/off")


def self_execute_allowed(env: Mapping[str, str]) -> bool:
    raw = env.get(SELF_EXECUTE_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{SELF_EXECUTE_ENV} must be 1/true/yes/on or 0/false/no/off")


def require_durable(env: Mapping[str, str]) -> bool:
    raw = env.get(REQUIRE_DURABLE_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{REQUIRE_DURABLE_ENV} must be 1/true/yes/on or 0/false/no/off")


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_environment(env: Mapping[str, str] | None = None) -> None:
    """Fail start-up on a garbled flag instead of running with a guessed setting."""
    source = os.environ if env is None else env
    required = require_durable(source)
    if actions_enabled(source) and database_settings(source) is None and required:
        raise ValueError(f"{REQUIRE_DURABLE_ENV} needs {APP_DSN_VARIABLE}")
    self_execute_allowed(source)
    build_executors(source)


def database_settings(env: Mapping[str, str]) -> PostgresSettings | None:
    """The PostgreSQL settings when ``DATABASE_URL`` is set (the durable store), else ``None`` (memory).

    A value that is set but is not a PostgreSQL URL raises instead of quietly meaning memory.
    """
    if not env.get(APP_DSN_VARIABLE, "").strip():
        return None
    try:
        return PostgresSettings.from_env(env)
    except StorageConfigurationError:
        raise ValueError(f"{APP_DSN_VARIABLE} must be a postgresql:// URL") from None


def build_store(env: Mapping[str, str], kill_switch: KillSwitch) -> ActionStore:
    """PostgreSQL when ``DATABASE_URL`` is configured, process memory otherwise. Connects to nothing."""
    settings = database_settings(env)
    allow_self = self_execute_allowed(env)
    if settings is None:
        if require_durable(env):
            raise ValueError(f"{REQUIRE_DURABLE_ENV} needs {APP_DSN_VARIABLE}")
        return InMemoryActionStore(
            kill_switch=kill_switch,
            on_system_transition=_audit_system_transition,
            allow_self_execute=allow_self,
        )
    from netsight_api.actions.postgres_store import PostgresActionStore  # lazy: needs psycopg

    return PostgresActionStore(
        settings,
        kill_switch=kill_switch,
        on_system_transition=_audit_system_transition,
        allow_self_execute=allow_self,
    )


def _probe(store: ActionStore) -> None:
    """Check a durable store once. Only a clear deployment error stops start-up; an outage does not."""
    if not store.durable:
        return
    try:
        store.check()
    except StoreMisconfigured:
        raise ValueError(
            "the action store is not set up: apply migration 0007 and the application-role grants"
        ) from None
    except StoreUnavailable:
        _LOGGER.error(
            "the action store could not be reached at start-up; requests answer 503 until it is"
        )


def _audit_system_transition(request_id: str, state: str, code: str) -> None:
    """The clock, not a person, moved a request: that is audited too (actor `system:actions`)."""
    record_audit(
        "actions.system-transition",
        outcome="success",
        actor_id="system:actions",
        correlation_id="system",
        target=request_id,
        state=state,
        code=code,
    )


def build_runtime(
    env: Mapping[str, str],
    *,
    clock: Callable[[], datetime] = utc_now,
    findings: Callable[[], FindingReader | None] | None = None,
) -> ActionRuntime | None:
    """The engine, or ``None`` when it is not enabled. Invalid configuration raises."""
    if not actions_enabled(env):
        return None
    kill_switch = KillSwitch(env_engaged=env_engaged(env))
    store = build_store(env, kill_switch)
    _probe(store)
    executors = build_executors(env)
    checks = [finding_pre_check(findings)] if findings is not None else []
    engine = ExecutionEngine(
        store=store, executors=executors, clock=clock, checks=checks, kill_switch=kill_switch
    )
    return ActionRuntime(store=store, kill_switch=kill_switch, executors=executors, engine=engine)


_lock = threading.Lock()
_runtime: ActionRuntime | None = None
_built = False


def _finding_reader() -> FindingReader | None:
    from netsight_api.unknown_devices.wiring import get_optional_store

    return get_optional_store()


def get_runtime_singleton() -> ActionRuntime | None:
    """The process-wide engine, built on first use from the environment."""
    global _runtime, _built
    with _lock:
        if not _built:
            _runtime = build_runtime(os.environ, findings=_finding_reader)
            _built = True
        return _runtime


def reset_for_tests() -> None:
    global _runtime, _built
    with _lock:
        _runtime = None
        _built = False
