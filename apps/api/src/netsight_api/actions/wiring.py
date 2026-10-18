"""Building the action engine from the environment (Step 12).

* ``NETSIGHT_ACTIONS_ENABLED`` (``1|true|yes|on``; ``0|false|no|off`` or unset keep it **off**; anything
  else fails start-up): without it the surface answers ``not-connected`` and nothing is stored,
  approved or executed. The default is off because the store is volatile and no live executor exists.
* ``NETSIGHT_ACTIONS_KILL_SWITCH`` (same syntax; an unreadable value counts as *engaged*).
* ``NETSIGHT_ACTIONS_LIVE_EXECUTION`` (same syntax; fails start-up if garbled): reported as ``disabled``
  when off and ``not-connected`` when on, because no live connector ships.

The store is process-local memory: requests, approvals and history are lost on restart and are not
shared between workers. The status contract says so (``store.durable: false``) and the operator
documentation lists it as the first thing a production deployment must replace.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from netsight_api.actions.engine import ExecutionEngine, FindingReader, finding_pre_check
from netsight_api.actions.executors import Executor, build_executors
from netsight_api.actions.killswitch import KillSwitch, env_engaged
from netsight_api.actions.store import ActionStore, InMemoryActionStore
from netsight_api.audit import record_audit

ENABLED_ENV: Final = "NETSIGHT_ACTIONS_ENABLED"
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


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_environment(env: Mapping[str, str] | None = None) -> None:
    """Fail start-up on a garbled flag instead of running with a guessed setting."""
    source = os.environ if env is None else env
    actions_enabled(source)
    build_executors(source)


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
    store = InMemoryActionStore(
        kill_switch=kill_switch, on_system_transition=_audit_system_transition
    )
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
