"""Executors: the interface between the action engine and the outside world (Step 12).

**This release ships only the dry-run executor**, which records what *would* happen and contacts
nothing: this module imports no socket, HTTP, SSH, SNMP or process library, and a test keeps it so.
A ``live`` executor slot exists so the framework (pre-checks, verification, rollback, timeouts, the
status contract) has a real shape, but it implements nothing: it reports ``disabled`` until
``NETSIGHT_ACTIONS_LIVE_EXECUTION`` is set and ``not-connected`` after, because no connector exists.
Selecting an executor therefore always yields the dry-run executor today, and every execution record
says ``mode: dry-run`` and ``effect: none``.

An executor receives an ``ExecutionContext``: the definition, the target and the validated typed
parameters. It never receives the reason, the requester or any free text, and there is no command
string anywhere in the interface, so nothing a caller wrote can become a command.

A future connector implements ``Executor``, is added to ``build_executors`` behind its own env gate,
passes a lab and a security review (ACTION-ENGINE.md), and uses short-lived credentials from the
secret store, never source or request data.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from netsight_api.actions.catalog import ActionDef
from netsight_api.schemas_actions import (
    ActionCheck,
    ActionRollback,
    ActionSource,
    ActionVerification,
    ExecutionMode,
    ExecutorStatus,
    ParamValue,
)

LIVE_ENV: Final = "NETSIGHT_ACTIONS_LIVE_EXECUTION"
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"0", "false", "no", "off", ""})
DRY_RUN_ID: Final = "dry-run"
LIVE_ID: Final = "live"


class ExecutorUnavailable(RuntimeError):
    """The executor cannot act: it is disabled or has no connector. Carries no detail."""


@dataclass(frozen=True)
class ExecutionContext:
    """Everything an executor may know. No reason, requester, note or command text."""

    action_id: str
    action_type: str
    target_id: str
    params: Mapping[str, ParamValue]
    source: ActionSource | None
    definition: ActionDef


@dataclass(frozen=True)
class ExecuteResult:
    """``failure`` is a static code (``^[a-z][a-z0-9-]+$``) or ``None`` for success."""

    failure: str | None = None


class Executor(Protocol):
    id: str
    mode: ExecutionMode

    def status(self) -> ExecutorStatus: ...
    def pre_checks(self, ctx: ExecutionContext) -> list[ActionCheck]: ...
    def execute(self, ctx: ExecutionContext) -> ExecuteResult: ...
    def verify(self, ctx: ExecutionContext) -> ActionVerification: ...
    def rollback(self, ctx: ExecutionContext) -> ActionRollback: ...


class DryRunExecutor:
    """Records what would happen. Contacts nothing and changes nothing, by construction."""

    id = DRY_RUN_ID
    mode: ExecutionMode = "dry-run"

    def status(self) -> ExecutorStatus:
        return ExecutorStatus(id=self.id, mode="dry-run", state="ok")

    def pre_checks(self, ctx: ExecutionContext) -> list[ActionCheck]:
        return []

    def execute(self, ctx: ExecutionContext) -> ExecuteResult:
        return ExecuteResult()

    def verify(self, ctx: ExecutionContext) -> ActionVerification:
        return ActionVerification(state="not-applicable", detail="dry-run")

    def rollback(self, ctx: ExecutionContext) -> ActionRollback:
        return ActionRollback(state="not-needed", detail="dry-run")


class LiveExecutor:
    """The slot for real connectors. It implements none: it is disabled, then not connected."""

    id = LIVE_ID
    mode: ExecutionMode = "live"

    def __init__(self, enabled: bool) -> None:
        self._enabled = enabled

    def status(self) -> ExecutorStatus:
        if self._enabled:
            return ExecutorStatus(id=self.id, mode="live", state="not-connected")
        return ExecutorStatus(id=self.id, mode="live", state="disabled")

    def pre_checks(self, ctx: ExecutionContext) -> list[ActionCheck]:
        raise ExecutorUnavailable

    def execute(self, ctx: ExecutionContext) -> ExecuteResult:
        raise ExecutorUnavailable

    def verify(self, ctx: ExecutionContext) -> ActionVerification:
        raise ExecutorUnavailable

    def rollback(self, ctx: ExecutionContext) -> ActionRollback:
        raise ExecutorUnavailable


def live_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get(LIVE_ENV, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{LIVE_ENV} must be 1/true/yes/on or 0/false/no/off")


def build_executors(env: Mapping[str, str]) -> list[Executor]:
    """The executors this process has. Invalid configuration raises (fail at start-up, not open)."""
    return [DryRunExecutor(), LiveExecutor(enabled=live_enabled(env))]


def select_executor(executors: Sequence[Executor]) -> Executor:
    """The first live executor that is ready, else the dry-run executor. Never an unready one."""
    for executor in executors:
        if executor.mode == "live" and executor.status().state == "ok":
            return executor
    for executor in executors:
        if executor.mode == "dry-run":
            return executor
    raise ExecutorUnavailable
