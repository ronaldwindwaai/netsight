"""The execution engine (Step 12): pre-checks, execute, verify, roll back, with timeouts.

Order, and what each step guarantees:

1. the store starts the run under its lock (``begin_execution``): digest and version must match what
   the person saw, the request must be approved and unexpired, the kill switch off, the target not
   locked, and the execution key unused. A retry with the same key reports the recorded result and
   does not run anything again;
2. the stored request is **re-validated against the catalogue** (defence in depth: what runs is what the
   catalogue allows today, not merely what was accepted once);
3. pre-checks run (the executor's own plus the engine's, such as "the finding is still open and its
   evidence has not moved"); a failed check stops before the executor acts, an unknown one stops a live
   run but not a dry run, and the result is recorded either way;
4. the executor acts under a timeout; an exception or an overrun is a failure with a static code, and
   the exception text is discarded (it may hold addresses or credentials);
5. the result is verified; a failed verification triggers the executor's rollback; an unverifiable result
   is failed, never assumed good.

A dry run ends ``succeeded`` with ``effect: none`` and ``verification: not-applicable``.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol

from netsight_api.actions import errors as e
from netsight_api.actions.catalog import (
    ActionDef,
    ParamError,
    TargetError,
    get_definition,
    plan_steps,
    validate_params,
    validate_target,
)
from netsight_api.actions.executors import (
    ExecuteResult,
    ExecutionContext,
    Executor,
    select_executor,
)
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.model import EffectName, ExecutionFinish, FinalState
from netsight_api.actions.store import ActionStore
from netsight_api.schemas_actions import (
    ActionActor,
    ActionCheck,
    ActionRequest,
    ActionRollback,
    ActionVerification,
    EventType,
)
from netsight_api.schemas_unknown_devices import FINAL_STATES, UnknownDeviceFinding

PreCheck = Callable[[ActionRequest], ActionCheck | None]
_CODE: Final = re.compile(r"[a-z][a-z0-9-]{1,63}")


class FindingReader(Protocol):
    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None: ...


def finding_pre_check(get_store: Callable[[], FindingReader | None]) -> PreCheck:
    """The check that the finding behind a request is still open and its evidence has not moved."""

    def check(request: ActionRequest) -> ActionCheck | None:
        source = request.source
        if source is None:
            return None
        store = get_store()
        if store is None:
            return ActionCheck(
                name="finding-current", state="unknown", detail="findings-not-connected"
            )
        try:
            finding = store.get_finding(source.id)
        except Exception:  # noqa: BLE001 - a storage failure is "unknown", never a guess or a leak
            return ActionCheck(
                name="finding-current", state="unknown", detail="findings-unreadable"
            )
        if finding is None:
            return ActionCheck(name="finding-current", state="fail", detail="finding-not-found")
        if finding.state in FINAL_STATES:
            return ActionCheck(name="finding-current", state="fail", detail="finding-closed")
        if finding.evidence_version != source.evidence_version:
            return ActionCheck(name="finding-current", state="fail", detail="evidence-changed")
        return ActionCheck(name="finding-current", state="pass", detail="ok")

    return check


@dataclass(frozen=True)
class ExecutionOutcome:
    """The request after the call, and whether this was a retry that ran nothing."""

    request: ActionRequest
    replayed: bool


class _Budget:
    """One monotonic deadline for the whole run: every step shares it, so the run always finishes
    (or is failed by the engine itself) before the store's sweep would fail it for being late."""

    def __init__(self, seconds: float) -> None:
        self._deadline = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())


class ExecutionEngine:
    def __init__(
        self,
        *,
        store: ActionStore,
        executors: Sequence[Executor],
        clock: Callable[[], datetime],
        checks: Sequence[PreCheck] = (),
        kill_switch: KillSwitch | None = None,
        timeout_override: float | None = None,
    ) -> None:
        self._store = store
        self._executors = list(executors)
        self._clock = clock
        self._checks = list(checks)
        self._kill = kill_switch
        self._timeout_override = timeout_override

    def execute(
        self,
        action_id: str,
        *,
        actor: ActionActor,
        expected_digest: str,
        expected_version: int,
        idempotency_key: str,
    ) -> ExecutionOutcome:
        request = self._store.get(action_id)
        if request is None:
            raise e.ActionNotFound
        definition = get_definition(request.action_type)
        executor = select_executor(self._executors)
        steps = plan_steps(definition, request.target_id, request.params) if definition else []
        began = self._store.begin_execution(
            action_id,
            actor=actor,
            expected_digest=expected_digest,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            executor_id=executor.id,
            mode=executor.mode,
            steps=steps,
            now=self._clock(),
        )
        if began.replayed:
            return ExecutionOutcome(began.request, True)
        try:
            return ExecutionOutcome(self._run(began.request, definition, executor), False)
        except e.ActionError:
            raise
        except Exception:  # noqa: BLE001 - never leave a started run "executing"; the cause is not kept
            failed = self._finish_failed(
                began.request, executor, "executor-error", (("failed", "executor-error"),), ()
            )
            return ExecutionOutcome(failed, False)

    # --- the run -------------------------------------------------------------------------------------

    def _run(
        self, request: ActionRequest, definition: ActionDef | None, executor: Executor
    ) -> ActionRequest:
        try:
            if definition is None:
                raise TargetError("action-not-allowed")
            params = validate_params(definition, request.params)
            validate_target(definition, request.target_id)
        except (ParamError, TargetError) as exc:
            return self._finish_failed(
                request, executor, str(exc), (("pre-check-failed", str(exc)),), ()
            )
        ctx = ExecutionContext(
            action_id=request.id,
            action_type=request.action_type,
            target_id=request.target_id,
            params=params,
            source=request.source,
            definition=definition,
        )
        budget = _Budget(self._timeout_override or float(definition.timeout_seconds))
        checks, error = self._pre_checks(request, executor, ctx, budget)
        if error is not None:
            return self._finish_failed(request, executor, error, (("failed", error),), checks)
        blocked = self._blocking(checks, executor)
        if blocked is not None:
            return self._finish_failed(
                request, executor, blocked, (("pre-check-failed", blocked),), checks
            )
        if self._kill is not None and self._kill.engaged:
            # Engaged since the run started: nothing is asked of the executor.
            return self._finish_failed(
                request, executor, "kill-switch", (("failed", "kill-switch"),), checks
            )
        return self._act(request, executor, ctx, budget, checks)

    def _pre_checks(
        self, request: ActionRequest, executor: Executor, ctx: ExecutionContext, budget: _Budget
    ) -> tuple[tuple[ActionCheck, ...], str | None]:
        own, error = _guard(lambda: executor.pre_checks(ctx), budget)
        if error is not None or own is None:
            return (), error or "executor-error"
        extra, error = _guard(lambda: self._engine_checks(request), budget)
        if error is not None or extra is None:
            return (), error or "executor-error"
        return (*own, *extra), None

    def _engine_checks(self, request: ActionRequest) -> list[ActionCheck]:
        found = (check(request) for check in self._checks)
        return [c for c in found if c is not None]

    @staticmethod
    def _blocking(checks: tuple[ActionCheck, ...], executor: Executor) -> str | None:
        if any(c.state == "fail" for c in checks):
            return "pre-check-failed"
        if executor.mode == "live" and any(c.state == "unknown" for c in checks):
            return "pre-check-unknown"
        return None

    def _act(
        self,
        request: ActionRequest,
        executor: Executor,
        ctx: ExecutionContext,
        budget: _Budget,
        checks: tuple[ActionCheck, ...],
    ) -> ActionRequest:
        result, error = _guard(lambda: executor.execute(ctx), budget)
        if error is not None or result is None:
            code = error or "executor-error"
            return self._finish_failed(request, executor, code, (("failed", code),), checks)
        if result.failure is not None:
            code = result.failure if _CODE.fullmatch(result.failure) else "executor-error"
            return self._finish_failed(request, executor, code, (("failed", code),), checks)
        verification, error = _guard(lambda: executor.verify(ctx), budget)
        if error is not None or verification is None:
            code = error or "executor-error"
            events: tuple[tuple[EventType, str], ...] = (("executed", "executed"), ("failed", code))
            return self._finish_failed(request, executor, code, events, checks)
        return self._conclude(request, executor, ctx, budget, checks, verification)

    def _conclude(
        self,
        request: ActionRequest,
        executor: Executor,
        ctx: ExecutionContext,
        budget: _Budget,
        checks: tuple[ActionCheck, ...],
        verification: ActionVerification,
    ) -> ActionRequest:
        live = executor.mode == "live"
        applied: EffectName = "applied" if live else "none"
        if verification.state == "not-applicable" and not live:
            events: tuple[tuple[EventType, str], ...] = (("executed", "dry-run-recorded"),)
            return self._finish(
                request, "succeeded", applied, None, verification, None, events, checks
            )
        if verification.state == "passed":
            events = (("executed", "executed"), ("verification-passed", "verified"))
            return self._finish(
                request, "succeeded", applied, None, verification, None, events, checks
            )
        if verification.state == "failed":
            return self._roll_back(request, executor, ctx, budget, checks, verification)
        return self._finish(
            request,
            "failed",
            "unknown" if live else "none",
            "verification-unknown",
            ActionVerification(state="unknown", detail="not-confirmed"),
            None,
            (("executed", "executed"), ("failed", "verification-unknown")),
            checks,
        )

    def _roll_back(
        self,
        request: ActionRequest,
        executor: Executor,
        ctx: ExecutionContext,
        budget: _Budget,
        checks: tuple[ActionCheck, ...],
        verification: ActionVerification,
    ) -> ActionRequest:
        live = executor.mode == "live"
        rollback, error = _guard(lambda: executor.rollback(ctx), budget)
        if error is None and rollback is not None and rollback.state in ("completed", "not-needed"):
            return self._finish(
                request,
                "rolled-back",
                "applied" if live else "none",
                None,
                verification,
                rollback,
                (
                    ("executed", "executed"),
                    ("verification-failed", "mismatch"),
                    ("rolled-back", "rollback-done"),
                ),
                checks,
            )
        failed = ActionRollback(state="failed", detail=error or "rollback-failed")
        return self._finish(
            request,
            "failed",
            "unknown" if live else "none",
            "rollback-failed",
            verification,
            failed,
            (
                ("executed", "executed"),
                ("verification-failed", "mismatch"),
                ("rollback-failed", "rollback-failed"),
            ),
            checks,
        )

    # --- recording -----------------------------------------------------------------------------------

    def _finish_failed(
        self,
        request: ActionRequest,
        executor: Executor,
        failure: str,
        events: tuple[tuple[EventType, str], ...],
        checks: tuple[ActionCheck, ...],
    ) -> ActionRequest:
        effect: EffectName = "unknown" if executor.mode == "live" else "none"
        return self._finish(
            request,
            "failed",
            effect,
            failure,
            ActionVerification(state="unknown", detail="not-run"),
            None,
            events,
            checks,
        )

    def _finish(
        self,
        request: ActionRequest,
        final_state: FinalState,
        effect: EffectName,
        failure: str | None,
        verification: ActionVerification,
        rollback: ActionRollback | None,
        events: tuple[tuple[EventType, str], ...],
        checks: tuple[ActionCheck, ...],
    ) -> ActionRequest:
        try:
            return self._store.finish_execution(
                request.id,
                ExecutionFinish(
                    final_state=final_state,
                    effect=effect,
                    failure=failure,
                    verification=verification,
                    rollback=rollback,
                    events=events,
                    finished_at=self._clock(),
                    pre_checks=checks,
                ),
                now=self._clock(),
            )
        except e.IllegalTransition:
            # The clock-driven sweep failed this run while the executor was still working. Report what
            # the record now says (failed, executor-timeout) rather than losing it as a conflict.
            current = self._store.get(request.id)
            if current is None:
                raise
            return current


def _guard[T](call: Callable[[], T], budget: _Budget) -> tuple[T | None, str | None]:
    """Run ``call`` within what is left of the budget. Returns (value, None) or (None, static code).

    The exception, if any, is discarded: its text may contain addresses, hostnames or credentials.
    A call that overruns is abandoned on a daemon thread (it cannot be killed), so executors must be
    written to honour their own deadlines; the request is failed regardless.
    """
    remaining = budget.remaining()
    if remaining <= 0:
        return None, "executor-timeout"
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = call()
        except Exception:  # noqa: BLE001 - deliberate: see the docstring
            box["error"] = "executor-error"

    worker = threading.Thread(target=target, daemon=True, name="netsight-action-executor")
    worker.start()
    worker.join(remaining)
    if worker.is_alive():
        return None, "executor-timeout"
    if "error" in box:
        return None, box["error"]
    return box.get("value"), None


__all__ = ["ExecuteResult", "ExecutionEngine", "ExecutionOutcome", "PreCheck", "finding_pre_check"]
