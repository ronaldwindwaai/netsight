"""Proposals, executors and the execution engine (Step 12): dry-run only, pre-checks, verification,
rollback, timeouts and the guarantee that nothing contacts a device or a network system."""

from __future__ import annotations

import inspect
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest
from actions_support import ALICE, BOB, FINDING, NOW, make_finding, new_action, new_store
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.actions import executors as ex
from netsight_api.actions.catalog import CATALOG
from netsight_api.actions.engine import ExecutionEngine, finding_pre_check
from netsight_api.actions.errors import ActionError
from netsight_api.actions.proposals import (
    DEFAULT_ISOLATION_MINUTES,
    ProposalError,
    propose,
    propose_from_finding,
)
from netsight_api.schemas_actions import (
    ActionActor,
    ActionCheck,
    ActionRequest,
    ActionRollback,
    ActionSource,
    ActionVerification,
)

# --- proposals ----------------------------------------------------------------------------------------------


def test_a_proposal_is_built_only_from_the_catalogue_and_validated_input() -> None:
    new = propose(
        actor=ALICE,
        action_type="endpoint.isolate",
        target_id="endpoint:laptop-1",
        params={"duration_minutes": 30},
        reason="Unknown device on the finance VLAN",
        source=None,
        now=NOW,
    )
    assert re.fullmatch(r"action-[0-9a-f-]{36}", new.id)
    assert new.risk == "C" and new.approvals_required == 1
    assert new.approve_by == NOW + timedelta(
        seconds=CATALOG["endpoint.isolate"].approve_within_seconds
    )
    names = {c.name: c.state for c in new.policy_checks}
    assert (
        names["catalogue"] == "pass"
        and names["parameters"] == "pass"
        and names["target-shape"] == "pass"
    )
    # Honesty: nothing here can know the target exists, and the record says so.
    assert names["target-exists"] == "unknown"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"action_type": "shell.exec"}, "action-not-allowed"),
        ({"params": {"duration_minutes": 4}}, "parameter-range"),
        ({"params": {"duration_minutes": 30, "cmd": "x"}}, "parameter-unknown"),
        ({"target_id": "interface:sw1-gi0-1"}, "target-not-allowed"),
    ],
)
def test_a_bad_proposal_is_refused_with_a_static_code(kwargs: dict[str, Any], code: str) -> None:
    base: dict[str, Any] = {
        "actor": ALICE,
        "action_type": "endpoint.isolate",
        "target_id": "endpoint:laptop-1",
        "params": {"duration_minutes": 30},
        "reason": "Unknown device on the finance VLAN",
        "source": None,
        "now": NOW,
    }
    with pytest.raises(ProposalError) as raised:
        propose(**{**base, **kwargs})
    assert raised.value.code == code


class FindingStore:
    def __init__(self, finding: Any) -> None:
        self._finding = finding

    def get_finding(self, finding_id: str) -> Any:
        return (
            self._finding if self._finding is not None and self._finding.id == finding_id else None
        )


def test_a_quarantine_proposal_becomes_an_action_request_that_is_still_only_a_proposal() -> None:
    new = propose_from_finding(
        actor=ALICE,
        finding=make_finding(),
        expected_evidence_version=3,
        reason="Seen on the finance VLAN",
        now=NOW,
    )
    assert new.action_type == "endpoint.isolate" and new.target_id == FINDING
    assert new.params == {"duration_minutes": DEFAULT_ISOLATION_MINUTES}
    assert new.source == ActionSource(kind="unknown-device-finding", id=FINDING, evidence_version=3)
    # The endpoint's MAC, address and name are not copied into the action store.
    assert "aa:bb" not in repr(new) and "10.0.5.9" not in repr(new)


@pytest.mark.parametrize(
    ("finding", "version", "code"),
    [
        (make_finding(proposed_action=None), 3, "no-proposal"),
        (make_finding(state="resolved"), 3, "finding-closed"),
        (make_finding(state="false-positive"), 3, "finding-closed"),
        (make_finding(), 2, "stale-evidence"),
    ],
)
def test_a_finding_that_cannot_back_a_request_is_refused(
    finding: Any, version: int, code: str
) -> None:
    with pytest.raises(ProposalError) as raised:
        propose_from_finding(
            actor=ALICE,
            finding=finding,
            expected_evidence_version=version,
            reason="Because of reasons",
            now=NOW,
        )
    assert raised.value.code == code


# --- executors ------------------------------------------------------------------------------------------------


def _old_import_scan() -> None:
    source = inspect.getsource(ex)
    for forbidden in (
        "socket",
        "httpx",
        "requests",
        "urllib",
        "subprocess",
        "asyncssh",
        "paramiko",
        "netmiko",
        "telnetlib",
        "pysnmp",
        "os.system",
        "ftplib",
        "smtplib",
        "aiohttp",
    ):
        assert not re.search(
            rf"^\s*(import|from)\s+{re.escape(forbidden)}\b", source, re.MULTILINE
        ), forbidden


def test_the_dry_run_executor_is_always_ok_and_the_live_executor_is_off_by_default() -> None:
    executors = ex.build_executors({})
    by_id = {e.id: e for e in executors}
    assert by_id["dry-run"].status().state == "ok" and by_id["dry-run"].mode == "dry-run"
    assert by_id["live"].status().state == "disabled" and by_id["live"].mode == "live"
    assert ex.select_executor(executors).id == "dry-run"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_enabling_live_execution_still_reports_not_connected_because_none_ships(value: str) -> None:
    live = {e.id: e for e in ex.build_executors({ex.LIVE_ENV: value})}["live"]
    assert live.status().state == "not-connected"
    assert ex.select_executor(ex.build_executors({ex.LIVE_ENV: value})).id == "dry-run"
    ctx = context()
    with pytest.raises(ex.ExecutorUnavailable):
        live.execute(ctx)
    with pytest.raises(ex.ExecutorUnavailable):
        live.rollback(ctx)


@pytest.mark.parametrize("value", ["maybe", "2", "enabled"])
def test_a_garbled_live_flag_fails_start_up_not_open(value: str) -> None:
    with pytest.raises(ValueError):
        ex.build_executors({ex.LIVE_ENV: value})


def context() -> ex.ExecutionContext:
    definition = CATALOG["endpoint.isolate"]
    return ex.ExecutionContext(
        action_id="action-00000001-0000-4000-8000-000000000000",
        action_type="endpoint.isolate",
        target_id="endpoint:laptop-1",
        params={"duration_minutes": 60},
        source=None,
        definition=definition,
    )


def test_an_execution_context_carries_no_free_text() -> None:
    names = set(ex.ExecutionContext.__dataclass_fields__)
    assert not names & {"reason", "requester", "note", "comment", "command"}


@pytest.mark.usefixtures("no_network")
def test_the_dry_run_executor_records_and_changes_nothing() -> None:
    executor = ex.DryRunExecutor()
    ctx = context()
    assert executor.pre_checks(ctx) == []
    assert executor.execute(ctx).failure is None
    assert executor.verify(ctx) == ActionVerification(state="not-applicable", detail="dry-run")
    assert executor.rollback(ctx) == ActionRollback(state="not-needed", detail="dry-run")


# --- the engine ----------------------------------------------------------------------------------------------


@dataclass
class FakeLive:
    """A pretend live executor: exercises the framework paths a future real executor will take."""

    id: str = "fake-live"
    mode: str = "live"
    checks: list[ActionCheck] = field(default_factory=list)
    execute_failure: str | None = None
    explode: bool = False
    sleep: float = 0.0
    verify_sleep: float = 0.0
    on_pre: Any = None
    on_execute: Any = None
    verify_state: str = "passed"
    rollback_state: str = "completed"
    calls: list[str] = field(default_factory=list)

    def status(self) -> Any:
        return ex.ExecutorStatus(id=self.id, mode="live", state="ok")

    def pre_checks(self, ctx: ex.ExecutionContext) -> list[ActionCheck]:
        self.calls.append("pre")
        if self.on_pre is not None:
            self.on_pre()
        return self.checks

    def execute(self, ctx: ex.ExecutionContext) -> ex.ExecuteResult:
        self.calls.append("execute")
        if self.on_execute is not None:
            self.on_execute()
        time.sleep(self.sleep)
        if self.explode:
            raise RuntimeError("connection to 10.0.0.1 failed with password hunter2")
        return ex.ExecuteResult(failure=self.execute_failure)

    def verify(self, ctx: ex.ExecutionContext) -> ActionVerification:
        self.calls.append("verify")
        time.sleep(self.verify_sleep)
        return ActionVerification(state=self.verify_state, detail="checked")  # type: ignore[arg-type]

    def rollback(self, ctx: ex.ExecutionContext) -> ActionRollback:
        self.calls.append("rollback")
        return ActionRollback(state=self.rollback_state, detail="done")  # type: ignore[arg-type]


def approved_request(store: Any, **overrides: Any) -> ActionRequest:
    request = store.create(
        new_action(**overrides), idempotency_key=f"k-{time.monotonic_ns():016d}", now=NOW
    ).request
    return store.approve(
        request.id,
        approver=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        now=NOW,
    )


def run(
    engine: ExecutionEngine,
    request: ActionRequest,
    key: str = "run-key-0000000001",
    actor: ActionActor = BOB,
) -> ActionRequest:
    return engine.execute(
        request.id,
        actor=actor,
        expected_digest=request.digest,
        expected_version=request.version,
        idempotency_key=key,
    ).request


def engine_with(store: Any, executor: Any, **kw: Any) -> ExecutionEngine:
    return ExecutionEngine(
        store=store,
        executors=[ex.DryRunExecutor(), executor] if executor else [ex.DryRunExecutor()],
        clock=lambda: NOW,
        **kw,
    )


@pytest.mark.usefixtures("no_network")
def test_a_dry_run_succeeds_records_what_would_happen_and_changes_nothing() -> None:
    store = new_store()
    request = approved_request(store)
    done = run(engine_with(store, None), request)
    assert done.state == "succeeded"
    assert done.execution is not None
    assert done.execution.mode == "dry-run" and done.execution.effect == "none"
    assert done.execution.executor == "dry-run"
    assert done.execution.verification.state == "not-applicable"
    assert any("Would" in step for step in done.execution.planned_steps)
    assert done.execution.finished_at is not None
    assert store.verify_chain(request.id)
    assert store.history(request.id)[-1].type == "executed"


def test_the_plan_never_contains_the_reason_or_other_request_text() -> None:
    store = new_store()
    secret_reason = "contains-marker-text-ZZZ"
    request = approved_request(store, reason=secret_reason)
    done = run(engine_with(store, None), request)
    assert done.execution is not None
    assert secret_reason not in " ".join(done.execution.planned_steps)


def test_a_retry_with_the_same_key_returns_the_recorded_result_without_running_again() -> None:
    store = new_store()
    live = FakeLive()
    request = approved_request(store)
    engine = engine_with(store, live)
    first = run(engine, request)
    again = engine.execute(
        request.id,
        actor=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        idempotency_key="run-key-0000000001",
    )
    assert again.replayed is True
    assert again.request.state == first.state
    assert live.calls.count("execute") == 1


def test_a_failed_pre_check_stops_before_the_executor_acts() -> None:
    store = new_store()
    live = FakeLive(
        checks=[ActionCheck(name="target-reachable", state="fail", detail="unreachable")]
    )
    done = run(engine_with(store, live), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "pre-check-failed"
    assert "execute" not in live.calls
    assert [c.state for c in done.pre_checks] == ["fail"]
    assert store.history(done.id)[-1].type == "pre-check-failed"


def test_an_unknown_pre_check_blocks_a_live_run_but_not_a_dry_run() -> None:
    unknown = ActionCheck(name="target-reachable", state="unknown", detail="not-verified")
    store = new_store()
    live = FakeLive(checks=[unknown])
    failed = run(engine_with(store, live), approved_request(store))
    assert failed.state == "failed" and "execute" not in live.calls
    assert failed.execution is not None and failed.execution.failure == "pre-check-unknown"
    other = new_store()
    engine = ExecutionEngine(
        store=other,
        executors=[ex.DryRunExecutor()],
        clock=lambda: NOW,
        checks=[lambda _request: unknown],
    )
    dry = run(engine, approved_request(other))
    assert dry.state == "succeeded"
    assert [c.state for c in dry.pre_checks] == ["unknown"]  # recorded, not hidden


def test_a_live_success_is_applied_and_verified() -> None:
    store = new_store()
    live = FakeLive()
    done = run(engine_with(store, live), approved_request(store))
    assert done.state == "succeeded"
    assert done.execution is not None
    assert done.execution.mode == "live" and done.execution.effect == "applied"
    assert done.execution.verification.state == "passed"
    assert live.calls == ["pre", "execute", "verify"]


def test_a_failed_verification_rolls_back() -> None:
    store = new_store()
    live = FakeLive(verify_state="failed")
    done = run(engine_with(store, live), approved_request(store))
    assert done.state == "rolled-back"
    assert done.execution is not None and done.execution.rollback == ActionRollback(
        state="completed", detail="done"
    )
    assert live.calls[-2:] == ["verify", "rollback"]
    assert [e.type for e in store.history(done.id)][-3:] == [
        "executed",
        "verification-failed",
        "rolled-back",
    ]


def test_a_failed_verification_and_a_failed_rollback_is_failed_and_says_so() -> None:
    store = new_store()
    live = FakeLive(verify_state="failed", rollback_state="failed")
    done = run(engine_with(store, live), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "rollback-failed"
    assert store.history(done.id)[-1].type == "rollback-failed"


def test_an_unverifiable_result_is_failed_not_assumed_good() -> None:
    store = new_store()
    done = run(engine_with(store, FakeLive(verify_state="unknown")), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "verification-unknown"


def test_an_executor_that_raises_is_failed_and_its_message_is_never_kept() -> None:
    store = new_store()
    done = run(engine_with(store, FakeLive(explode=True)), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-error"
    assert done.execution.effect == "unknown"  # a live run that blew up may have changed something
    dumped = done.model_dump_json() + "".join(e.model_dump_json() for e in store.history(done.id))
    assert "hunter2" not in dumped and "10.0.0.1" not in dumped


def test_an_executor_that_reports_a_failure_is_failed_with_its_code() -> None:
    store = new_store()
    done = run(
        engine_with(store, FakeLive(execute_failure="device-refused")), approved_request(store)
    )
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "device-refused"


def test_an_executor_that_overruns_its_timeout_is_failed() -> None:
    store = new_store()
    live = FakeLive(sleep=0.5)
    engine = engine_with(store, live, timeout_override=0.05)
    started = time.monotonic()
    done = run(engine, approved_request(store))
    assert time.monotonic() - started < 0.45
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-timeout"


def test_a_stale_digest_or_version_never_reaches_the_executor() -> None:
    store = new_store()
    live = FakeLive()
    request = approved_request(store)
    engine = engine_with(store, live)
    with pytest.raises(ActionError):
        engine.execute(
            request.id,
            actor=BOB,
            expected_digest="sha256:" + "0" * 64,
            expected_version=request.version,
            idempotency_key="run-key-0000000001",
        )
    assert live.calls == []


def test_the_engine_revalidates_what_it_executes() -> None:
    """A stored request that no longer satisfies the catalogue is failed, not executed."""
    store = new_store()
    live = FakeLive()
    request = approved_request(store)
    record = store._records[request.id]  # simulate corruption of the stored parameters
    record.request = record.request.model_copy(update={"params": {"duration_minutes": 10**6}})
    done = run(engine_with(store, live), record.request)
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "parameter-range"
    assert live.calls == []


# --- the finding pre-check -------------------------------------------------------------------------------------


def request_for_finding(version: int = 3) -> ActionRequest:
    store = new_store()
    request = approved_request(
        store,
        target_id=FINDING,
        source=ActionSource(kind="unknown-device-finding", id=FINDING, evidence_version=version),
    )
    return request


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (make_finding(), "pass"),
        (make_finding(evidence_version=4), "fail"),
        (make_finding(state="resolved"), "fail"),
        (None, "fail"),
    ],
)
def test_the_finding_pre_check_catches_evidence_that_moved_or_a_closed_finding(
    finding: Any, expected: str
) -> None:
    check = finding_pre_check(lambda: FindingStore(finding))
    assert check(request_for_finding()).state == expected


def test_the_finding_pre_check_is_unknown_when_findings_are_not_connected() -> None:
    check = finding_pre_check(lambda: None)
    assert check(request_for_finding()).state == "unknown"


def test_a_request_without_a_finding_source_has_no_finding_check() -> None:
    store = new_store()
    request = approved_request(store)
    assert finding_pre_check(lambda: None)(request) is None


# --- review fixes -----------------------------------------------------------------------------------------------------


def _imported_names(module: Any) -> set[str]:
    import ast

    tree = ast.parse(inspect.getsource(module))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"__import__", "exec", "eval", "compile"}
        ):
            names.add(node.func.id)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "importlib"
        ):
            names.add("importlib")
    return names


def test_the_executor_and_engine_modules_import_nothing_that_can_reach_a_device_a_network_or_a_process() -> (
    None
):
    from netsight_api.actions import engine as engine_module

    forbidden = {
        "socket",
        "ssl",
        "httpx",
        "requests",
        "urllib",
        "http",
        "subprocess",
        "asyncssh",
        "paramiko",
        "netmiko",
        "telnetlib",
        "pysnmp",
        "os",
        "ftplib",
        "smtplib",
        "aiohttp",
        "asyncio",
        "importlib",
        "multiprocessing",
        "__import__",
        "exec",
        "eval",
        "compile",
        "ctypes",
        "shutil",
        "pty",
    }
    for module in (ex, engine_module):
        assert not forbidden & _imported_names(module), module.__name__


def test_the_kill_switch_is_checked_again_just_before_the_executor_acts() -> None:
    from netsight_api.actions.killswitch import KillSwitch

    kill = KillSwitch()
    store = new_store(kill_switch=kill)
    live = FakeLive(on_pre=lambda: kill.engage(NOW))
    engine = ExecutionEngine(
        store=store, executors=[ex.DryRunExecutor(), live], clock=lambda: NOW, kill_switch=kill
    )
    done = run(engine, approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "kill-switch"
    assert "execute" not in live.calls


def test_the_whole_run_shares_one_time_budget_so_it_always_finishes_before_the_sweep_would_fail_it() -> (
    None
):
    store = new_store()
    live = FakeLive(sleep=0.15, verify_sleep=0.15)
    done = run(engine_with(store, live, timeout_override=0.2), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-timeout"
    assert store.verify_chain(done.id)


def test_a_run_the_sweep_already_failed_is_reported_not_lost_as_a_conflict() -> None:
    store = new_store()
    live = FakeLive(on_execute=lambda: store.expire_due(NOW + timedelta(minutes=5)))
    done = run(engine_with(store, live), approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-timeout"


class FakeDryRunVerifyFails:
    """A dry-run-mode executor whose verification fails: the rollback path must not break the record."""

    id = "dry-run"
    mode = "dry-run"

    def status(self) -> Any:
        return ex.ExecutorStatus(id="dry-run", mode="dry-run", state="ok")

    def pre_checks(self, ctx: ex.ExecutionContext) -> list[ActionCheck]:
        return []

    def execute(self, ctx: ex.ExecutionContext) -> ex.ExecuteResult:
        return ex.ExecuteResult()

    def verify(self, ctx: ex.ExecutionContext) -> ActionVerification:
        return ActionVerification(state="failed", detail="mismatch")

    def rollback(self, ctx: ex.ExecutionContext) -> ActionRollback:
        return ActionRollback(state="completed", detail="done")


def test_a_dry_run_mode_executor_that_fails_verification_still_rolls_back_cleanly() -> None:
    store = new_store()
    engine = ExecutionEngine(store=store, executors=[FakeDryRunVerifyFails()], clock=lambda: NOW)
    done = run(engine, approved_request(store))
    assert done.state == "rolled-back"
    assert done.execution is not None and done.execution.effect == "none"


def test_an_unexpected_error_after_the_run_started_fails_the_request_instead_of_leaving_it_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = new_store()
    engine = engine_with(store, FakeLive())

    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("storage exploded at 10.0.0.9")

    monkeypatch.setattr(engine, "_act", explode)
    done = run(engine, approved_request(store))
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-error"
    assert "10.0.0.9" not in done.model_dump_json()


def test_an_engine_check_that_hangs_is_cut_off_by_the_timeout() -> None:
    store = new_store()
    engine = ExecutionEngine(
        store=store,
        executors=[ex.DryRunExecutor()],
        clock=lambda: NOW,
        checks=[lambda _request: time.sleep(0.5)],
        timeout_override=0.05,
    )
    started = time.monotonic()
    done = run(engine, approved_request(store))
    assert time.monotonic() - started < 0.45
    assert done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-timeout"
