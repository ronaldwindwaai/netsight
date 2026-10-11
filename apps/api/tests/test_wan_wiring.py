"""Assembly and scheduling of the WAN collector (Step 5b): off by default, env-gated, one leader.

Mirrors the evaluation service's rules: nothing is probed or written unless
``NETSIGHT_WAN_SAMPLING_ENABLED`` is set explicitly; enabled but unbuildable fails start-up instead
of silently running something weaker; exactly one process samples per database (its own advisory
lock, distinct from the evaluator's so the two jobs can live in different processes).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.evaluation.leader import EVALUATOR_LOCK_KEY, InMemoryLeaderLock, LeaseBoard
from netsight_api.main import app
from netsight_api.storage.postgres_wan import CollectorRoleError
from netsight_api.wan.collector import WanCollector
from netsight_api.wan.wiring import (
    WAN_COLLECTOR_LOCK_KEY,
    WanCollectorService,
    build_wan_collector,
    start_wan_sampling,
)

LINKS = json.dumps(
    [
        {
            "id": "fibre-1",
            "name": "Primary fibre",
            "role": "primary",
            "probe_targets": ["probe-a.example"],
            "probe_location": "branch",
        }
    ]
)
DSN = "postgresql://netsight_app:pw@127.0.0.1:5432/netsight"
COLLECTOR_DSN = "postgresql://netsight_wan:wanpw@127.0.0.1:5432/netsight"
COLLECTOR_VARIABLE = "NETSIGHT_WAN_COLLECTOR_DATABASE_URL"


def enabled_env(**overrides: str) -> dict[str, str]:
    env = {
        "NETSIGHT_WAN_SAMPLING_ENABLED": "true",
        "DATABASE_URL": DSN,
        COLLECTOR_VARIABLE: COLLECTOR_DSN,
        "NETSIGHT_WAN_LINKS": LINKS,
    }
    env.update(overrides)
    return env


def build(
    env: dict[str, str], role_guard: Callable[[Any], None] | None = None
) -> WanCollectorService | None:
    return build_wan_collector(
        env,
        local_factory=lambda: None,
        exporter_factory=list,
        role_guard=role_guard or (lambda _settings: None),
    )


# --- off by default, strict when on --------------------------------------------------------------------


def test_nothing_is_built_unless_sampling_is_explicitly_enabled() -> None:
    assert build({}) is None
    assert build({"NETSIGHT_WAN_SAMPLING_ENABLED": "false", "DATABASE_URL": DSN}) is None
    assert build({"NETSIGHT_WAN_LINKS": LINKS, "DATABASE_URL": DSN}) is None


def test_a_garbled_flag_fails_start_up_instead_of_guessing() -> None:
    with pytest.raises(ValueError, match="NETSIGHT_WAN_SAMPLING_ENABLED"):
        build({"NETSIGHT_WAN_SAMPLING_ENABLED": "maybe"})


def test_enabled_without_the_collector_database_fails_start_up() -> None:
    with pytest.raises(ValueError, match=COLLECTOR_VARIABLE):
        build(enabled_env(**{COLLECTOR_VARIABLE: ""}))
    with pytest.raises(ValueError, match=COLLECTOR_VARIABLE):
        build(enabled_env(**{COLLECTOR_VARIABLE: "mysql://u:p@h/db"}))


def test_the_api_database_url_alone_is_not_enough_to_start_the_collector() -> None:
    env = enabled_env()
    del env[COLLECTOR_VARIABLE]
    with pytest.raises(ValueError, match=COLLECTOR_VARIABLE):
        build(env)


def test_the_collector_does_not_need_the_api_database_url() -> None:
    assert build(enabled_env(DATABASE_URL="")) is not None


def test_the_collector_may_not_share_the_api_roles_credentials() -> None:
    with pytest.raises(ValueError, match="differ"):
        build(enabled_env(**{COLLECTOR_VARIABLE: DSN}))
    with pytest.raises(ValueError, match="differ"):
        build(
            enabled_env(
                DATABASE_URL=DSN.replace("postgresql://", "postgresql+psycopg://"),
                **{COLLECTOR_VARIABLE: DSN},
            )
        )


def test_the_database_role_guard_runs_against_the_collector_dsn_before_it_may_start() -> None:
    seen: list[str] = []

    def guard(settings: Any) -> None:
        seen.append(settings.dsn)

    assert build(enabled_env(), guard) is not None
    assert seen == [COLLECTOR_DSN]  # the collector's own credential, never the API's


def test_a_role_the_guard_rejects_fails_start_up_without_leaking_the_dsn() -> None:
    def guard(_settings: Any) -> None:
        raise CollectorRoleError("the WAN collector database role must not be a superuser")

    with pytest.raises(ValueError, match="superuser") as raised:
        build(enabled_env(), guard)
    assert "wanpw" not in str(raised.value) and "postgresql" not in str(raised.value)


def test_the_guard_is_not_run_when_sampling_is_off() -> None:
    def guard(_settings: Any) -> None:
        raise AssertionError("must not connect when sampling is off")

    assert (
        build({"NETSIGHT_WAN_SAMPLING_ENABLED": "false", COLLECTOR_VARIABLE: COLLECTOR_DSN}, guard)
        is None
    )


@pytest.mark.parametrize("links", ["", "[]", "not json", '[{"id": "Bad Id"}]'])
def test_enabled_without_a_usable_link_declaration_fails_start_up(links: str) -> None:
    with pytest.raises(ValueError, match="NETSIGHT_WAN_LINKS"):
        build(enabled_env(NETSIGHT_WAN_LINKS=links))


@pytest.mark.parametrize("seconds", ["29", "301", "x"])
def test_an_invalid_interval_fails_start_up(seconds: str) -> None:
    with pytest.raises(ValueError, match="NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS"):
        build(enabled_env(NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS=seconds))


def test_a_valid_configuration_builds_a_single_leader_collector() -> None:
    service = build(enabled_env(NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS="45"))
    assert service is not None and isinstance(service.runner, WanCollector)
    assert service.interval_seconds == 45 and service.lock is not None
    assert COLLECTOR_DSN not in repr(service) and "wanpw" not in repr(service)


def test_its_lock_key_is_its_own_and_not_the_evaluators() -> None:
    assert WAN_COLLECTOR_LOCK_KEY != EVALUATOR_LOCK_KEY
    assert 0 < WAN_COLLECTOR_LOCK_KEY < 2**63


def test_the_application_refuses_to_start_when_enabled_but_unbuildable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in enabled_env(**{COLLECTOR_VARIABLE: ""}).items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("NETSIGHT_EVALUATION_ENABLED", raising=False)
    with pytest.raises(ValueError, match=COLLECTOR_VARIABLE), TestClient(app):
        pass


def test_the_application_starts_without_the_collector_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NETSIGHT_WAN_SAMPLING_ENABLED", raising=False)
    monkeypatch.delenv("NETSIGHT_EVALUATION_ENABLED", raising=False)
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert app.state.wan_sampling_task is None


# --- scheduling and leadership --------------------------------------------------------------------------


class CountingRunner:
    def __init__(self) -> None:
        self.cycles = 0
        self.resets = 0

    async def run_cycle(self) -> None:
        self.cycles += 1

    def reset_state(self) -> None:
        self.resets += 1


def test_only_the_leader_samples_and_the_service_stops_on_request() -> None:
    async def scenario() -> tuple[int, int]:
        board = LeaseBoard()
        first, second = CountingRunner(), CountingRunner()
        services = [
            WanCollectorService(first, 30, InMemoryLeaderLock(board)),  # type: ignore[arg-type]
            WanCollectorService(second, 30, InMemoryLeaderLock(board)),  # type: ignore[arg-type]
        ]
        runtimes = [start_wan_sampling(service) for service in services]
        await asyncio.sleep(0.2)
        for runtime in runtimes:
            await runtime.shutdown()
        return first.cycles, second.cycles

    cycles = asyncio.run(scenario())
    assert sorted(cycles) == [0, 1]  # one writer; the other idled


def test_a_disabled_service_has_no_task_and_shutdown_is_a_no_op() -> None:
    async def scenario() -> Any:
        runtime = start_wan_sampling(None)
        await runtime.shutdown()
        return runtime.task

    assert asyncio.run(scenario()) is None


# --- the collector adds no capability ---------------------------------------------------------------------


WAN_DIR = Path(__file__).resolve().parents[1] / "src" / "netsight_api" / "wan"


def test_the_collector_never_issues_sql_or_a_delete() -> None:
    for module in ("collector.py", "wiring.py"):
        text = (WAN_DIR / module).read_text("utf-8").upper()
        for word in ("DELETE", "UPDATE ", "TRUNCATE", "DROP "):
            assert word not in text, (module, word)


def test_the_collector_sends_nothing_and_opens_no_connection_of_its_own() -> None:
    text = (WAN_DIR / "collector.py").read_text("utf-8")
    for needle in ("httpx", "socket", "smtplib", "notifications", "open_connection"):
        assert needle not in text
