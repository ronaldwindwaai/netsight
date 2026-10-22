"""Which store the action engine gets from the environment, and what the API says about it (Step 12, D-53).

``DATABASE_URL`` selects the durable PostgreSQL store, its absence the process-local one, a value that is not
a PostgreSQL URL fails start-up when the engine is enabled; nothing here needs a database except the last
test, which restarts a runtime over real tables.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from actions_api_support import (
    BASE,
    ENV_ON,
    Clock,
    FindingStub,
    Person,
    clean_wiring,
    install_clock,
    install_findings,
)
from actions_pg_support import settings_fixture  # noqa: F401
from pg_support import requires_pg

from netsight_api import actions_route_support as support
from netsight_api.actions import wiring
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.postgres_store import PostgresActionStore
from netsight_api.actions.store import InMemoryActionStore
from netsight_api.actions.wiring import build_runtime, build_store, validate_environment
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.storage.connection import PostgresSettings

DEAD = "postgresql://nobody@127.0.0.1:1/none"
ENV_PG = {**ENV_ON, "DATABASE_URL": DEAD}


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_wiring(monkeypatch)


def test_without_a_database_the_store_is_memory_and_says_it_is_volatile() -> None:
    store = build_store(ENV_ON, KillSwitch())
    assert isinstance(store, InMemoryActionStore)
    assert (store.kind, store.durable) == ("memory", False)


@pytest.mark.parametrize("url", [DEAD, DEAD.replace("postgresql://", "postgresql+psycopg://")])
def test_with_a_database_url_the_store_is_postgres_and_nothing_is_connected_yet(url: str) -> None:
    runtime = build_runtime({**ENV_ON, "DATABASE_URL": url})
    assert runtime is not None
    assert isinstance(runtime.store, PostgresActionStore)
    assert (runtime.store.kind, runtime.store.durable) == ("postgres", True)


def test_a_blank_database_url_means_memory() -> None:
    runtime = build_runtime({**ENV_ON, "DATABASE_URL": "   "})
    assert runtime is not None and runtime.store.kind == "memory"


@pytest.mark.parametrize("url", ["mysql://x/y", "not a url", "sqlite:///tmp.db"])
def test_a_database_url_that_is_not_postgres_fails_start_up_instead_of_meaning_memory(
    url: str,
) -> None:
    env = {**ENV_ON, "DATABASE_URL": url}
    for refused in (lambda: build_runtime(env), lambda: validate_environment(env)):
        with pytest.raises(ValueError, match="DATABASE_URL") as raised:
            refused()
        assert url not in str(raised.value)  # the value may be a secret: never echoed


def test_a_disabled_engine_does_not_care_about_the_database_url() -> None:
    env = {"DATABASE_URL": "mysql://x/y"}
    assert build_runtime(env) is None
    validate_environment(env)


def test_the_self_execute_policy_reaches_the_postgres_store() -> None:
    store = build_store({**ENV_PG, "NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE": "true"}, KillSwitch())
    assert store.allow_self_execute is True


def test_status_reports_the_postgres_store_as_durable() -> None:
    clock, findings = install_clock(), install_findings()
    built = build_runtime(ENV_PG, clock=clock, findings=lambda: findings)
    app.dependency_overrides[support.get_runtime] = lambda: built
    response = Person("auditor").get(f"{BASE}/status")
    assert response.status_code == 200
    validate("action_status", response.json())
    assert response.json()["store"] == {"kind": "postgres", "durable": True}


def test_status_without_a_database_still_says_memory() -> None:
    clock, findings = install_clock(), install_findings()
    built = build_runtime(ENV_ON, clock=clock, findings=lambda: findings)
    app.dependency_overrides[support.get_runtime] = lambda: built
    assert Person("auditor").get(f"{BASE}/status").json()["store"] == {
        "kind": "memory",
        "durable": False,
    }


@requires_pg
def test_a_request_survives_a_restart_of_the_service(
    settings: PostgresSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "database_settings", lambda _env: settings)
    clock: Clock = install_clock()
    findings: FindingStub = install_findings()

    def start() -> None:
        built = build_runtime(ENV_PG, clock=clock, findings=lambda: findings)
        app.dependency_overrides[support.get_runtime] = lambda: built

    start()
    engineer, admin = Person("network_engineer"), Person("administrator")
    made = engineer.create()
    assert made.status_code == 201, made.text
    approved = admin.approve(made.json())
    assert approved.status_code == 200, approved.text
    start()  # a restart: a new process, a new store object, the same database
    detail: Any = admin.show(made.json()["id"])
    assert detail.status_code == 200, detail.text
    body = detail.json()
    validate("action_detail", body)
    assert body["request"]["state"] == "approved" and body["chain_intact"] is True
    done = admin.execute(body["request"])
    assert done.status_code == 200 and done.json()["state"] == "succeeded", done.text
    start()
    final = admin.show(made.json()["id"]).json()
    assert final["request"]["state"] == "succeeded" and final["chain_intact"] is True
    assert final["history"][-1]["type"] == "executed"
