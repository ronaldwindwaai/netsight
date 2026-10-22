"""Fixtures and helpers for the live PostgreSQL action-store tests (shared by the test modules)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack
from typing import Any

import pytest
from actions_support import BOB, NOW, new_action
from pg_support import PG_DSN, app_role, isolated_schema

from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.postgres_store import PostgresActionStore
from netsight_api.schemas_actions import ActionRequest
from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings

KEY = "pg-store-key-00000001"
EXEC = "pg-exec-key-000000001"
DEAD_DSN = "postgresql://nobody@127.0.0.1:1/none"


@pytest.fixture(name="settings", params=["owner", "app-role"])
def settings_fixture(request: pytest.FixtureRequest) -> Iterator[PostgresSettings]:
    pytest.importorskip("psycopg")
    if not PG_DSN:
        pytest.skip("set NETSIGHT_TEST_PG_DSN to run live PostgreSQL tests")
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        runtime = owner
        role = ""
        if request.param == "app-role":
            role, role_dsn = stack.enter_context(app_role())
            runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            if role:
                migrate.apply_grants(conn, role)
        yield runtime


@pytest.fixture(name="owner_conn")
def owner_conn_fixture() -> Iterator[Any]:
    """An owner connection to a migrated throwaway schema, for poking at the tables directly."""
    assert PG_DSN
    with isolated_schema() as schema:
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
        with owner.connect() as conn:
            conn.settings = owner  # type: ignore[attr-defined]
            yield conn


def store_for(settings: PostgresSettings, **kw: Any) -> PostgresActionStore:
    return PostgresActionStore(settings, kill_switch=kw.pop("kill_switch", KillSwitch()), **kw)


def propose(store: PostgresActionStore, **kw: Any) -> ActionRequest:
    return store.create(new_action(**kw), idempotency_key=KEY, now=NOW).request


def approve(store: PostgresActionStore, request: ActionRequest, who: Any = BOB) -> ActionRequest:
    return store.approve(
        request.id,
        approver=who,
        expected_digest=request.digest,
        expected_version=request.version,
        now=NOW,
    )


def seed(settings: PostgresSettings) -> ActionRequest:
    """One proposed request, written through the store (so its history is genuine)."""
    return store_for(settings).create(new_action(), idempotency_key=KEY, now=NOW).request
