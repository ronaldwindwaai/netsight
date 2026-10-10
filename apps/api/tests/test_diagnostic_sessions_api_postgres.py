"""The session routes against live PostgreSQL as the least-privilege application role.

Skipped without ``NETSIGHT_TEST_PG_DSN``. Proves the end-to-end path (run -> INSERT -> read back)
works with SELECT/INSERT grants only, that the DSN-driven dependency builds a working store, and
that a stored row that no longer satisfies the contract reads as an explicit ``unknown``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import ExitStack

import pytest
from alerting_support import Caller
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg
from test_diagnostic_sessions_api import (
    BASE,
    FakeContext,
    LocatedProbe,
    body,
    topology,
    use_context,
    use_probes,
)

from netsight_api import diagnostic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.diagnostic_context import get_optional_diagnostic_session_store
from netsight_api.main import app
from netsight_api.storage import StorageError, migrate
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository


@pytest.fixture
def stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[PostgresSettings, PostgresSettings]]:
    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        role, role_dsn = stack.enter_context(app_role())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.apply_grants(conn, role)
        runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        app.dependency_overrides.clear()
        session_policy.cache_clear()
        monkeypatch.setattr(diagnostic_routes, "_run_limiter", RateLimiter())
        store = PostgresDiagnosticSessionRepository(runtime)
        app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: store
        yield owner, runtime
        app.dependency_overrides.clear()
        session_policy.cache_clear()


@requires_pg
def test_a_run_is_stored_with_insert_only_rights_and_read_back(
    stores: tuple[PostgresSettings, PostgresSettings],
) -> None:
    use_probes(
        LocatedProbe("cloud-external", {"tcp": "fail"}),
        LocatedProbe("server-vlan", {"tcp": "pass"}),
    )
    use_context(FakeContext(topo=topology()))
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    assert posted["stored"] is True

    fetched = caller.get(f"{BASE}/{posted['run']['id']}").json()
    validate("diagnostic_session_response", fetched)
    assert fetched["session"]["run"] == posted["run"]
    assert fetched["session"]["probable_cause"]["pattern"] == "external-only-failure"

    page = caller.get(BASE).json()
    validate("diagnostic_session_list_response", page)
    assert [row["id"] for row in page["sessions"]] == [posted["run"]["id"]]


@requires_pg
def test_a_corrupt_stored_row_reads_as_unknown_not_as_a_session(
    stores: tuple[PostgresSettings, PostgresSettings],
) -> None:
    owner, _runtime = stores
    key = uuid.UUID(int=77)
    with owner.connect() as conn:
        conn.execute(
            "INSERT INTO diagnostic_sessions (id, target, started_at, completed_at, "
            "probable_fault_domain, confidence, created_by, created_at, document) "
            "VALUES (%s, 't', now(), now(), NULL, 'unknown', 'u', now(), '{}'::jsonb)",
            (key,),
        )
    caller = Caller("administrator")
    fetched = caller.get(f"{BASE}/diagnostic-{key}")
    assert fetched.status_code == 200
    assert fetched.json() == {"state": "unknown", "session": None}


def test_the_environment_driven_store_follows_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_optional_diagnostic_session_store() is None
    monkeypatch.setenv("DATABASE_URL", "postgresql://app@localhost:1/none")
    assert isinstance(get_optional_diagnostic_session_store(), PostgresDiagnosticSessionRepository)
    # A configured-but-unusable DSN is a store whose calls fail, never "not connected".
    monkeypatch.setenv("DATABASE_URL", "mysql://nope")
    broken = get_optional_diagnostic_session_store()
    assert broken is not None
    with pytest.raises(StorageError):
        broken.list_sessions()
