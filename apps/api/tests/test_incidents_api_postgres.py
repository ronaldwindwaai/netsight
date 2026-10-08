"""Incident routes against live PostgreSQL through the real ``DATABASE_URL`` wiring.

Opt-in: runs only when ``NETSIGHT_TEST_PG_DSN`` is set (see ``pg_support``). The API
connects as a throwaway least-privilege application role (never the owner), exactly as
production does, in a throwaway schema.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import psycopg
import pytest
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg
from psycopg import sql
from test_incidents_api import API, Caller, resolve_body

from netsight_api import incident_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.storage import lifecycle
from netsight_api.storage.migrate import apply_grants, apply_up
from netsight_api.storage.postgres import PostgresIncidentRepository, PostgresSettings

pytestmark = requires_pg


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch) -> Iterator[PostgresIncidentRepository]:
    """Migrated schema + app role; DATABASE_URL points at the app role. Yields an owner-side
    repository used only to seed incidents (the API has no create endpoint)."""
    assert PG_DSN
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(incident_routes, "_write_limiter", RateLimiter())
    monkeypatch.delenv("NETSIGHT_ENV", raising=False)
    monkeypatch.delenv("NETSIGHT_ENABLE_DEV_IDENTITY", raising=False)
    with isolated_schema() as schema, app_role() as (role, role_dsn):
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            apply_up(conn)
            apply_grants(conn, role)
        with psycopg.connect(PG_DSN, autocommit=True) as admin:
            admin.execute(
                sql.SQL("ALTER ROLE {} SET search_path TO {}").format(
                    sql.Identifier(role), sql.Identifier(schema)
                )
            )
        monkeypatch.setenv("DATABASE_URL", role_dsn)
        yield PostgresIncidentRepository(owner)
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def seed(repo: PostgresIncidentRepository, **overrides: Any) -> str:
    args: dict[str, Any] = {"title": "Perimeter outage", "severity": "high", "actor_id": "seed:op"}
    args.update(overrides)
    return repo.create_incident(**args).id


def test_full_lifecycle_through_the_api_on_postgres(live: PostgresIncidentRepository) -> None:
    incident_id = seed(live, title="<img src=x onerror=alert(1)>")
    lead = Caller("network_engineer", "lead")

    listed = lead.get(API).json()
    assert listed["state"] == "ok"
    assert [i["id"] for i in listed["incidents"]] == [incident_id]
    assert listed["incidents"][0]["title"] == "<img src=x onerror=alert(1)>"

    for step in ("acknowledged", "investigating", "mitigated"):
        assert lead.post(f"{API}/{incident_id}/transition", {"to_state": step}).status_code == 200
    assert (
        lead.post(f"{API}/{incident_id}/assign", {"assignee_id": "microsoft:sub-9"}).status_code
        == 200
    )
    assert lead.post(f"{API}/{incident_id}/evidence", {"evidence_id": "ev-1"}).status_code == 200
    assert (
        lead.post(f"{API}/{incident_id}/comment", {"message": "Failover done"}).status_code == 201
    )
    resolved = lead.post(f"{API}/{incident_id}/resolve", resolve_body())
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["resolution"]["resolved_by"] == lead.identity_id
    assert lead.post(f"{API}/{incident_id}/reopen", {"reason": "Regression"}).status_code == 200

    timeline = lead.get(f"{API}/{incident_id}/timeline").json()["events"]
    assert [e["seq"] for e in timeline] == list(range(1, len(timeline) + 1))
    assert all(e["actor_id"] == lead.identity_id for e in timeline)
    assert lead.get(f"{API}/{incident_id}").json()["incident"]["state"] == "open"


def test_concurrent_acknowledgements_have_exactly_one_winner(
    live: PostgresIncidentRepository,
) -> None:
    incident_id = seed(live)
    callers = [Caller("administrator", f"racer-{n}") for n in range(6)]

    def acknowledge(caller: Caller) -> int:
        return int(caller.post(f"{API}/{incident_id}/acknowledge").status_code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = sorted(pool.map(acknowledge, callers))
    assert statuses == [200] + [409] * 5
    assert [e.kind for e in live.list_timeline(incident_id)] == ["state-changed"]


def test_technician_scope_and_filters_work_against_postgres(
    live: PostgresIncidentRepository,
) -> None:
    tech = Caller("technician", "tech-1")
    mine = seed(live, severity="low")
    theirs = seed(live, severity="high")
    live.set_assignee(mine, assignee_id=tech.identity_id, actor_id="seed:op")
    live.set_assignee(theirs, assignee_id="microsoft:other", actor_id="seed:op")
    assert tech.post(f"{API}/{theirs}/acknowledge").status_code == 403
    assert tech.post(f"{API}/{mine}/acknowledge").status_code == 200
    by_assignee = tech.get(API, assignee_id=tech.identity_id).json()["incidents"]
    assert [i["id"] for i in by_assignee] == [mine]
    by_severity = tech.get(API, severity="high", state="open").json()["incidents"]
    assert [i["id"] for i in by_severity] == [theirs]


def test_unknown_id_and_pagination_on_postgres(live: PostgresIncidentRepository) -> None:
    ids = [seed(live, title=f"inc {n}") for n in range(3)]
    caller = Caller("auditor")
    page = caller.get(API, limit=2).json()
    assert [i["id"] for i in page["incidents"]] == ids[::-1][:2]
    assert page["next_offset"] == 2
    missing = "incident-00000000-0000-4000-8000-000000000000"
    assert caller.get(f"{API}/{missing}").status_code == 404
    assert caller.get(f"{API}/{missing}/timeline").status_code == 404
    assert Caller("administrator").post(f"{API}/{missing}/acknowledge").status_code == 404


def _wait_for_a_blocked_writer(timeout_seconds: float = 4.0) -> bool:
    """True once a netsight-api session is waiting on a row lock (the write reached the lock)."""
    assert PG_DSN
    deadline = time.monotonic() + timeout_seconds
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        while time.monotonic() < deadline:
            row = admin.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE application_name = 'netsight-api' AND wait_event_type = 'Lock'"
            ).fetchone()
            if row is not None and row[0] > 0:
                return True
            time.sleep(0.05)
    return False


@pytest.mark.parametrize(
    ("suffix", "body"),
    [
        ("/acknowledge", None),
        ("/comment", {"message": "On site"}),
        ("/evidence", {"evidence_id": "ev-7"}),
    ],
)
def test_reassignment_while_a_technician_write_waits_for_the_lock_is_refused(
    live: PostgresIncidentRepository, suffix: str, body: Any
) -> None:
    """The scope decision is made on the locked row, not on a stale pre-read.

    Another transaction reassigns the incident and holds the row lock. The technician's
    request (assigned at the time it was authorised) blocks on that lock; once the
    reassignment commits it must be refused, and nothing may be written.
    """
    tech = Caller("technician", "tech-1")
    incident_id = seed(live)
    live.set_assignee(incident_id, assignee_id=tech.identity_id, actor_id="seed:op")
    history = live.list_timeline(incident_id)
    row_id = lifecycle.parse_id("incident", incident_id)

    with live._settings.connect() as reassigner:
        reassigner.execute(
            "UPDATE incidents SET assignee_id = %s WHERE id = %s", ("microsoft:tech-2", row_id)
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(tech.post, f"{API}/{incident_id}{suffix}", body)
            reached_the_lock = _wait_for_a_blocked_writer()
            reassigner.commit()  # releases the row lock with the new assignee visible
            response = pending.result(timeout=15)

    assert reached_the_lock, "the technician write never reached the row lock"
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert live.list_timeline(incident_id) == history
    stored = live.get_incident(incident_id)
    assert stored is not None
    assert stored.assignee_id == "microsoft:tech-2"
    assert stored.state == "open"
    assert stored.evidence_ids == []
