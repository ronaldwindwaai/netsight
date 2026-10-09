"""Alert-rule and maintenance routes against live PostgreSQL through the real ``DATABASE_URL``.

Opt-in: runs only when ``NETSIGHT_TEST_PG_DSN`` is set (see ``pg_support``). The API connects as
a throwaway least-privilege application role (never the owner), exactly as production does,
in a throwaway schema. No new SQL was added in S6-3; these tests prove the existing rule and
window SQL behaves correctly behind the new routes, including the approval race under real
row locks.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from alerting_support import (
    NOW,
    RULES,
    WINDOWS,
    XSS,
    Caller,
    audit_records,
    iso,
    rule_body,
    window_body,
)
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg
from psycopg import sql

from netsight_api import alerting_route_support
from netsight_api.alerting_route_support import get_now
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.storage.migrate import apply_grants, apply_up
from netsight_api.storage.postgres import PostgresSettings

pytestmark = requires_pg


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch) -> Iterator[PostgresSettings]:
    """Migrated schema + app role; DATABASE_URL points at the app role."""
    assert PG_DSN
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(alerting_route_support, "_write_limiter", RateLimiter())
    monkeypatch.setattr(alerting_route_support, "WRITE_LIMIT_PER_MINUTE", 10_000)
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "NETSIGHT_PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides[get_now] = lambda: NOW
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
        yield owner
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def test_rule_lifecycle_round_trips_through_postgres(
    live: PostgresSettings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    author, admin = Caller("network_engineer", "sub-eng"), Caller("administrator", "sub-admin")
    created = author.post(RULES, rule_body(name=XSS, labels={"team": XSS}))
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["status"] == "draft" and rule["name"] == XSS and rule["labels"]["team"] == XSS
    edited = author.put(
        f"{RULES}/{rule['id']}", {"expected_version": 1, "definition": rule_body(name="v2")}
    ).json()
    assert edited["version"] == 2
    stale = admin.post(f"{RULES}/{rule['id']}/approve", {"expected_version": 1})
    assert stale.status_code == 409
    approved = admin.post(f"{RULES}/{rule['id']}/approve", {"expected_version": 2}).json()
    assert approved["status"] == "active" and approved["approved_by"] == admin.identity_id
    assert (
        author.put(
            f"{RULES}/{rule['id']}", {"expected_version": 3, "definition": rule_body()}
        ).status_code
        == 409
    )
    disabled = author.post(f"{RULES}/{rule['id']}/disable").json()
    assert disabled["status"] == "disabled"
    listing = admin.get(RULES).json()
    assert listing["state"] == "ok" and [r["status"] for r in listing["rules"]] == ["disabled"]
    assert admin.get(f"{RULES}/{rule['id']}").json()["rule"]["name"] == "v2"
    actions = [r["action"] for r in audit_records(caplog) if r["outcome"] == "success"]
    assert actions == [
        "alert_rule.create",
        "alert_rule.update",
        "alert_rule.approve",
        "alert_rule.disable",
    ]


def test_approval_race_under_real_row_locks_never_activates_an_unreviewed_definition(
    live: PostgresSettings,
) -> None:
    admin, author = Caller("administrator", "sub-admin"), Caller("network_engineer", "sub-eng")
    for round_number in range(8):
        _race_once(admin, author, round_number)


def _race_once(admin: Caller, author: Caller, round_number: int) -> None:
    rule = author.post(RULES, rule_body(name=f"reviewed-{round_number}")).json()
    rule_id = rule["id"]
    barrier = threading.Barrier(2)
    results: dict[str, int] = {}

    def edit() -> None:
        barrier.wait()
        results["edit"] = author.put(
            f"{RULES}/{rule_id}",
            {"expected_version": 1, "definition": rule_body(name=f"edited-{round_number}")},
        ).status_code

    def approve() -> None:
        barrier.wait()
        results["approve"] = admin.post(
            f"{RULES}/{rule_id}/approve", {"expected_version": 1}
        ).status_code

    threads = [threading.Thread(target=edit), threading.Thread(target=approve)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    final = admin.get(f"{RULES}/{rule_id}").json()["rule"]
    if final["status"] == "active":
        assert final["name"] == f"reviewed-{round_number}"
        assert results == {"edit": 409, "approve": 200}
    else:
        assert final["status"] == "draft" and final["name"] == f"edited-{round_number}"
        assert results == {"edit": 200, "approve": 409}


def test_two_concurrent_approvals_activate_once(live: PostgresSettings) -> None:
    admin = Caller("administrator", "sub-admin")
    rule = admin.post(RULES, rule_body()).json()
    barrier = threading.Barrier(2)
    statuses: list[int] = []

    def approve() -> None:
        barrier.wait()
        statuses.append(
            Caller("administrator", "sub-admin")
            .post(f"{RULES}/{rule['id']}/approve", {"expected_version": 1})
            .status_code
        )

    threads = [threading.Thread(target=approve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(statuses) == [200, 409]
    assert admin.get(f"{RULES}/{rule['id']}").json()["rule"]["version"] == 2


def test_window_lifecycle_and_derived_active_filter_through_postgres(
    live: PostgresSettings,
) -> None:
    caller = Caller("network_engineer", "sub-eng")
    running = caller.post(
        WINDOWS,
        window_body(
            name="running",
            starts_at=iso(NOW - timedelta(hours=1)),
            ends_at=iso(NOW + timedelta(hours=1)),
        ),
    )
    upcoming = caller.post(WINDOWS, window_body(name=XSS, reason=XSS))
    assert running.status_code == 201 and upcoming.status_code == 201, upcoming.text
    reader = Caller("auditor")
    assert [w["name"] for w in reader.get(WINDOWS, active="true").json()["windows"]] == ["running"]
    assert [w["name"] for w in reader.get(WINDOWS).json()["windows"]] == ["running", XSS]
    cancelled = caller.post(f"{WINDOWS}/{upcoming.json()['id']}/cancel")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert caller.post(f"{WINDOWS}/{upcoming.json()['id']}/cancel").status_code == 409
    assert [w["name"] for w in reader.get(WINDOWS).json()["windows"]] == ["running"]
    with_cancelled = reader.get(WINDOWS, include_cancelled="true").json()
    assert {w["name"] for w in with_cancelled["windows"]} == {"running", XSS}
    detail = reader.get(f"{WINDOWS}/{upcoming.json()['id']}").json()["window"]
    assert detail["cancelled_by"] == caller.identity_id and detail["reason"] == XSS


def test_the_app_role_cannot_activate_a_rule_around_the_api(live: PostgresSettings) -> None:
    """Defence in depth: SQL run as the app role is limited to what the grants allow."""
    admin = Caller("administrator", "sub-admin")
    rule = admin.post(RULES, rule_body()).json()
    dsn = os.environ["DATABASE_URL"]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(live.schema)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM alert_rules")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM maintenance_windows")
    assert admin.get(f"{RULES}/{rule['id']}").json()["state"] == "ok"


def test_text_the_database_cannot_hold_is_not_a_server_error(live: PostgresSettings) -> None:
    """A NUL character is valid JSON text but not valid PostgreSQL text."""
    admin = Caller("administrator", "sub-admin")
    response = admin.post(RULES, rule_body(name="bad\u0000name"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_OPERATION"
    assert "bad" not in response.text
    assert admin.get(RULES).json()["rules"] == []


# --- capacity caps and the organisation-scope cancel, under the real database ------------------------


def live_window(**overrides: object) -> dict[str, object]:
    """A window that is still running for the database's real clock (the store judges 'live'
    by its own clock, not by the route clock the other tests pin to NOW)."""
    real = datetime.now(UTC)
    body = window_body(
        starts_at=iso(real + timedelta(hours=1)), ends_at=iso(real + timedelta(hours=5))
    )
    return {**body, **overrides}


def test_the_per_scope_window_cap_holds_under_concurrent_creators(live: PostgresSettings) -> None:
    from netsight_api.storage import lifecycle

    caller = Caller("network_engineer", "sub-eng")
    for _ in range(lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE - 1):
        assert caller.post(WINDOWS, live_window()).status_code == 201
    barrier = threading.Barrier(6)
    statuses: list[int] = []

    def create() -> None:
        barrier.wait()
        statuses.append(
            Caller("network_engineer", "sub-eng").post(WINDOWS, live_window()).status_code
        )

    threads = [threading.Thread(target=create) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(statuses) == [201, 409, 409, 409, 409, 409]
    stored = Caller("auditor").get(WINDOWS, limit=100).json()["windows"]
    assert len(stored) == lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE
    other = caller.post(WINDOWS, live_window(scope={"kind": "site", "ref": "elsewhere"}))
    assert other.status_code == 201


def test_cancelled_windows_free_capacity_and_the_rule_cap_is_enforced(
    live: PostgresSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netsight_api.storage import lifecycle

    monkeypatch.setattr(lifecycle, "MAX_LIVE_WINDOWS_PER_SCOPE", 2)
    monkeypatch.setattr(lifecycle, "MAX_RULES", 2)
    caller = Caller("network_engineer", "sub-eng")
    first = caller.post(WINDOWS, live_window()).json()
    assert caller.post(WINDOWS, live_window()).status_code == 201
    assert caller.post(WINDOWS, live_window()).status_code == 409
    assert caller.post(f"{WINDOWS}/{first['id']}/cancel").status_code == 200
    assert caller.post(WINDOWS, live_window()).status_code == 201
    expired_scope = {"kind": "site", "ref": "past"}
    past = live_window(
        scope=expired_scope,
        starts_at=iso(NOW - timedelta(hours=3)),
        ends_at=iso(NOW + timedelta(seconds=1)),
    )
    assert caller.post(WINDOWS, past).status_code == 201
    assert caller.post(RULES, rule_body()).status_code == 201
    assert caller.post(RULES, rule_body()).status_code == 201
    refused = caller.post(RULES, rule_body())
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "LIMIT_REACHED"


def test_organisation_window_cancel_is_judged_on_the_locked_row(
    live: PostgresSettings, caplog: pytest.LogCaptureFixture
) -> None:
    admin, engineer = Caller("administrator", "sub-admin"), Caller("network_engineer", "sub-eng")
    window = admin.post(
        WINDOWS, live_window(scope={"kind": "organisation", "ref": "default"}, evaluation="disable")
    )
    assert window.status_code == 201, window.text
    window_id = window.json()["id"]
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    denied = engineer.post(WINDOWS, live_window(evaluation="disable"))
    assert denied.status_code == 403  # disable mode is administrator-only whatever the scope
    refused = engineer.post(f"{WINDOWS}/{window_id}/cancel")
    assert refused.status_code == 403
    assert engineer.get(f"{WINDOWS}/{window_id}").json()["window"]["status"] == "scheduled"
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [
        ("denied", "disable-evaluation"),
        ("denied", "organisation-scope"),
    ]
    assert admin.post(f"{WINDOWS}/{window_id}/cancel").status_code == 200
