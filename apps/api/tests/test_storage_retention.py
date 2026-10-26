"""Retention prune: expired rows go, recent rows stay, the append-only guard is restored."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from pg_support import PG_DSN, isolated_schema, requires_pg
from unknown_support import detection

from netsight_api.storage import migrate, retention
from netsight_api.storage.postgres import PostgresSettings
from netsight_api.storage.postgres_unknown_devices import PostgresUnknownDeviceRepository

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
_INSERT = (
    "INSERT INTO notification_delivery_attempts (notification_id, alert_ref, channel, "
    "destination, attempt, status, code, attempted_at) "
    "VALUES (%s, 'a', 'email', 'd', 1, 'sent', 'OK', %s)"
)


def test_rules_use_the_accepted_periods() -> None:
    periods = {rule.table: rule.keep for rule in retention.RULES}
    assert periods["notification_delivery_attempts"] == timedelta(days=90)
    assert periods["diagnostic_sessions"] == timedelta(days=365)


@requires_pg
def test_prune_deletes_only_expired_rows_and_keeps_the_guard() -> None:
    assert PG_DSN
    with (
        isolated_schema() as schema,
        PostgresSettings(dsn=PG_DSN, schema=schema).connect() as conn,
    ):
        migrate.apply_up(conn)
        conn.execute(_INSERT, ("old", NOW - timedelta(days=91)))  # type: ignore[arg-type]
        conn.execute(_INSERT, ("new", NOW - timedelta(days=89)))  # type: ignore[arg-type]
        conn.commit()

        counted = retention.prune(conn, NOW, dry_run=True)
        assert {r.table: r.rows for r in counted}["notification_delivery_attempts"] == 1

        results = retention.prune(conn, NOW)
        assert {r.table: r.rows for r in results} == {
            "notification_delivery_attempts": 1,
            "diagnostic_sessions": 0,
            "unknown_device_findings": 0,
        }
        left = conn.execute("SELECT notification_id FROM notification_delivery_attempts").fetchall()
        assert [row["notification_id"] for row in left] == ["new"]

        # The guard is back and still fires for the owner.
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            conn.execute("DELETE FROM notification_delivery_attempts")
        conn.rollback()
        modes = conn.execute(
            "SELECT tgenabled FROM pg_trigger WHERE tgname IN "
            "('notification_delivery_attempts_no_update_delete', "
            "'diagnostic_sessions_no_update_delete')"
        ).fetchall()
        assert [row["tgenabled"] for row in modes] == ["A", "A"]


def _finding(settings: PostgresSettings, at: datetime, n: int, *, finish: bool) -> str:
    repo = PostgresUnknownDeviceRepository(settings, clock=lambda: at)
    finding_id = repo.observe(
        detection(ip=f"10.0.9.{n}", mac=f"aa:bb:cc:00:09:{n:02x}", hostname=f"host-{n}")
    ).finding_id
    if finish:
        repo.transition_state(
            finding_id,
            to_state="resolved",
            actor_id="t",
            expected_evidence_version=1,
            reason="fixed",
        )
    return finding_id


@requires_pg
def test_prune_removes_old_finished_findings_with_their_timeline_only() -> None:
    assert PG_DSN
    old, recent = NOW - timedelta(days=800), NOW - timedelta(days=100)
    with isolated_schema() as schema:
        settings = PostgresSettings(dsn=PG_DSN, schema=schema)
        with settings.connect() as conn:
            migrate.apply_up(conn)
        gone = _finding(settings, old, 1, finish=True)
        open_old = _finding(settings, old, 2, finish=False)
        recent_done = _finding(settings, recent, 3, finish=True)
        with settings.connect() as conn:
            counted = retention.prune(conn, NOW, dry_run=True)
            assert {r.table: r.rows for r in counted}["unknown_device_findings"] == 1
            results = retention.prune(conn, NOW)
            assert {r.table: r.rows for r in results}["unknown_device_findings"] == 1
            ids = {str(r["id"]) for r in conn.execute("SELECT id FROM unknown_device_findings")}
            assert ids == {i.removeprefix("unknown-device-") for i in (open_old, recent_done)}
            orphans = conn.execute(
                "SELECT count(*) AS n FROM unknown_device_events WHERE finding_id::text = %s",
                (gone.removeprefix("unknown-device-"),),
            ).fetchone()
            assert orphans["n"] == 0
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
                conn.execute("DELETE FROM unknown_device_events")
            conn.rollback()
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
                conn.execute("DELETE FROM unknown_device_findings")
