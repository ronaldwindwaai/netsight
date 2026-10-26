"""DEMO ONLY: migrate a throwaway PostgreSQL, create a least-privilege app role and seed fixtures.

Reads the owner DSN from NETSIGHT_DEMO_PG_DSN (a database you may freely change), applies the
migrations and grants, seeds unknown-device findings and two days of WAN probe cycles when those
tables are empty, and sets the app role's password from NETSIGHT_DEMO_PG_APP_PASSWORD (chosen by scripts/demo-local.py,
so nothing secret is printed here).
Refuses to run unless NETSIGHT_DEMO=1, like demo_app.py.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1] / "src"), str(HERE.parent)]

import psycopg
from psycopg import sql
from unknown_support import detection

from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.postgres_unknown_devices import (
    PostgresUnknownDeviceRepository,
)
from netsight_api.storage.postgres_wan import PostgresWanSampleRepository
from netsight_api.wan import sla

APP_ROLE = "netsight_demo_app"
LINK_ID = "demo-primary"
INTERVAL = 300
DAYS = 2
OUTAGE = (timedelta(hours=30), timedelta(hours=30) - timedelta(minutes=25))  # start, end ago
FINDINGS = (
    {"ip": "10.0.5.9", "mac": "aa:bb:cc:00:00:09", "hostname": "printer-x", "severity": "low"},
    {"ip": "10.0.6.41", "mac": "aa:bb:cc:00:00:41", "hostname": None, "severity": "medium"},
    {"ip": "10.0.7.77", "mac": "aa:bb:cc:00:00:77", "hostname": "unknown-iot", "severity": "high"},
)


def _samples(now: datetime, at: datetime) -> list[sla.Sample]:
    down = now - OUTAGE[0] <= at <= now - OUTAGE[1]
    degraded = at.hour in (18, 19) and at.minute < 20
    outcomes = ("fail", "fail") if down else (("pass", "fail") if degraded else ("pass", "pass"))
    targets = ("198.51.100.1", "198.51.100.2")
    return [
        sla.Sample("icmp", target, outcome, None if outcome == "fail" else 14.0 + (at.minute % 7))
        for target, outcome in zip(targets, outcomes, strict=True)
    ]


def _seed_wan(owner: PostgresSettings) -> None:
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    start = now - timedelta(days=DAYS)
    with owner.connect() as conn:
        migrate.ensure_wan_partitions(conn, migrate.wan_partition_months(start, 1))
    repo = PostgresWanSampleRepository(owner)
    moment = start - timedelta(seconds=start.timestamp() % INTERVAL)
    while moment <= now:
        samples = _samples(now, moment)
        repo.record_cycle(sla.build_cycle(LINK_ID, moment, INTERVAL, samples), samples)
        moment += timedelta(seconds=INTERVAL)


def _seed_findings(owner: PostgresSettings) -> None:
    repo = PostgresUnknownDeviceRepository(owner)
    for spec in FINDINGS:
        repo.observe(detection(with_action=spec["severity"] == "high", **spec))
    first = repo.list_findings(states=None, severity=None, assigned=None, limit=50, offset=0)[0][-1]
    repo.transition_state(
        first.id,
        to_state="acknowledged",
        actor_id="demo",
        expected_evidence_version=first.evidence_version,
    )


def _count(owner: PostgresSettings, table: str) -> int:
    with owner.connect() as conn:
        row = conn.execute(sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(table)))
        return int(row.fetchone()["n"])  # type: ignore[index]


def main() -> int:
    if os.environ.get("NETSIGHT_DEMO") != "1":
        print("refusing to seed a database outside the demo", file=sys.stderr)
        return 2
    owner_dsn = os.environ["NETSIGHT_DEMO_PG_DSN"]
    owner = PostgresSettings(dsn=owner_dsn)
    with owner.connect() as conn:
        migrate.apply_up(conn)
    password = os.environ["NETSIGHT_DEMO_PG_APP_PASSWORD"]
    with psycopg.connect(owner_dsn, autocommit=True) as admin:
        exists = admin.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (APP_ROLE,)).fetchone()
        verb = "ALTER" if exists else "CREATE"
        admin.execute(
            sql.SQL(
                verb + " ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(APP_ROLE), sql.Literal(password))
        )
    with owner.connect() as conn:
        migrate.apply_grants(conn, APP_ROLE)
    if _count(owner, "unknown_device_findings") == 0:
        _seed_findings(owner)
    if _count(owner, "wan_link_cycles") == 0:
        _seed_wan(owner)
    print("demo database ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
