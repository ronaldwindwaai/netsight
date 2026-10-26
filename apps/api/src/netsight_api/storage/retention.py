"""Retention prune for the append-only tables, run by the migrator credential only.

The runtime role has no DELETE anywhere, and the append-only triggers refuse DELETE for every role
(they are ENABLE ALWAYS, so ``session_replication_role`` cannot skip them). The owner may still
disable a trigger, so a prune is the one deliberate, audited exception: per table, in ONE transaction,
disable the row triggers, delete the expired rows, re-enable them as ENABLE ALWAYS, and report the
count. DDL is transactional in PostgreSQL, so any failure leaves the triggers exactly as they were.

Periods are the owner's accepted defaults (docs/10-project-management/OPEN-DECISIONS.md, 2026-10-26):

* D-06 notification delivery attempts: 90 days.
* D-03 diagnostic sessions: 12 months. (The 90-day minimisation of free text inside the stored
  document is not built: it needs a jsonb rewrite that the append-only UPDATE trigger forbids.)

* D-02 unknown-device findings: events reference their finding with ON DELETE RESTRICT, so a finding
  cannot go before its timeline. Resolved by pruning a *finished* finding (resolved or false-positive,
  which can no longer change) TOGETHER with its timeline once it is 24 months old, the longer of the two
  accepted periods. A finding that a newer one names as ``recurrence_of`` stays until that one goes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from psycopg import Connection, sql

from netsight_api.storage.migrate import _first_value


@dataclass(frozen=True)
class RetentionRule:
    table: str
    time_column: str
    keep: timedelta
    triggers: tuple[str, ...]


RULES: tuple[RetentionRule, ...] = (
    RetentionRule(
        "notification_delivery_attempts",
        "attempted_at",
        timedelta(days=90),
        ("notification_delivery_attempts_no_update_delete",),
    ),
    RetentionRule(
        "diagnostic_sessions",
        "created_at",
        timedelta(days=365),
        ("diagnostic_sessions_no_update_delete",),
    ),
)


FINDINGS_KEEP = timedelta(days=730)
_FINISHED_FINDINGS = """
    FROM unknown_device_findings f
    WHERE f.state IN ('resolved', 'false-positive') AND f.updated_at < %s
      AND NOT EXISTS (SELECT 1 FROM unknown_device_findings r WHERE r.recurrence_of = f.id)
"""
_FINDING_TRIGGERS = (
    ("unknown_device_events", "unknown_device_events_no_update_delete"),
    ("unknown_device_findings", "unknown_device_findings_no_delete"),
)


@dataclass(frozen=True)
class PruneResult:
    table: str
    cutoff: datetime
    rows: int


def prune(
    conn: Connection,
    now: datetime | None = None,
    rules: Sequence[RetentionRule] = RULES,
    *,
    dry_run: bool = False,
) -> list[PruneResult]:
    """Delete the rows older than each rule's period; with ``dry_run`` only count them."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    results: list[PruneResult] = []
    for rule in rules:
        cutoff = moment - rule.keep
        table = sql.Identifier(rule.table)
        column = sql.Identifier(rule.time_column)
        if dry_run:
            row = conn.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE {} < %s").format(table, column), (cutoff,)
            ).fetchone()
            results.append(PruneResult(rule.table, cutoff, int(_first_value(row)) if row else 0))
            continue
        with conn.transaction():
            for name in rule.triggers:
                conn.execute(
                    sql.SQL("ALTER TABLE {} DISABLE TRIGGER {}").format(table, sql.Identifier(name))
                )
            deleted = conn.execute(
                sql.SQL("DELETE FROM {} WHERE {} < %s").format(table, column), (cutoff,)
            ).rowcount
            for name in rule.triggers:
                conn.execute(
                    sql.SQL("ALTER TABLE {} ENABLE ALWAYS TRIGGER {}").format(
                        table, sql.Identifier(name)
                    )
                )
        results.append(PruneResult(rule.table, cutoff, deleted))
    results.append(_prune_findings(conn, moment, dry_run=dry_run))
    return results


def _prune_findings(conn: Connection, moment: datetime, *, dry_run: bool) -> PruneResult:
    cutoff = moment - FINDINGS_KEEP
    if dry_run:
        row = conn.execute(
            sql.SQL("SELECT count(*) AS n " + _FINISHED_FINDINGS),
            (cutoff,),  # type: ignore[arg-type]
        ).fetchone()
        return PruneResult("unknown_device_findings", cutoff, int(_first_value(row)) if row else 0)
    with conn.transaction():
        for table, trigger in _FINDING_TRIGGERS:
            conn.execute(
                sql.SQL("ALTER TABLE {} DISABLE TRIGGER {}").format(
                    sql.Identifier(table), sql.Identifier(trigger)
                )
            )
        conn.execute(
            "DELETE FROM unknown_device_events WHERE finding_id IN (SELECT f.id "  # type: ignore[arg-type]
            + _FINISHED_FINDINGS
            + ")",
            (cutoff,),
        )
        deleted = conn.execute(
            "DELETE FROM unknown_device_findings WHERE id IN (SELECT f.id "  # type: ignore[arg-type]
            + _FINISHED_FINDINGS
            + ")",
            (cutoff,),
        ).rowcount
        for table, trigger in _FINDING_TRIGGERS:
            conn.execute(
                sql.SQL("ALTER TABLE {} ENABLE ALWAYS TRIGGER {}").format(
                    sql.Identifier(table), sql.Identifier(trigger)
                )
            )
    return PruneResult("unknown_device_findings", cutoff, deleted)
