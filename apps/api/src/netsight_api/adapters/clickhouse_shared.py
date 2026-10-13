"""The process-wide ClickHouse flow client.

A client carries what it discovered about the flows table, so building a new one for every request
repeats the ``system.columns`` round trip on every Explorer request. One client is kept for as long as
the configuration (DSN, user, password, table) is unchanged; a different configuration builds a fresh
one, and an unset DSN drops it. The client's own schema cache expires (``SCHEMA_TTL_SECONDS``), and
what the process learned about per-query limits is keyed by endpoint and user (``clickhouse_limits``),
so neither goes stale. Credentials stay out of ``repr`` and are never logged.
"""

from __future__ import annotations

import hashlib
import os

from netsight_api.adapters.clickhouse_explorer import ExplorerClickhouse

_kept: tuple[tuple[str, str, str, str], ExplorerClickhouse] | None = None


def _fingerprint(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def shared_client() -> ExplorerClickhouse | None:
    """The configured client (shared), or ``None`` when ``CLICKHOUSE_DSN`` is unset."""
    global _kept
    dsn = os.environ.get("CLICKHOUSE_DSN", "").strip()
    if not dsn:
        _kept = None
        return None
    user = os.environ.get("CLICKHOUSE_USER", "").strip()
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    table = os.environ.get("CLICKHOUSE_FLOWS_TABLE", "").strip() or "flows"
    key = (dsn, user, _fingerprint(password), table)
    if _kept is not None and _kept[0] == key:
        return _kept[1]
    client = ExplorerClickhouse(dsn=dsn, user=user, password=password, flows_table=table)
    _kept = (key, client)
    return client


def reset_for_tests() -> None:
    global _kept
    _kept = None
