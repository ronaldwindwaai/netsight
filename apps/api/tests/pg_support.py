"""Opt-in PostgreSQL test support.

Live PostgreSQL tests run only when ``NETSIGHT_TEST_PG_DSN`` is set (the same
opt-in pattern as ``CLICKHOUSE_TEST_DSN``). Each test gets its own throwaway
schema, so a shared test database is never mutated outside that schema.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import psycopg
import pytest
from psycopg import sql

PG_DSN = os.environ.get("NETSIGHT_TEST_PG_DSN")

requires_pg = pytest.mark.skipif(
    not PG_DSN,
    reason="set NETSIGHT_TEST_PG_DSN to run live PostgreSQL tests",
)


@contextmanager
def isolated_schema() -> Iterator[str]:
    assert PG_DSN
    name = f"nstest_{secrets.token_hex(6)}"
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def dsn_for_role(admin_dsn: str, role: str, password: str) -> str:
    """Rewrite ``admin_dsn`` to connect as ``role`` (same host, port and database)."""
    parts = urlsplit(admin_dsn)
    host = parts.hostname or "localhost"
    host = f"[{host}]" if ":" in host else host
    port = f":{parts.port}" if parts.port else ""
    return f"postgresql://{role}:{password}@{host}{port}{parts.path}"


@contextmanager
def app_role() -> Iterator[tuple[str, str]]:
    """Create a throwaway non-owner, non-superuser login role; yield ``(name, dsn)``.

    The password is random per call and never leaves the test process. Cleanup drops
    every privilege the role was granted, then the role itself.
    """
    assert PG_DSN
    name = f"nsapp_{secrets.token_hex(6)}"
    password = secrets.token_hex(16)
    with psycopg.connect(PG_DSN, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}").format(
                sql.Identifier(name), sql.Literal(password)
            )
        )
        try:
            yield name, dsn_for_role(PG_DSN, name, password)
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
