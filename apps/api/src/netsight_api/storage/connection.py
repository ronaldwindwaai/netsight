"""PostgreSQL connection settings, session timeouts and error translation.

* The DSN is a secret: read from the environment, excluded from repr, never logged.
* Runtime code connects as the least-privilege application role (``DATABASE_URL``);
  schema changes and grants use the separate migrator role (``DATABASE_MIGRATION_URL``).
* Every session is bounded by lock / statement / idle-in-transaction timeouts, and
  ``PostgresSettings.session()`` is the single place psycopg failures become
  ``StorageError`` subclasses.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg.rows import dict_row

from netsight_api.storage.errors import (
    InvalidOperationError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
)

Connection = psycopg.Connection[dict[str, Any]]

_SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_SQLALCHEMY_PREFIX = "postgresql+psycopg://"
_CONNECT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class SessionTimeouts:
    """Server-side limits applied to every session (milliseconds)."""

    lock_ms: int
    statement_ms: int
    idle_in_transaction_ms: int


APP_TIMEOUTS = SessionTimeouts(lock_ms=5_000, statement_ms=15_000, idle_in_transaction_ms=30_000)
# Schema changes legitimately run longer (index builds, table rewrites).
MIGRATOR_TIMEOUTS = SessionTimeouts(
    lock_ms=30_000, statement_ms=600_000, idle_in_transaction_ms=600_000
)

APP_DSN_VARIABLE = "DATABASE_URL"
MIGRATOR_DSN_VARIABLE = "DATABASE_MIGRATION_URL"


@dataclass(frozen=True)
class PostgresSettings:
    """Connection settings. The DSN is a secret: excluded from repr/str and never echoed."""

    dsn: str = field(repr=False)
    schema: str | None = None
    timeouts: SessionTimeouts = APP_TIMEOUTS

    def __post_init__(self) -> None:
        if not isinstance(self.dsn, str) or not self.dsn.startswith(
            ("postgresql://", "postgres://")
        ):
            raise StorageConfigurationError("the database DSN must be a postgresql:// URL")
        if self.schema is not None and not _SCHEMA_NAME.fullmatch(self.schema):
            raise StorageConfigurationError("the database schema name is not a safe identifier")

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        variable: str = APP_DSN_VARIABLE,
        schema: str | None = None,
        timeouts: SessionTimeouts = APP_TIMEOUTS,
    ) -> PostgresSettings:
        source = os.environ if env is None else env
        raw = source.get(variable, "").strip()
        if not raw:
            raise StorageConfigurationError(f"{variable} is not set")
        if raw.startswith(_SQLALCHEMY_PREFIX):
            raw = "postgresql://" + raw[len(_SQLALCHEMY_PREFIX) :]
        return cls(dsn=raw, schema=schema, timeouts=timeouts)

    @classmethod
    def for_migrator(
        cls, env: Mapping[str, str] | None = None, *, schema: str | None = None
    ) -> PostgresSettings:
        """Settings for the owner/migrator role (``DATABASE_MIGRATION_URL``), never the app role."""
        return cls.from_env(
            env, variable=MIGRATOR_DSN_VARIABLE, schema=schema, timeouts=MIGRATOR_TIMEOUTS
        )

    def _options(self) -> str:
        flags = [
            f"-c lock_timeout={self.timeouts.lock_ms}",
            f"-c statement_timeout={self.timeouts.statement_ms}",
            f"-c idle_in_transaction_session_timeout={self.timeouts.idle_in_transaction_ms}",
        ]
        if self.schema is not None:
            flags.append(f"-c search_path={self.schema}")
        return " ".join(flags)

    def connect(self, *, autocommit: bool = False, **extra: Any) -> Connection:
        """Open a new connection (use as a context manager: commit or rollback).

        Raises raw psycopg errors; repositories use ``session()`` instead. timestamptz
        values come back as timezone-aware datetimes whatever the session time zone is,
        so no session time zone is forced. ``extra`` are further libpq parameters
        (for example TCP keepalives for a long-lived session).
        """
        return psycopg.connect(
            self.dsn,
            row_factory=dict_row,
            options=self._options(),
            connect_timeout=_CONNECT_TIMEOUT_SECONDS,
            application_name="netsight-api",
            autocommit=autocommit,
            **extra,
        )

    @contextmanager
    def session(self) -> Iterator[Connection]:
        """One bounded transaction; psycopg failures become ``StorageError`` subclasses.

        This is the single place database errors are translated, including failures
        raised while committing on exit.
        """
        try:
            with self.connect() as conn:
                yield conn
        except psycopg.Error as error:
            raise translate_database_error(error) from error


_CONFLICT_ERRORS = (
    psycopg.errors.UniqueViolation,
    psycopg.errors.SerializationFailure,
    psycopg.errors.DeadlockDetected,
)
_UNAVAILABLE_ERRORS = (
    psycopg.errors.LockNotAvailable,
    psycopg.errors.QueryCanceled,
    psycopg.errors.IdleInTransactionSessionTimeout,
    psycopg.OperationalError,
    psycopg.InterfaceError,
)
_INVALID_ERRORS = (psycopg.errors.CheckViolation, psycopg.DataError)


def translate_database_error(error: psycopg.Error) -> StorageError:
    """Map a psycopg failure to a storage-domain error with a fixed, non-leaking message.

    Original details stay on ``__cause__`` for server-side logging only.
    """
    if isinstance(error, _CONFLICT_ERRORS):
        return StorageConflictError("the change conflicted with a concurrent update")
    if isinstance(error, _UNAVAILABLE_ERRORS):
        return StorageUnavailableError("the database could not serve the request in time")
    if isinstance(error, _INVALID_ERRORS):
        return InvalidOperationError("the database rejected the supplied values")
    return StorageError("unexpected database error")
