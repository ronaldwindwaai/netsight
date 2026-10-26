"""Start-up refusal of a database role the API must never run as.

The append-only triggers and grants only hold if the runtime role is not a superuser, does not
bypass row security and does not own the tables (an owner can disable triggers). A definite
violation fails start-up; an unreachable database does not (stores already report ``unknown``).
"""

from __future__ import annotations

import logging
import os

import psycopg

from netsight_api.storage.connection import APP_DSN_VARIABLE, PostgresSettings
from netsight_api.storage.errors import StorageConfigurationError

ALLOW_PRIVILEGED_VARIABLE = "NETSIGHT_ALLOW_PRIVILEGED_DB_ROLE"
_LOGGER = logging.getLogger("netsight_api")

_ROLE_SQL = "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
_OWNED_SQL = (
    "SELECT count(*) AS owned FROM pg_tables "
    "WHERE tableowner = current_user AND schemaname = current_schema()"
)


def check_app_role(settings: PostgresSettings) -> None:
    """Raise ``StorageConfigurationError`` when the connected role is privileged."""
    try:
        with settings.connect(autocommit=True) as conn:
            role = conn.execute(_ROLE_SQL).fetchone()
            owned = conn.execute(_OWNED_SQL).fetchone()
    except psycopg.Error:
        _LOGGER.warning("database role check skipped: database unreachable")
        return
    if role is None or owned is None:
        return
    problems = []
    if role["rolsuper"]:
        problems.append("is a superuser")
    if role["rolbypassrls"]:
        problems.append("bypasses row security")
    if owned["owned"]:
        problems.append("owns tables")
    if problems:
        raise StorageConfigurationError(
            f"{APP_DSN_VARIABLE} role {' and '.join(problems)}; use the least-privilege "
            f"application role (or set {ALLOW_PRIVILEGED_VARIABLE}=true for local development)"
        )


def check_app_role_from_env() -> None:
    """No-op without ``DATABASE_URL`` or with the explicit local-development opt-out."""
    if not os.environ.get(APP_DSN_VARIABLE, "").strip():
        return
    if os.environ.get(ALLOW_PRIVILEGED_VARIABLE, "").strip().lower() == "true":
        return
    check_app_role(PostgresSettings.from_env())
