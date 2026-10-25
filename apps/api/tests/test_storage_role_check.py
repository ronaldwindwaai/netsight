"""The start-up role check refuses a privileged runtime role and tolerates an unreachable database."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import psycopg
import pytest

from netsight_api.storage.errors import StorageConfigurationError
from netsight_api.storage.role_check import check_app_role, check_app_role_from_env


class _Result:
    def __init__(self, row: dict[str, Any]) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any]:
        return self._row


class _Settings:
    def __init__(self, *, suser: bool = False, bypass: bool = False, owned: int = 0) -> None:
        self._rows = {
            "pg_roles": {"rolname": "app", "rolsuper": suser, "rolbypassrls": bypass},
            "pg_tables": {"owned": owned},
        }

    @contextmanager
    def connect(self, **_: Any):
        rows = self._rows

        class _Conn:
            def execute(self, sql: str) -> _Result:
                return _Result(rows["pg_roles" if "pg_roles" in sql else "pg_tables"])

        yield _Conn()


def test_least_privilege_role_passes() -> None:
    check_app_role(_Settings())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "text"),
    [({"suser": True}, "superuser"), ({"bypass": True}, "row security"), ({"owned": 2}, "owns")],
)
def test_privileged_role_is_refused(kwargs: dict[str, Any], text: str) -> None:
    with pytest.raises(StorageConfigurationError, match=text):
        check_app_role(_Settings(**kwargs))  # type: ignore[arg-type]


def test_unreachable_database_does_not_block_start() -> None:
    class _Down:
        def connect(self, **_: Any):
            raise psycopg.OperationalError("down")

    check_app_role(_Down())  # type: ignore[arg-type]


def test_no_database_url_or_opt_out_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    check_app_role_from_env()
    monkeypatch.setenv("DATABASE_URL", "postgresql://x:y@127.0.0.1:1/z")
    monkeypatch.setenv("NETSIGHT_ALLOW_PRIVILEGED_DB_ROLE", "true")
    check_app_role_from_env()
