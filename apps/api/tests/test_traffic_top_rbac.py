"""Top talkers name source addresses (endpoint level); top destinations are an aggregate.

The two rungs of the traffic permission applied to the S4 routes: Management holds the aggregate rung
only, so it reads destinations but not talkers; every read of talkers is audited.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient

from netsight_api import read_limit
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app, get_optional_traffic_source
from netsight_api.schemas import TrafficItem

TALKERS = "/api/v1/traffic/top-talkers"
DESTINATIONS = "/api/v1/traffic/top-destinations"


class _Source:
    async def top(self, **_: Any) -> tuple[list[TrafficItem], None]:
        item = TrafficItem(
            rank=1,
            subject_kind="ip",
            subject_id=None,
            label="10.0.0.1",
            bytes=5,
            packets=None,
            share=None,
        )
        return [item], None


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "CLICKHOUSE_DSN"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    app.dependency_overrides[get_optional_traffic_source] = lambda: _Source()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


@pytest.mark.parametrize(
    "role", ["administrator", "network_engineer", "security_analyst", "auditor"]
)
def test_endpoint_level_roles_read_talkers(role: str) -> None:
    assert Caller(role).get(TALKERS).status_code == 200


@pytest.mark.parametrize("role", ["management", "technician"])
def test_the_aggregate_rung_does_not_name_source_addresses(role: str) -> None:
    assert Caller(role).get(TALKERS).status_code == 403


def test_management_still_reads_destinations_and_technician_does_not() -> None:
    assert Caller("management").get(DESTINATIONS).status_code == 200
    assert Caller("auditor").get(DESTINATIONS).status_code == 200
    assert Caller("technician").get(DESTINATIONS).status_code == 403


def test_anonymous_callers_are_refused() -> None:
    assert TestClient(app).get(TALKERS).status_code == 401


def test_talkers_reads_and_denials_are_audited_without_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert Caller("security_analyst").get(TALKERS).status_code == 200
        assert Caller("management").get(TALKERS).status_code == 403
    records = [r for r in audit_records(caplog) if r["action"] == "traffic.top-talkers.read"]
    assert [(r["outcome"], r.get("reason")) for r in records] == [
        ("success", None),
        ("denied", "permission"),
    ]
    assert records[0]["row_count"] == 1 and "10.0.0.1" not in str(records)
