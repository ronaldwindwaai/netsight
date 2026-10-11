"""Admission control seen through the routes: one heavy read per identity, a slot kept for detail.

The guard itself is covered in ``test_traffic_guards``; these pin what a caller sees (status, code,
``Retry-After``, the audit record) and that the refusal happens before the flow store is touched.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from traffic_support import (
    NOW,
    WINDOW,
    FakeSource,
    applications_read,
    destinations_read,
    inputs,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.traffic import guards
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.policy import POLICY_FILE_ENV

PATHS = {
    "/api/v1/traffic/flows": "traffic.flows.read",
    "/api/v1/traffic/applications": "traffic.applications.read",
    "/api/v1/traffic/destinations": "traffic.destinations.read",
    "/api/v1/traffic/anomalies": "traffic.anomalies.read",
}
HOUR = {"from": "2026-10-11T11:00:00Z", "to": "2026-10-11T12:00:00Z"}


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "DATABASE_URL", "CLICKHOUSE_DSN", POLICY_FILE_ENV):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_now] = lambda: NOW
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: TtlCache()
    app.dependency_overrides[traffic_routes.get_identity_service] = lambda: None
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def use(source: FakeSource) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source


def fake() -> FakeSource:
    return FakeSource(
        applications=applications_read(),
        destinations=destinations_read(),
        inputs=inputs(),
    )


def fetch(role: str, path: str, **params: Any) -> Any:
    window = HOUR if path.endswith("anomalies") else WINDOW
    return Caller(role).get(path, **{**window, **params})


@pytest.mark.parametrize("path", PATHS)
def test_an_identity_with_a_read_running_is_refused_with_429(
    path: str, caplog: pytest.LogCaptureFixture
) -> None:
    source = fake()
    use(source)
    caller = Caller("administrator")
    guards._running.add(caller.identity_id)  # a read of this identity is in flight
    window = HOUR if path.endswith("anomalies") else WINDOW
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = caller.get(path, **window)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "TRAFFIC_CONCURRENCY"
    assert response.headers["retry-after"] == "5"
    assert source.calls == []  # refused before the flow store is touched
    (record,) = [r for r in audit_records(caplog) if r["action"] == PATHS[path]]
    assert record["outcome"] == "failure" and record["reason"] == "identity-busy"


@pytest.mark.parametrize("path", PATHS)
def test_another_identity_is_not_affected(path: str) -> None:
    use(fake())
    guards._running.add("someone-else")
    assert fetch("administrator", path).status_code == 200


@pytest.mark.parametrize("path", PATHS)
def test_the_last_slot_is_kept_for_the_detail_tier(
    path: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    use(fake())
    monkeypatch.setattr(guards, "_active", guards.MAX_CONCURRENT_HEAVY - guards.RESERVED_FOR_DETAIL)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        refused = fetch("management", path)
    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "TRAFFIC_BUSY"
    assert refused.headers["retry-after"] == "5"
    (record,) = [r for r in audit_records(caplog) if r["action"] == PATHS[path]]
    assert record["outcome"] == "failure" and record["reason"] == "busy"
    # The same load does not stop the detail tier.
    assert fetch("security_analyst", path).status_code == 200


@pytest.mark.parametrize("path", PATHS)
def test_when_every_slot_is_taken_even_the_detail_tier_is_refused(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    use(fake())
    monkeypatch.setattr(guards, "_active", guards.MAX_CONCURRENT_HEAVY)
    assert fetch("administrator", path).status_code == 503


@pytest.mark.parametrize("path", PATHS)
def test_slots_are_released_after_each_read(path: str) -> None:
    use(fake())
    for _ in range(guards.MAX_CONCURRENT_HEAVY + 2):
        assert fetch("administrator", path).status_code == 200
    assert guards._active == 0 and not guards._running


@pytest.mark.parametrize("path", PATHS)
def test_a_failing_source_still_releases_the_slot(path: str) -> None:
    use(FakeSource(error=RuntimeError("boom")))
    assert fetch("administrator", path).status_code == 200
    assert guards._active == 0 and not guards._running
