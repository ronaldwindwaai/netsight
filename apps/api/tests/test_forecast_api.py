"""The forecast routes over HTTP: RBAC, strict parameters, explicit states, audit, limits (Step 13).

Hermetic: the flow source is a fake; the real session, RBAC and rate-limit stack runs through
``Caller``. Every body is checked against the canonical JSON Schema.
"""

from __future__ import annotations

import csv
import io
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from forecast_support import GB, NOW, FakeSource, growing, totals

from netsight_api import forecast_routes, read_limit
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.rbac import Permission, Role, is_allowed
from netsight_api.traffic.cache import TtlCache


def caches(reads: float = 0.0, failures: float = 0.0) -> forecast_routes.ForecastCaches:
    return forecast_routes.ForecastCaches(reads=TtlCache(reads), failures=TtlCache(failures))


BASE = "/api/v1/forecast/capacity"
EXPORT = BASE + "/export"
READ_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
EXPORT_ROLES = ["administrator", "network_engineer", "security_analyst", "management", "auditor"]


def use(source: Any = "default", *, limit: int | None = None) -> None:
    chosen = FakeSource(totals(growing(40))) if source == "default" else source
    app.dependency_overrides[forecast_routes.get_history_source] = lambda: chosen
    app.dependency_overrides[forecast_routes.get_now] = lambda: NOW
    app.dependency_overrides[forecast_routes.get_traffic_limit] = lambda: limit
    app.dependency_overrides[forecast_routes.get_forecast_caches] = lambda: caches()


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    use()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


# --- authentication and authorisation ----------------------------------------------------------------


def test_unauthenticated_callers_get_401() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(BASE).status_code == 401
    assert client.get(EXPORT).status_code == 401


@pytest.mark.parametrize("role", READ_ROLES)
def test_every_role_reads_the_forecast(role: str) -> None:
    response = Caller(role).get(BASE)
    assert response.status_code == 200
    validate("forecast_response", response.json())


@pytest.mark.parametrize("role", READ_ROLES)
def test_the_export_follows_its_own_permission(role: str) -> None:
    response = Caller(role).get(EXPORT)
    assert response.status_code == (200 if role in EXPORT_ROLES else 403)


def test_unknown_roles_are_denied() -> None:
    assert Caller("superuser").get(BASE).status_code == 403


def test_the_permission_matrix_is_read_for_all_and_export_not_for_technician() -> None:
    for role in Role:
        holds = {p for p in Permission if is_allowed(_identity(role), p.value)}
        assert Permission.FORECAST_READ in holds
        assert (Permission.FORECAST_EXPORT in holds) == (role is not Role.TECHNICIAN)


def _identity(role: Role) -> Any:
    from netsight_api.rbac import Identity, PrincipalKind

    return Identity("x", frozenset({role.value}), PrincipalKind.HUMAN)


def test_authorisation_runs_before_validation_and_before_the_limiter() -> None:
    caller = Caller("technician")
    assert caller.get(EXPORT, horizon_days=999).status_code == 403
    for _ in range(40):
        assert caller.get(EXPORT).status_code == 403  # never a 429


def test_there_is_no_write_route_under_forecast() -> None:
    paths = {p: m for p, m in app.openapi()["paths"].items() if "/forecast" in p}
    assert paths and all(set(methods) == {"get"} for methods in paths.values())


# --- the forecast ------------------------------------------------------------------------------------


def test_the_default_forecast_is_labelled_not_cacheable_and_valid() -> None:
    response = Caller("network_engineer").get(BASE)
    body = response.json()
    assert response.headers["cache-control"] == "no-store"
    assert body["is_forecast"] is True and body["state"] == "ok"
    assert (body["horizon_days"], body["history_days"]) == (14, 56)
    traffic = next(s for s in body["series"] if s["id"] == "traffic-volume")
    assert len(traffic["forecast"]) == 14
    assert all(r["advisory"] is True and r["executable"] is False for r in body["recommendations"])


def test_parameters_are_applied() -> None:
    body = Caller("auditor").get(BASE, horizon_days=5, history_days=30).json()
    traffic = next(s for s in body["series"] if s["id"] == "traffic-volume")
    assert len(traffic["forecast"]) == 5 and body["history_days"] == 30


def test_no_flow_source_is_not_connected() -> None:
    use(None)
    body = Caller("network_engineer").get(BASE).json()
    validate("forecast_response", body)
    assert body["state"] == "not-connected"
    assert all(s["forecast"] == [] and s["history"] == [] for s in body["series"])


def test_a_failing_source_is_unknown_and_audited_as_a_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    use(FakeSource(error=RuntimeError("secret-token-123")))
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("network_engineer").get(BASE)
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert "secret-token-123" not in response.text
    record = [r for r in audit_records(caplog) if r["action"] == "forecast.capacity.read"][-1]
    assert record["outcome"] == "failure" and record["state"] == "unknown"


def test_a_response_that_fails_its_contract_degrades_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.contracts import ContractViolation

    def refuse(*_: Any, **__: Any) -> None:
        raise ContractViolation("forecast_response", "broken")

    monkeypatch.setattr(forecast_routes, "validate", refuse)
    body = Caller("network_engineer").get(BASE).json()
    assert body["state"] == "unknown"
    assert all(s["forecast"] == [] for s in body["series"])


def test_a_configured_limit_adds_a_threshold_and_a_crossing() -> None:
    use(limit=125 * GB)
    body = Caller("network_engineer").get(BASE, horizon_days=7).json()
    validate("forecast_response", body)
    traffic = next(s for s in body["series"] if s["id"] == "traffic-volume")
    assert traffic["threshold"] == {"value": 125 * GB, "basis": "operator-configured"}
    assert traffic["crossing"]["point_day"] is not None


@pytest.mark.parametrize(
    "params",
    [
        {"horizon_days": "0"},
        {"horizon_days": "31"},
        {"horizon_days": "x"},
        {"horizon_days": "-1"},
        {"history_days": "13"},
        {"history_days": "121"},
        {"history_days": ""},
        {"unknown": "1"},
    ],
)
def test_bad_queries_are_a_422_that_echoes_nothing(params: dict[str, str]) -> None:
    response = Caller("network_engineer").get(BASE, **params)
    assert response.status_code == 422
    assert "unknown" not in response.text.lower().replace("validation", "")


def test_a_repeated_parameter_is_refused() -> None:
    assert Caller("auditor").http.get(BASE + "?horizon_days=7&horizon_days=8").status_code == 422


# --- limits, admission, caching ------------------------------------------------------------------------


def test_the_read_rate_limit_answers_429_with_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(forecast_routes, "READ_LIMIT_PER_MINUTE", 3)
    caller = Caller("network_engineer")
    assert [caller.get(BASE).status_code for _ in range(3)] == [200, 200, 200]
    blocked = caller.get(BASE)
    assert blocked.status_code == 429 and blocked.headers["retry-after"] == "60"


def test_the_export_has_its_own_tighter_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(forecast_routes, "EXPORT_LIMIT_PER_MINUTE", 2)
    caller = Caller("auditor")
    assert [caller.get(EXPORT).status_code for _ in range(2)] == [200, 200]
    assert caller.get(EXPORT).status_code == 429
    assert caller.get(BASE).status_code == 200  # a separate budget


def test_a_busy_flow_store_is_refused_not_queued(caplog: pytest.LogCaptureFixture) -> None:
    from netsight_api.traffic import guards

    guards._active = guards.MAX_CONCURRENT_HEAVY  # every slot taken
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("network_engineer").get(BASE)
    assert response.status_code == 503 and "retry-after" in response.headers
    assert any(r.get("reason") == "busy" for r in audit_records(caplog))


def test_a_cached_read_does_not_hit_the_flow_store_again() -> None:
    source = FakeSource(totals(growing(40)))
    shared = caches(reads=300.0)
    app.dependency_overrides[forecast_routes.get_history_source] = lambda: source
    app.dependency_overrides[forecast_routes.get_forecast_caches] = lambda: shared
    caller = Caller("network_engineer")
    first, second = caller.get(BASE).json(), caller.get(BASE).json()
    assert first == second and len(source.calls) == 1


def test_varying_the_window_never_multiplies_flow_store_reads() -> None:
    source = FakeSource(totals(growing(120)))
    shared = caches(reads=300.0)
    app.dependency_overrides[forecast_routes.get_history_source] = lambda: source
    app.dependency_overrides[forecast_routes.get_forecast_caches] = lambda: shared
    caller = Caller("network_engineer")
    for horizon in (1, 7, 14, 30):
        for history in (14, 56, 120):
            assert caller.get(BASE, horizon_days=horizon, history_days=history).status_code == 200
    assert len(source.calls) == 1  # one fixed read behind every window


def test_a_failed_read_is_not_kept_as_a_result() -> None:
    source = FakeSource(error=RuntimeError("down"))
    app.dependency_overrides[forecast_routes.get_history_source] = lambda: source
    shared = caches(reads=300.0)
    app.dependency_overrides[forecast_routes.get_forecast_caches] = lambda: shared
    caller = Caller("network_engineer")
    assert caller.get(BASE).json()["state"] == "unknown"
    assert caller.get(BASE).json()["state"] == "unknown"
    assert len(source.calls) == 2  # no negative cache here (ttl 0): each request tries again


def test_a_failing_store_is_not_hammered_while_it_is_down() -> None:
    source = FakeSource(error=RuntimeError("down"))
    app.dependency_overrides[forecast_routes.get_history_source] = lambda: source
    shared = caches(failures=30.0)
    app.dependency_overrides[forecast_routes.get_forecast_caches] = lambda: shared
    caller = Caller("network_engineer")
    states = [caller.get(BASE).json()["state"] for _ in range(4)]
    assert states == ["unknown"] * 4 and len(source.calls) == 1


@pytest.mark.asyncio
async def test_waiters_behind_a_failed_read_fail_fast_instead_of_reading_in_turn() -> None:
    import asyncio
    from datetime import date
    from types import SimpleNamespace

    from netsight_api.rbac import Identity, PrincipalKind

    class Slow(FakeSource):
        async def daily_totals(self, *, first_day: date, end_day: date):  # type: ignore[override]
            self.calls.append((first_day, end_day))
            await asyncio.sleep(0.05)
            raise RuntimeError("down")

    source = Slow()
    shared = caches(failures=30.0)
    request = SimpleNamespace()
    people = [Identity(f"user-{i}", frozenset({"auditor"}), PrincipalKind.HUMAN) for i in range(3)]
    results = await asyncio.gather(
        *[
            forecast_routes.read_totals(
                request,  # type: ignore[arg-type]
                who,
                "forecast.capacity.read",
                source=source,
                last_day=date(2026, 10, 17),
                caches=shared,
            )
            for who in people
        ]
    )
    assert results == [None, None, None] and len(source.calls) == 1


# --- audit -----------------------------------------------------------------------------------------------


def test_reads_denials_and_refusals_are_audited_without_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Caller("network_engineer").get(BASE, horizon_days=7)
        Caller("technician").get(EXPORT)
        Caller("network_engineer").get(BASE, horizon_days="zz")
    records = audit_records(caplog)
    read = next(
        r for r in records if r["action"] == "forecast.capacity.read" and r["outcome"] == "success"
    )
    assert read["state"] == "ok" and read["horizon_days"] == 7
    assert any(
        r["action"] == "forecast.capacity.export" and r["outcome"] == "denied" for r in records
    )
    assert any(r["outcome"] == "failure" and r.get("reason") == "invalid-request" for r in records)
    assert "zz" not in str(records)


# --- the export (the capacity report) --------------------------------------------------------------------------


def rows(response: Any) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(response.text)))


def test_the_export_is_csv_with_labelled_measured_and_forecast_rows() -> None:
    response = Caller("auditor").get(EXPORT, horizon_days=7, history_days=40)
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="netsight-capacity-forecast.csv"'
    )
    table = rows(response)
    kinds = [r["kind"] for r in table if r["series_id"] == "traffic-volume"]
    assert kinds.count("measured") == 40 and kinds.count("forecast") == 7
    forecast = next(r for r in table if r["kind"] == "forecast")
    assert (
        forecast["lower"] != "" and forecast["upper"] != "" and forecast["method"] == "linear-trend"
    )
    measured = next(r for r in table if r["kind"] == "measured")
    assert measured["lower"] == "" and measured["upper"] == ""
    assert table[-1]["kind"] == "notice" and "not measurement" in table[-1]["note"]


def test_the_export_of_a_series_without_data_says_why_and_has_no_values() -> None:
    use(None)
    table = rows(Caller("auditor").get(EXPORT))
    assert {r["kind"] for r in table} == {"state", "notice"}
    state = next(r for r in table if r["series_id"] == "traffic-volume")
    assert state["state"] == "not-connected" and state["value"] == "" and state["day"] == ""


def test_the_export_is_audited_with_counts_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Caller("auditor").get(EXPORT, history_days=30)
    record = next(r for r in audit_records(caplog) if r["action"] == "forecast.capacity.export")
    assert record["outcome"] == "success" and record["state"] == "ok"
    assert record["row_count"] > 0
