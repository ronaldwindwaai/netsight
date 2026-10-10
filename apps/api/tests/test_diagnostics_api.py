"""/api/v1/diagnostics: RBAC, CSRF, rate limit, states, contract and audit (S7-2).

Authentication goes through real server-side sessions (cookie plus CSRF token), so the session,
CSRF and origin stack is exercised rather than bypassed. Probes are fakes: a test never opens a
network connection from the API, and the deny-by-default paths are proven in ``test_blackbox_adapter``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from alerting_support import ALL_ROLES, Caller, audit_records
from fastapi.testclient import TestClient

from netsight_api import diagnostic_routes
from netsight_api.adapters.blackbox import get_optional_blackbox_client
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.diagnostics import Observation
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind

DIAGNOSTICS = "/api/v1/diagnostics"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
_BLACKBOX_ENV = ("BLACKBOX_ALLOWED_TARGETS", "BLACKBOX_VANTAGE", "BLACKBOX_TIMEOUT_SECONDS")


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "target": "srv-db-01",
        "symptom": "Intermittent timeouts",
        "vantage": "internal",
        "requested_checks": ["icmp", "tcp"],
    }
    body.update(overrides)
    return body


class FakeProbeClient:
    """A probe source with no I/O: outcomes are declared, calls are recorded.

    ``vantages`` lets one run mix an external and an internal observation, which a single request
    vantage cannot express but the contract's per-check vantage can.
    """

    def __init__(
        self,
        outcomes: dict[str, tuple[str, int | None]],
        *,
        raises: bool = False,
        vantages: dict[str, str] | None = None,
    ) -> None:
        self._outcomes = outcomes
        self._raises = raises
        self._vantages = vantages or {}
        self.calls: list[tuple[str, str, str | None]] = []

    async def probe(self, *, kind: str, target: str, vantage: str | None) -> Observation:
        self.calls.append((kind, target, vantage))
        if self._raises:
            raise RuntimeError("probe backend exploded")
        status, port = self._outcomes.get(kind, ("unknown", None))
        return Observation(
            kind=kind,  # type: ignore[arg-type]
            label=f"{kind} check",
            status=status,  # type: ignore[arg-type]
            vantage=self._vantages.get(kind, vantage),
            port=port,
            detail=None if status != "unknown" else "no data",
            observed_at=NOW,
            evidence_id=f"evidence-{kind}",
        )


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _BLACKBOX_ENV:
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(diagnostic_routes, "_run_limiter", RateLimiter())
    app.dependency_overrides[diagnostic_routes.get_now] = lambda: NOW
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


# --- authentication and RBAC ---------------------------------------------------------------------


def test_anonymous_is_refused() -> None:
    response = TestClient(app).post(DIAGNOSTICS, json=_body())
    assert response.status_code == 401


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_may_start_a_read_only_run(role: str) -> None:
    response = Caller(role).post(DIAGNOSTICS, _body())
    assert response.status_code == 200, response.text
    assert response.json() == {"state": "not-connected", "run": None}


def test_identity_without_the_permission_is_refused() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "nobody", frozenset(), PrincipalKind.HUMAN
    )
    response = Caller("administrator").post(DIAGNOSTICS, _body())
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_missing_csrf_token_is_refused() -> None:
    response = Caller("administrator").post(DIAGNOSTICS, _body(), csrf=None)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


# --- read states ---------------------------------------------------------------------------------


def test_not_connected_when_no_probe_capability_is_configured() -> None:
    body = Caller("administrator").post(DIAGNOSTICS, _body()).json()
    validate("diagnostic_run_response", body)
    assert body == {"state": "not-connected", "run": None}


def test_ok_run_matches_the_contract_and_reports_its_checks() -> None:
    client = FakeProbeClient({"icmp": ("pass", None), "tcp": ("pass", 443)})
    app.dependency_overrides[get_optional_blackbox_client] = lambda: client
    response = Caller("administrator").post(DIAGNOSTICS, _body())
    assert response.status_code == 200, response.text
    body = response.json()
    validate("diagnostic_run_response", body)
    assert body["state"] == "ok"
    run = body["run"]
    assert [check["kind"] for check in run["checks"]] == ["icmp", "tcp"]
    assert run["vantage"] == "internal"
    # A passing round is not a fault: the engine must not name a domain.
    assert run["probable_fault_domain"] is None
    assert run["confidence"] == "unknown"
    assert run["unknowns"]
    assert client.calls == [("icmp", "srv-db-01", "internal"), ("tcp", "srv-db-01", "internal")]


def test_a_failing_external_check_with_internal_success_narrows_the_domain() -> None:
    client = FakeProbeClient(
        {"icmp": ("fail", None), "tcp": ("pass", 443)},
        vantages={"icmp": "internet", "tcp": "internal"},
    )
    app.dependency_overrides[get_optional_blackbox_client] = lambda: client
    body = Caller("administrator").post(
        DIAGNOSTICS, _body(requested_checks=["icmp", "tcp"])
    ).json()
    validate("diagnostic_run_response", body)
    assert body["run"]["probable_fault_domain"] == "firewall"
    assert body["run"]["confidence"] == "low"


def test_the_run_reports_where_the_checks_ran_not_the_requested_vantage() -> None:
    # The client reports a single vantage ("internet") that differs from the requested one
    # ("internal"): provenance must come from the observations, never the request text.
    client = FakeProbeClient(
        {"icmp": ("pass", None), "tcp": ("pass", 443)},
        vantages={"icmp": "internet", "tcp": "internet"},
    )
    app.dependency_overrides[get_optional_blackbox_client] = lambda: client
    body = Caller("administrator").post(DIAGNOSTICS, _body(vantage="internal")).json()
    validate("diagnostic_run_response", body)
    assert body["run"]["vantage"] == "internet"
    assert {check["vantage"] for check in body["run"]["checks"]} == {"internet"}


def test_probe_failure_degrades_to_an_explicit_unknown(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    app.dependency_overrides[get_optional_blackbox_client] = lambda: FakeProbeClient({}, raises=True)
    response = Caller("administrator").post(DIAGNOSTICS, _body())
    assert response.status_code == 200
    assert response.json() == {"state": "unknown", "run": None}
    failed = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"]
    assert failed and failed[-1]["outcome"] == "failure"


def test_target_is_echoed_verbatim_never_interpreted() -> None:
    payload = "<script>alert(1)</script> \u202e {{7*7}}"
    app.dependency_overrides[get_optional_blackbox_client] = lambda: FakeProbeClient(
        {"icmp": ("pass", None)}
    )
    response = Caller("administrator").post(
        DIAGNOSTICS, _body(target=payload, requested_checks=["icmp"])
    )
    assert response.status_code == 200, response.text
    assert response.json()["run"]["target"] == payload


# --- rate limiting and audit ---------------------------------------------------------------------


def test_run_rate_limit_is_enforced() -> None:
    caller = Caller("administrator")
    for _ in range(diagnostic_routes.DIAGNOSTIC_RUN_LIMIT_PER_MINUTE):
        assert caller.post(DIAGNOSTICS, _body()).status_code == 200
    blocked = caller.post(DIAGNOSTICS, _body())
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMITED"


def test_a_successful_run_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    app.dependency_overrides[get_optional_blackbox_client] = lambda: FakeProbeClient(
        {"icmp": ("pass", None)}
    )
    Caller("administrator").post(DIAGNOSTICS, _body(requested_checks=["icmp"]))
    records = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"]
    assert records and records[-1]["outcome"] == "success"
    assert records[-1]["state"] == "ok"


def test_a_refusal_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    Caller("administrator").post(DIAGNOSTICS, _body(), csrf=None)
    records = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"]
    assert records and records[-1]["outcome"] == "denied"
    assert records[-1]["reason"] == "csrf"


# --- OpenAPI -------------------------------------------------------------------------------------


def test_openapi_exposes_exactly_the_diagnostic_operations() -> None:
    paths = app.openapi()["paths"]
    operations = {
        (path, method)
        for path, item in paths.items()
        if path.startswith("/api/v1/diagnostics")
        for method in item
    }
    assert operations == {("/api/v1/diagnostics", "post")}
    assert {"200", "401", "403", "422", "429"} <= set(
        paths["/api/v1/diagnostics"]["post"]["responses"]
    )
