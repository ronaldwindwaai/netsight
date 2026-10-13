"""The audit trail of the traffic routes: successful reads, rejected input and endpoint fingerprints.

A record names the actor, the action, the outcome, a static reason, counts and the *names* of the
filters used. It never carries a value: no address, application, destination, person or policy name.
The single, optional exception is a keyed fingerprint of an endpoint-level filter value on a
detail-tier lookup, so an auditor can ask who looked up a given address without the trail holding it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
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
    first_seen,
    inputs,
    make_application,
    make_destination,
    spike_inputs,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.traffic import audit_trail, cohort, guards
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.filters import FlowFilterSet
from netsight_api.traffic.policy import POLICY_FILE_ENV

FLOWS = "/api/v1/traffic/flows"
APPS = "/api/v1/traffic/applications"
DESTS = "/api/v1/traffic/destinations"
ANOMS = "/api/v1/traffic/anomalies"
ACTIONS = {
    APPS: "traffic.applications.read",
    DESTS: "traffic.destinations.read",
    ANOMS: "traffic.anomalies.read",
    FLOWS: "traffic.flows.read",
}
HOUR = {"from": "2026-10-11T11:00:00Z", "to": "2026-10-11T12:00:00Z"}
KEY = "audit-filter-key-0123456789abcdef0123456789"


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "CLICKHOUSE_DSN",
        POLICY_FILE_ENV,
        cohort.MIN_COHORT_ENV,
        audit_trail.FINGERPRINT_ENV,
        audit_trail.FILTER_KEY_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    audit_trail.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_now] = lambda: NOW
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: TtlCache()
    app.dependency_overrides[traffic_routes.get_identity_service] = lambda: None
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: FakeSource(
        applications=applications_read([make_application(application="SecretApp")]),
        destinations=destinations_read([make_destination(address="203.0.113.77")]),
        inputs=spike_inputs(NOW.replace(hour=11)),
    )
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def records(caplog: pytest.LogCaptureFixture, action: str) -> list[dict[str, Any]]:
    return [r for r in audit_records(caplog) if r["action"] == action]


def get(role: str, path: str, **params: Any) -> Any:
    window = HOUR if path == ANOMS else WINDOW
    return Caller(role).get(path, **{**window, **params})


# --- successful reads ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["administrator", "management"])
@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_a_successful_read_is_audited_with_counts_and_no_values(
    caplog: pytest.LogCaptureFixture, role: str, path: str
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert get(role, path).status_code == 200
    (record,) = records(caplog, ACTIONS[path])
    assert record["outcome"] == "success" and record["actor_id"]
    assert record["state"] == "ok"
    assert record["tier"] == ("detail" if role == "administrator" else "aggregate")
    assert record["cohort"] in {"not-applied", "sufficient", "too-few-sources"}
    assert record["window_seconds"] == (3600 if path == ANOMS else 43200)
    text = json.dumps(record)
    for value in ("SecretApp", "203.0.113.77", "198.51.100", "Microsoft"):
        assert value not in text


def test_list_audits_carry_the_row_count_and_the_policy_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        get("administrator", APPS)
        get("administrator", DESTS)
    for path in (APPS, DESTS):
        (record,) = records(caplog, ACTIONS[path])
        assert record["row_count"] == 1 and record["policy"] == "not-configured"


def test_the_anomaly_audit_carries_counts_and_the_daylight_saving_flag(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert get("administrator", ANOMS).status_code == 200
    (record,) = records(caplog, ACTIONS[ANOMS])
    assert record["row_count"] == 1 and record["first_seen_count"] == 0
    assert record["evaluation"] == "evaluated" and record["daylight_saving"] == "not-applicable"


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_an_unknown_state_is_audited_as_a_failure(
    caplog: pytest.LogCaptureFixture, path: str
) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: FakeSource(
        error=RuntimeError("boom")
    )
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert get("administrator", path).status_code == 200
    (record,) = records(caplog, ACTIONS[path])
    assert record["outcome"] == "failure" and record["state"] == "unknown"


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_not_connected_is_audited_as_a_success(caplog: pytest.LogCaptureFixture, path: str) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: None
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        get("administrator", path)
    (record,) = records(caplog, ACTIONS[path])
    assert record["outcome"] == "success" and record["state"] == "not-connected"
    assert record["cohort"] == "not-applied"


def test_first_seen_withholding_is_visible_in_the_anomaly_audit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    base = spike_inputs(NOW.replace(hour=11))
    few = inputs(hourly_total=base.hourly_total, first_seen=(first_seen(endpoints=1),))
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: FakeSource(inputs=few)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        get("management", ANOMS)
    (record,) = records(caplog, ACTIONS[ANOMS])
    assert record["cohort"] == "too-few-sources" and record["first_seen_count"] == 0


# --- rejected input -------------------------------------------------------------------------------------------


REJECTED = [
    ({"source_ip": "10.0.0.1"}, "unknown-parameter"),
    ({"sort": "bytes"}, "unknown-parameter"),
    ({"preset": "12h"}, "invalid-request"),
    ({"from": "2026-10-11T00:00:00Z"}, "invalid-window"),
    ({"from": "2026-10-11T12:00:00Z", "to": "2026-10-11T00:00:00Z"}, "invalid-window"),
    ({"from": "2026-01-01T00:00:00Z", "to": "2026-10-11T00:00:00Z"}, "invalid-window"),
    ({"limit": "0"}, "invalid-request"),
    ({"limit": "101"}, "invalid-request"),
]


@pytest.mark.parametrize("path", [APPS, DESTS])
@pytest.mark.parametrize(("params", "reason"), REJECTED)
def test_rejected_list_input_is_audited_with_a_static_reason(
    caplog: pytest.LogCaptureFixture, path: str, params: dict[str, str], reason: str
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("administrator").get(path, **params)
    assert response.status_code == 422
    (record,) = records(caplog, ACTIONS[path])
    assert record["outcome"] == "failure" and record["reason"] == reason
    assert record["actor_id"]
    assert "10.0.0.1" not in json.dumps(record) and "bytes" not in record.get("reason", "")


@pytest.mark.parametrize(
    ("params", "reason"),
    [r for r in REJECTED if r[0] != {"limit": "0"} and r[0] != {"limit": "101"}],
)
def test_rejected_anomaly_input_is_audited_with_a_static_reason(
    caplog: pytest.LogCaptureFixture, params: dict[str, str], reason: str
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("administrator").get(ANOMS, **params)
    assert response.status_code == 422
    (record,) = records(caplog, ACTIONS[ANOMS])
    assert record["outcome"] == "failure" and record["reason"] == reason


def test_a_repeated_parameter_has_its_own_reason(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Caller("administrator").http.get(DESTS + "?preset=1h&preset=6h")
    (record,) = records(caplog, ACTIONS[DESTS])
    assert record["reason"] == "repeated-parameter"


def test_an_over_long_anomaly_window_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("administrator").get(
            ANOMS, **{"from": "2026-10-01T00:00:00Z", "to": "2026-10-11T00:00:00Z"}
        )
    assert response.status_code == 422
    (record,) = records(caplog, ACTIONS[ANOMS])
    assert record["reason"] == "window-too-long"


def test_a_malformed_explorer_request_is_audited_by_fastapi_validation_too(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert Caller("administrator").get(FLOWS, limit="0").status_code == 422
    (record,) = records(caplog, ACTIONS[FLOWS])
    assert record["reason"] == "invalid-request"


def test_a_caller_without_permission_is_denied_before_validation_is_audited(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert Caller("technician").get(APPS, limit="0").status_code == 403
    assert [r["reason"] for r in records(caplog, ACTIONS[APPS])] == ["permission"]


# --- keyed fingerprints of endpoint-level filter values ---------------------------------------------------------------


def expected(name: str, value: str, key: str = KEY) -> str:
    message = b"\x00".join((b"netsight.audit.filter.v1", name.encode(), value.encode()))
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()[:16]


def lookup(
    caplog: pytest.LogCaptureFixture, role: str = "administrator", **params: str
) -> dict[str, Any]:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert Caller(role).get(FLOWS, **WINDOW, **params).status_code == 200
    return records(caplog, ACTIONS[FLOWS])[-1]


def test_a_detail_lookup_carries_a_keyed_fingerprint_of_the_address(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = lookup(
        caplog, source_ip="10.0.0.10", destination_ip="2001:DB8::1", device="edge-1", vlan="20"
    )
    assert record["fp_source_ip"] == expected("source_ip", "10.0.0.10")
    assert record["fp_destination_ip"] == expected(
        "destination_ip", "2001:db8::1"
    )  # canonical form
    assert record["fp_device"] == expected("device", "edge-1")
    assert record["fp_vlan"] == expected("vlan", "20")
    text = json.dumps(record)
    for value in ("10.0.0.10", "2001:db8::1", "edge-1"):
        assert value not in text
    assert record["filters"] == "source_ip,destination_ip,device,vlan"


def test_the_fingerprint_is_stable_and_distinguishes_targets(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    first = lookup(caplog, source_ip="10.0.0.10")
    again = lookup(caplog, source_ip="10.0.0.10")
    other = lookup(caplog, source_ip="10.0.0.11")
    assert first["fp_source_ip"] == again["fp_source_ip"] != other["fp_source_ip"]
    assert len(first["fp_source_ip"]) == 16


def test_the_same_value_under_another_filter_has_another_fingerprint(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = lookup(caplog, source_ip="10.0.0.10", destination_ip="10.0.0.10")
    assert record["fp_source_ip"] != record["fp_destination_ip"]


def test_the_key_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    one = lookup(caplog, source_ip="10.0.0.10")["fp_source_ip"]
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY[::-1])
    two = lookup(caplog, source_ip="10.0.0.10")["fp_source_ip"]
    assert one != two


def test_without_its_own_key_the_identity_key_is_used(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # conftest sets NETSIGHT_IDENTITY_ID_KEY for every test.
    import os

    identity_key = os.environ["NETSIGHT_IDENTITY_ID_KEY"]
    record = lookup(caplog, source_ip="10.0.0.10")
    assert record["fp_source_ip"] == expected("source_ip", "10.0.0.10", identity_key)


def test_the_dedicated_key_wins_over_the_identity_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = lookup(caplog, source_ip="10.0.0.10")
    assert record["fp_source_ip"] == expected("source_ip", "10.0.0.10", KEY)


@pytest.mark.parametrize("setting", ["off", "OFF", "0", "false", "No"])
def test_fingerprints_can_be_switched_off(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, setting: str
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    monkeypatch.setenv(audit_trail.FINGERPRINT_ENV, setting)
    record = lookup(caplog, source_ip="10.0.0.10")
    assert not [key for key in record if key.startswith("fp_")]
    assert record["filters"] == "source_ip"


def test_with_no_usable_key_the_fingerprint_is_omitted_not_degraded_to_a_plain_hash(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("NETSIGHT_IDENTITY_ID_KEY", raising=False)
    record = lookup(caplog, source_ip="10.0.0.10")
    assert not [key for key in record if key.startswith("fp_")]
    plain = hashlib.sha256(b"10.0.0.10").hexdigest()[:16]
    assert plain not in json.dumps(record)
    assert record["outcome"] == "success"  # the read itself is unaffected


def test_a_short_key_is_not_a_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, "too-short")
    monkeypatch.delenv("NETSIGHT_IDENTITY_ID_KEY", raising=False)
    record = lookup(caplog, source_ip="10.0.0.10")
    assert not [key for key in record if key.startswith("fp_")]


def test_the_missing_key_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("NETSIGHT_IDENTITY_ID_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        lookup(caplog, source_ip="10.0.0.10")
        lookup(caplog, source_ip="10.0.0.11")
    notes = [
        r for r in caplog.records if r.name == "netsight_api" and "fingerprint" in r.getMessage()
    ]
    assert len(notes) == 1


def test_a_read_without_an_endpoint_filter_has_no_fingerprint(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = lookup(caplog, application="Zoom", port="443")
    assert not [key for key in record if key.startswith("fp_")]
    assert record["filters"] == "application,port"
    assert "Zoom" not in json.dumps(record)


def test_the_aggregate_tier_never_carries_a_fingerprint(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = lookup(caplog, "management", protocol="tcp")
    assert not [key for key in record if key.startswith("fp_")]
    assert record["tier"] == "aggregate"


def test_fingerprints_are_computed_from_canonical_filters_only() -> None:
    filters = FlowFilterSet(source_ip="10.0.0.10", application="Zoom")
    assert set(audit_trail.filter_fingerprints(filters)) == {"fp_source_ip"}
    assert audit_trail.filter_fingerprints(FlowFilterSet()) == {}


# --- a configured-but-short key is loud, never a silent fallback; denied lookups are fingerprinted --------------


def test_a_short_dedicated_key_is_not_silently_replaced_by_the_identity_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, "too-short-secret")  # set, but under 32
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        record = lookup(caplog, source_ip="10.0.0.10")
        lookup(caplog, source_ip="10.0.0.11")
    assert not [key for key in record if key.startswith("fp_")]  # no fallback to the identity key
    notes = [
        r
        for r in caplog.records
        if r.name == "netsight_api" and audit_trail.FILTER_KEY_ENV in r.getMessage()
    ]
    assert len(notes) == 1  # said once, and says why
    assert "32" in notes[0].getMessage()
    assert "too-short-secret" not in notes[0].getMessage()


def test_an_unset_dedicated_key_still_falls_back_to_the_identity_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, "   ")
    assert "fp_source_ip" in lookup(caplog, source_ip="10.0.0.10")


def denied_lookup(caplog: pytest.LogCaptureFixture, **params: str) -> dict[str, Any]:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert Caller("management").get(FLOWS, **WINDOW, **params).status_code == 403
    return records(caplog, ACTIONS[FLOWS])[-1]


def test_a_denied_endpoint_filter_is_fingerprinted_when_a_key_is_configured(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    record = denied_lookup(caplog, source_ip="10.0.0.10", protocol="tcp")
    assert record["outcome"] == "denied"
    assert record["reason"] == "filter-needs-detail"
    assert record["fp_source_ip"] == expected("source_ip", "10.0.0.10")
    assert "fp_protocol" not in record  # only endpoint-level values are fingerprinted
    assert "10.0.0.10" not in json.dumps(record)


def test_a_denied_endpoint_filter_carries_no_fingerprint_without_a_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("NETSIGHT_IDENTITY_ID_KEY", raising=False)
    record = denied_lookup(caplog, source_ip="10.0.0.10")
    assert record["reason"] == "filter-needs-detail"
    assert not [key for key in record if key.startswith("fp_")]


def test_a_denied_fingerprint_honours_the_off_switch(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(audit_trail.FILTER_KEY_ENV, KEY)
    monkeypatch.setenv(audit_trail.FINGERPRINT_ENV, "off")
    assert not [k for k in denied_lookup(caplog, device="edge-1") if k.startswith("fp_")]
