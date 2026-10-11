"""The operator's severity policy for unknown devices (Step 8c).

Netsight does not decide how serious an unknown device is. The operator says so in one JSON document
(``NETSIGHT_UNKNOWN_DEVICE_POLICY_FILE`` path, or ``NETSIGHT_UNKNOWN_DEVICE_POLICY`` inline) and every
severity traces to an entry in it. No document, or one that does not validate, means the severity is
``unknown`` (fail closed: half a policy is never applied) and no quarantine is ever recommended.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsight_api.unknown_devices.policy import (
    MAX_RULES,
    POLICY_ENV,
    POLICY_FILE_ENV,
    SeverityPolicy,
    load_policy,
)

VALID = {
    "version": 1,
    "default_severity": "medium",
    "rules": [
        {"cidrs": ["10.20.0.0/16"], "severity": "high"},
        {"vlans": [30], "severity": "critical"},
        {"cidrs": ["192.168.50.0/24"], "vlans": [50], "severity": "low"},
    ],
    "quarantine_recommended_at": "high",
}


def inline(document: object) -> SeverityPolicy:
    return load_policy({POLICY_ENV: json.dumps(document)})


def test_no_policy_means_unknown_severity_and_no_recommendation() -> None:
    policy = load_policy({})
    assert policy.state == "not-configured"
    assert policy.decide("10.0.0.1", None) == ("unknown", "no-policy")
    assert policy.recommends_quarantine("critical") is False


def test_the_first_matching_rule_decides() -> None:
    policy = inline(VALID)
    assert policy.state == "configured"
    assert policy.decide("10.20.4.5", None) == ("high", "policy-rule")
    assert policy.decide("10.20.4.5", 30) == ("high", "policy-rule")  # rule order, not severity
    assert policy.decide("172.16.0.1", 30) == ("critical", "policy-rule")


def test_a_rule_matches_on_any_of_its_networks_or_vlans() -> None:
    policy = inline(VALID)
    assert policy.decide("192.168.50.9", None) == ("low", "policy-rule")
    assert policy.decide("172.16.0.1", 50) == ("low", "policy-rule")


def test_a_vlan_rule_never_matches_a_vlan_nobody_observed() -> None:
    policy = inline({"version": 1, "rules": [{"vlans": [30], "severity": "high"}]})
    assert policy.decide("10.0.0.1", None) == ("unknown", "no-policy")


def test_a_rule_does_not_match_an_address_that_was_not_observed() -> None:
    policy = inline({"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"], "severity": "high"}]})
    assert policy.decide(None, None) == ("unknown", "no-policy")


def test_the_default_applies_when_no_rule_does() -> None:
    assert inline(VALID).decide("172.16.0.1", None) == ("medium", "policy-default")


def test_a_policy_without_a_default_leaves_the_rest_unknown() -> None:
    policy = inline({"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"], "severity": "high"}]})
    assert policy.decide("172.16.0.1", None) == ("unknown", "no-policy")


def test_a_default_alone_is_a_valid_policy() -> None:
    assert inline({"version": 1, "default_severity": "low"}).decide("1.2.3.4", None) == (
        "low",
        "policy-default",
    )


def test_ipv6_networks_are_supported() -> None:
    policy = inline({"version": 1, "rules": [{"cidrs": ["2001:db8::/32"], "severity": "high"}]})
    assert policy.decide("2001:db8::5", None) == ("high", "policy-rule")
    assert policy.decide("10.0.0.1", None) == ("unknown", "no-policy")


def test_host_bits_in_a_network_are_tolerated_like_netbox_does() -> None:
    policy = inline({"version": 1, "rules": [{"cidrs": ["10.20.1.5/16"], "severity": "high"}]})
    assert policy.decide("10.20.9.9", None) == ("high", "policy-rule")


@pytest.mark.parametrize(
    ("threshold", "severity", "expected"),
    [
        ("high", "low", False),
        ("high", "medium", False),
        ("high", "high", True),
        ("high", "critical", True),
        ("critical", "high", False),
        ("critical", "critical", True),
        ("low", "low", True),
    ],
)
def test_quarantine_is_recommended_from_the_operators_threshold_up(
    threshold: str, severity: str, expected: bool
) -> None:
    policy = inline(
        {"version": 1, "default_severity": "low", "quarantine_recommended_at": threshold}
    )
    assert policy.recommends_quarantine(severity) is expected  # type: ignore[arg-type]


def test_an_unknown_severity_is_never_a_reason_to_recommend_anything() -> None:
    assert inline(VALID).recommends_quarantine("unknown") is False


def test_without_a_threshold_nothing_is_recommended() -> None:
    policy = inline({"version": 1, "default_severity": "critical"})
    assert policy.recommends_quarantine("critical") is False


@pytest.mark.parametrize(
    "document",
    [
        [],
        "text",
        {"rules": []},
        {"version": 2},
        {"version": 1, "extra": 1},
        {"version": 1, "default_severity": "severe"},
        {"version": 1, "default_severity": "unknown"},
        {"version": 1, "quarantine_recommended_at": "unknown"},
        {"version": 1, "quarantine_recommended_at": "extreme"},
        {"version": 1, "rules": "no"},
        {"version": 1, "rules": [{"severity": "high"}]},
        {"version": 1, "rules": [{"cidrs": [], "severity": "high"}]},
        {"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"]}]},
        {"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"], "severity": "unknown"}]},
        {"version": 1, "rules": [{"cidrs": ["not-a-network"], "severity": "high"}]},
        {"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"], "severity": "high", "x": 1}]},
        {"version": 1, "rules": [{"vlans": [0], "severity": "high"}]},
        {"version": 1, "rules": [{"vlans": [4095], "severity": "high"}]},
        {"version": 1, "rules": [{"vlans": ["20"], "severity": "high"}]},
        {"version": 1, "rules": [{"vlans": [True], "severity": "high"}]},
        {"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"] * 51, "severity": "high"}]},
        {"version": 1, "rules": [{"cidrs": ["10.0.0.0/8"], "severity": "high"}] * (MAX_RULES + 1)},
    ],
)
def test_an_invalid_policy_is_invalid_and_decides_nothing(document: object) -> None:
    policy = inline(document)
    assert policy.state == "invalid"
    assert policy.decide("10.20.4.5", 30) == ("unknown", "no-policy")
    assert policy.recommends_quarantine("critical") is False


def test_half_a_policy_is_never_applied() -> None:
    document = {
        "version": 1,
        "default_severity": "high",
        "rules": [{"cidrs": ["bad"], "severity": "low"}],
    }
    policy = inline(document)
    assert policy.state == "invalid" and policy.decide("1.2.3.4", None) == ("unknown", "no-policy")


def test_duplicate_keys_and_malformed_json_are_invalid() -> None:
    assert load_policy({POLICY_ENV: '{"version": 1, "version": 1}'}).state == "invalid"
    assert load_policy({POLICY_ENV: "{nope"}).state == "invalid"


def test_a_file_is_read_and_validated(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(VALID), encoding="utf-8")
    policy = load_policy({POLICY_FILE_ENV: str(path)})
    assert policy.state == "configured" and policy.decide("10.20.1.1", None)[0] == "high"


def test_a_missing_directory_or_oversized_file_is_invalid(tmp_path: Path) -> None:
    assert load_policy({POLICY_FILE_ENV: str(tmp_path / "missing.json")}).state == "invalid"
    assert load_policy({POLICY_FILE_ENV: str(tmp_path)}).state == "invalid"
    big = tmp_path / "big.json"
    big.write_text(" " * (70 * 1024) + json.dumps(VALID), encoding="utf-8")
    assert load_policy({POLICY_FILE_ENV: str(big)}).state == "invalid"


def test_a_file_and_inline_json_together_are_ambiguous() -> None:
    env = {POLICY_FILE_ENV: "x.json", POLICY_ENV: json.dumps(VALID)}
    assert load_policy(env).state == "invalid"


def test_a_hostile_address_is_just_no_match() -> None:
    assert inline(VALID).decide("<script>", None) == ("medium", "policy-default")
