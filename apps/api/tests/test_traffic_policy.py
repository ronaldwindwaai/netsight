"""The operator traffic policy: application approval and risk, destination allow/deny, working hours.

Nothing here classifies on its own. Every classification comes from an explicit entry in the
operator's file; no file (or a file that does not validate) means ``unknown``, never a guess.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from netsight_api.traffic.policy import (
    MAX_POLICY_BYTES,
    POLICY_FILE_ENV,
    TrafficPolicy,
    load_policy,
    policy_from_environment,
)


def write(tmp_path: Path, document: Any, name: str = "policy.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(document) if not isinstance(document, str) else document, "utf-8")
    return str(path)


FULL = {
    "version": 1,
    "working_hours": {
        "timezone": "Africa/Johannesburg",
        "days": ["mon", "tue", "wed", "thu", "fri"],
        "start": "08:00",
        "end": "17:00",
    },
    "applications": {
        "approved": ["Microsoft 365", "Zoom"],
        "unapproved": ["BitTorrent"],
        "risk": {"BitTorrent": "high", "Zoom": "low", "Dropbox": "medium"},
    },
    "destinations": {
        "allow": ["203.0.113.0/24", "AS64500", "198.51.100.7"],
        "deny": ["bad.example", "192.0.2.0/28", "AS64666", "2001:db8::bad"],
    },
}


# --- no policy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, "", "   "])
def test_no_file_means_not_configured_and_everything_unknown(path: str | None) -> None:
    policy = load_policy(path)
    assert policy.state == "not-configured"
    assert policy.working_hours_state == "not-configured"
    assert policy.application_approval("Zoom") == "unknown"
    assert policy.application_risk("Zoom") == "unknown"
    assert policy.destination_reputation("203.0.113.5", None, 64500) == "unknown"
    assert policy.outside_working_hours(datetime(2026, 10, 6, 2, tzinfo=UTC)) is None
    assert policy.timezone_name is None


def test_a_missing_file_is_invalid_not_empty(tmp_path: Path) -> None:
    policy = load_policy(str(tmp_path / "absent.json"))
    assert policy.state == "invalid"
    assert policy.working_hours_state == "invalid"
    assert policy.application_approval("Zoom") == "unknown"


# --- applications ------------------------------------------------------------------------------


def test_applications_are_classified_only_by_listed_names(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    assert policy.state == "configured"
    assert policy.application_approval("Microsoft 365") == "approved"
    assert policy.application_approval("BitTorrent") == "unapproved"
    assert policy.application_approval("Slack") == "unknown"  # not listed: not "unapproved"
    assert policy.application_risk("BitTorrent") == "high"
    assert policy.application_risk("Dropbox") == "medium"
    assert policy.application_risk("Microsoft 365") == "unknown"  # approved is not "low risk"


def test_application_names_match_case_insensitively_and_exactly(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    assert policy.application_approval("microsoft 365") == "approved"
    assert policy.application_approval("  ZOOM ") == "approved"
    assert policy.application_approval("Microsoft 365 Admin") == "unknown"  # no prefix matching
    assert policy.application_approval("") == "unknown"


def test_hostile_application_text_is_never_interpreted(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    hostile = "<script>alert(1)</script> approved"
    assert policy.application_approval(hostile) == "unknown"
    assert policy.application_risk(hostile) == "unknown"


def test_an_application_both_approved_and_unapproved_invalidates_the_file(tmp_path: Path) -> None:
    document = {"version": 1, "applications": {"approved": ["Zoom"], "unapproved": ["zoom"]}}
    assert load_policy(write(tmp_path, document)).state == "invalid"


@pytest.mark.parametrize("risk", ["critical", "", None, 3])
def test_an_unknown_risk_level_invalidates_the_file(tmp_path: Path, risk: Any) -> None:
    document = {"version": 1, "applications": {"risk": {"Zoom": risk}}}
    assert load_policy(write(tmp_path, document)).state == "invalid"


# --- destinations ------------------------------------------------------------------------------


def test_destinations_match_address_range_asn_and_domain(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    assert policy.destination_reputation("203.0.113.77", None, None) == "allow-listed"
    assert policy.destination_reputation("198.51.100.7", None, None) == "allow-listed"
    assert policy.destination_reputation("8.8.8.8", None, 64500) == "allow-listed"
    assert policy.destination_reputation("192.0.2.5", None, None) == "deny-listed"
    assert policy.destination_reputation("8.8.8.8", None, 64666) == "deny-listed"
    assert policy.destination_reputation("8.8.8.8", "bad.example", None) == "deny-listed"
    assert policy.destination_reputation("8.8.8.8", "cdn.bad.example", None) == "deny-listed"
    assert policy.destination_reputation("2001:db8::bad", None, None) == "deny-listed"
    assert policy.destination_reputation("8.8.8.8", "good.example", 15169) == "unknown"
    assert policy.destination_reputation(None, None, None) == "unknown"


def test_a_domain_must_match_on_a_label_boundary(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    assert policy.destination_reputation("8.8.8.8", "notbad.example", None) == "unknown"
    assert policy.destination_reputation("8.8.8.8", "bad.example.evil.test", None) == "unknown"
    assert policy.destination_reputation("8.8.8.8", "BAD.EXAMPLE.", None) == "deny-listed"


def test_deny_wins_over_allow(tmp_path: Path) -> None:
    document = {
        "version": 1,
        "destinations": {"allow": ["203.0.113.0/24"], "deny": ["203.0.113.9"]},
    }
    policy = load_policy(write(tmp_path, document))
    assert policy.destination_reputation("203.0.113.9", None, None) == "deny-listed"
    assert policy.destination_reputation("203.0.113.10", None, None) == "allow-listed"


def test_a_hostname_cannot_earn_an_allow_listing(tmp_path: Path) -> None:
    # The hostname is reverse DNS, which the address owner controls: it may deny but never allow.
    document = {"version": 1, "destinations": {"allow": ["trusted.example"]}}
    assert load_policy(write(tmp_path, document)).state == "invalid"
    attack = {"version": 1, "destinations": {"allow": ["AS64500"]}}
    policy = load_policy(write(tmp_path, attack))
    assert policy.destination_reputation("8.8.8.8", "AS64500", None) == "unknown"
    assert policy.destination_reputation("8.8.8.8", "as64500.example", None) == "unknown"


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "http://evil.example",
        "bad.example/path",
        "999.1.1.1",
        "AS",
        "ASx",
        "AS0",
        "AS4294967296",
        "10.0.0.0/33",
        "a b",
        "-bad.example",
        "*.example.com",
        "x" * 300,
    ],
)
def test_a_malformed_destination_entry_invalidates_the_file(tmp_path: Path, entry: str) -> None:
    document = {"version": 1, "destinations": {"deny": [entry]}}
    assert load_policy(write(tmp_path, document)).state == "invalid"


# --- working hours -----------------------------------------------------------------------------


def test_working_hours_are_decided_in_the_configured_zone(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    assert policy.working_hours_state == "configured"
    assert policy.timezone_name == "Africa/Johannesburg"
    # Johannesburg is UTC+2 all year: Tuesday 2026-10-06 08:00 local is 06:00 UTC.
    inside = datetime(2026, 10, 6, 6, 0, tzinfo=UTC)
    assert policy.outside_working_hours(inside) is False
    assert policy.outside_working_hours(inside - timedelta(hours=1)) is True  # 07:00 local
    assert policy.outside_working_hours(inside + timedelta(hours=8)) is False  # 16:00 local
    assert policy.outside_working_hours(inside + timedelta(hours=9)) is True  # 17:00 local
    assert policy.outside_working_hours(datetime(2026, 10, 10, 8, tzinfo=UTC)) is True  # Saturday


def test_a_bucket_not_wholly_inside_working_hours_counts_as_outside(tmp_path: Path) -> None:
    document = {
        "version": 1,
        "working_hours": {"timezone": "UTC", "days": ["mon"], "start": "08:30", "end": "17:00"},
    }
    policy = load_policy(write(tmp_path, document))
    monday = datetime(2026, 10, 5, 8, tzinfo=UTC)
    assert policy.outside_working_hours(monday) is True  # 08:00-09:00 starts before 08:30
    assert policy.outside_working_hours(monday + timedelta(hours=1)) is False
    assert policy.outside_working_hours(monday + timedelta(hours=8)) is False  # 16:00-17:00 fits
    assert policy.outside_working_hours(monday + timedelta(hours=9)) is True  # 17:00-18:00


def test_the_last_whole_hour_before_closing_is_inside(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, FULL))
    sixteen_local = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
    assert policy.outside_working_hours(sixteen_local) is False


def test_daylight_saving_is_respected(tmp_path: Path) -> None:
    document = {
        "version": 1,
        "working_hours": {
            "timezone": "Europe/London",
            "days": ["mon", "tue", "wed", "thu", "fri"],
            "start": "09:00",
            "end": "17:00",
        },
    }
    policy = load_policy(write(tmp_path, document))
    # 2026-07-01 is BST (UTC+1): 08:00 UTC is 09:00 local, inside. 2026-12-01 is GMT: 08:00 UTC is 08:00.
    assert policy.outside_working_hours(datetime(2026, 7, 1, 8, tzinfo=UTC)) is False
    assert policy.outside_working_hours(datetime(2026, 12, 1, 8, tzinfo=UTC)) is True


def test_a_policy_without_working_hours_leaves_them_not_configured(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, {"version": 1, "applications": {"approved": ["Zoom"]}}))
    assert policy.state == "configured"
    assert policy.working_hours_state == "not-configured"
    assert policy.outside_working_hours(datetime(2026, 10, 6, 2, tzinfo=UTC)) is None


@pytest.mark.parametrize(
    "working_hours",
    [
        {"timezone": "Mars/Olympus", "days": ["mon"], "start": "08:00", "end": "17:00"},
        {"timezone": "../../etc/passwd", "days": ["mon"], "start": "08:00", "end": "17:00"},
        {"timezone": "UTC", "days": [], "start": "08:00", "end": "17:00"},
        {"timezone": "UTC", "days": ["funday"], "start": "08:00", "end": "17:00"},
        {"timezone": "UTC", "days": ["mon", "mon"], "start": "08:00", "end": "17:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "17:00", "end": "08:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "08:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "8am", "end": "17:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "24:00", "end": "24:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "24:30"},
        {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "25:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "08:00"},
        {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "17:00", "extra": 1},
    ],
)
def test_invalid_working_hours_invalidate_the_file(tmp_path: Path, working_hours: Any) -> None:
    policy = load_policy(write(tmp_path, {"version": 1, "working_hours": working_hours}))
    assert policy.state == "invalid"
    assert policy.working_hours_state == "invalid"
    assert policy.outside_working_hours(datetime(2026, 10, 6, 6, tzinfo=UTC)) is None
    assert policy.timezone_name is None


# --- the file itself -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        "not json",
        "[]",
        '"text"',
        "null",
        {"version": 2},
        {},
        {"version": 1, "surprise": True},
        {"version": 1, "applications": {"approved": "Zoom"}},
        {"version": 1, "applications": {"approved": [1]}},
        {"version": 1, "applications": {"approved": [""]}},
        {"version": 1, "applications": {"approved": ["a\u0000b"]}},
        {"version": 1, "applications": {"nope": []}},
        {"version": 1, "destinations": {"allow": {}}},
        {"version": 1, "destinations": {"allow": ["AS1"] * 1001}},
        {"version": True},
    ],
)
def test_a_document_that_does_not_validate_is_invalid_and_classifies_nothing(
    tmp_path: Path, document: Any
) -> None:
    policy = load_policy(write(tmp_path, document))
    assert policy.state == "invalid"
    assert policy.application_approval("Zoom") == "unknown"
    assert policy.destination_reputation("203.0.113.9", None, 64500) == "unknown"


def test_an_oversize_file_is_refused_without_being_parsed(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text(" " * (MAX_POLICY_BYTES + 1), "utf-8")
    assert load_policy(str(path)).state == "invalid"


def test_a_directory_or_unreadable_path_is_invalid(tmp_path: Path) -> None:
    assert load_policy(str(tmp_path)).state == "invalid"


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    raw = '{"version": 1, "applications": {"approved": ["Zoom"]}, "applications": {"approved": []}}'
    assert load_policy(write(tmp_path, raw)).state == "invalid"


def test_the_policy_is_immutable() -> None:
    policy = load_policy(None)
    with pytest.raises(AttributeError):
        policy.state = "configured"  # type: ignore[misc]


# --- environment ---------------------------------------------------------------------------------


def test_the_environment_variable_names_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(POLICY_FILE_ENV, write(tmp_path, FULL))
    assert policy_from_environment().state == "configured"
    monkeypatch.delenv(POLICY_FILE_ENV)
    assert policy_from_environment().state == "not-configured"


def test_an_edited_file_is_picked_up_without_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path, {"version": 1, "applications": {"approved": ["Zoom"]}})
    monkeypatch.setenv(POLICY_FILE_ENV, path)
    first = policy_from_environment()
    assert first.application_approval("Zoom") == "approved"
    Path(path).write_text(
        json.dumps({"version": 1, "applications": {"unapproved": ["Zoom"]}, "x": 1}), "utf-8"
    )
    assert policy_from_environment().state == "invalid"
    Path(path).write_text(
        json.dumps({"version": 1, "applications": {"unapproved": ["Zoom"]}}), "utf-8"
    )
    assert policy_from_environment().application_approval("Zoom") == "unapproved"


def test_an_unchanged_file_is_read_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(POLICY_FILE_ENV, write(tmp_path, FULL))
    assert policy_from_environment() is policy_from_environment()


def test_the_type_is_exported() -> None:
    assert isinstance(load_policy(None), TrafficPolicy)
