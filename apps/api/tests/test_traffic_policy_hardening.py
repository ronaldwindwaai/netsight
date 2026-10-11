"""Policy hardening from the Step 7 reviews: label comparison, broad ranges, the file read, 24:00, DST.

Every rule fails closed: a label or entry that is not stable under NFKC is unknown (or refuses the
file), a destination allow range wide enough to cover most of the Internet refuses the *whole* file,
and the file is read through one handle so a swap between a size check and a read can not matter.
"""

from __future__ import annotations

import json
import os
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from netsight_api.traffic import policy as policy_module
from netsight_api.traffic.policy import (
    MAX_POLICY_BYTES,
    POLICY_FILE_ENV,
    TrafficPolicy,
    load_policy,
    policy_from_environment,
)

UTC_HOURS = {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "24:00"}


def policy_of(tmp_path: Path, document: Any) -> TrafficPolicy:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document), "utf-8")
    return load_policy(str(path))


def london_hours() -> dict[str, Any]:
    return {"timezone": "Europe/London", "days": ["mon"], "start": "09:00", "end": "17:00"}


# --- labels: casefold only, NFKC-unstable is unknown ---------------------------------------------


def test_labels_compare_by_casefold_only(tmp_path: Path) -> None:
    policy = policy_of(tmp_path, {"version": 1, "applications": {"approved": ["Straße", "Zoom"]}})
    assert policy.application_approval("STRASSE") == "approved"  # casefold: ß folds to ss
    assert policy.application_approval("zoom") == "approved"


@pytest.mark.parametrize("label", ["Ｚoom", "Zo₀m", "ﬁle-share", "Zoom x"])
def test_a_label_that_changes_under_nfkc_is_unknown(tmp_path: Path, label: str) -> None:
    # Compatibility forms (full-width, subscript, ligature, no-break space) must not borrow an
    # approval or a risk that an ASCII look-alike holds.
    document = {
        "version": 1,
        "applications": {
            "approved": ["Zoom", "Zo0m", "zoom x", "file-share"],
            "risk": {"Zoom": "low", "file-share": "high"},
        },
    }
    policy = policy_of(tmp_path, document)
    assert policy.application_approval(label) == "unknown"
    assert policy.application_risk(label) == "unknown"


def test_a_hostname_that_changes_under_nfkc_does_not_match_a_deny_entry(tmp_path: Path) -> None:
    policy = policy_of(tmp_path, {"version": 1, "destinations": {"deny": ["bad.example"]}})
    assert policy.destination_reputation("8.8.8.8", "bad.example", None) == "deny-listed"
    assert policy.destination_reputation("8.8.8.8", "ｂad.example", None) == "unknown"


@pytest.mark.parametrize(
    "document",
    [
        {"version": 1, "applications": {"approved": ["ﬁle"]}},
        {"version": 1, "applications": {"unapproved": ["Ｚoom"]}},
        {"version": 1, "applications": {"risk": {"Ｚoom": "high"}}},
    ],
)
def test_an_entry_that_changes_under_nfkc_invalidates_the_file(
    tmp_path: Path, document: Any
) -> None:
    # Such an entry could never match (labels like it are unknown), so it is refused, not ignored.
    assert policy_of(tmp_path, document).state == "invalid"


# --- overly broad allow ranges ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry", ["0.0.0.0/0", "128.0.0.0/1", "10.0.0.0/7", "::/0", "2000::/3", "2001::/15"]
)
def test_an_overly_broad_allow_range_invalidates_the_whole_file(tmp_path: Path, entry: str) -> None:
    document = {
        "version": 1,
        "applications": {"approved": ["Zoom"]},
        "destinations": {"allow": ["203.0.113.0/24", entry]},
    }
    policy = policy_of(tmp_path, document)
    assert policy.state == "invalid"
    assert policy.application_approval("Zoom") == "unknown"  # half a policy is never applied


@pytest.mark.parametrize(
    "entry", ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/16", "2001:db8::/32"]
)
def test_the_narrowest_broad_boundaries_are_accepted(tmp_path: Path, entry: str) -> None:
    assert policy_of(tmp_path, {"version": 1, "destinations": {"allow": [entry]}}).state == (
        "configured"
    )


def test_a_broad_deny_range_is_allowed(tmp_path: Path) -> None:
    # Denying too much fails safe (a destination is flagged); allowing too much hides one.
    policy = policy_of(tmp_path, {"version": 1, "destinations": {"deny": ["0.0.0.0/0", "::/0"]}})
    assert policy.destination_reputation("8.8.8.8", None, None) == "deny-listed"


# --- one handle for the file -----------------------------------------------------------------------


def test_the_file_is_read_through_one_handle_without_a_separate_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "applications": {"approved": ["Zoom"]}}), "utf-8")

    def forbidden(*_: Any, **__: Any) -> Any:
        raise AssertionError("stat+read race: open the policy file once and fstat the handle")

    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert load_policy(str(path)).state == "configured"
    monkeypatch.setenv(POLICY_FILE_ENV, str(path))
    assert policy_from_environment().application_approval("Zoom") == "approved"


def test_a_file_that_grows_after_the_size_check_is_still_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "grown.json"
    path.write_text(" " * (MAX_POLICY_BYTES + 10), "utf-8")
    real = os.fstat

    def small(fd: int) -> Any:
        found = real(fd)
        return types.SimpleNamespace(
            st_size=10, st_mode=found.st_mode, st_mtime_ns=found.st_mtime_ns
        )

    monkeypatch.setattr(policy_module.os, "fstat", small)
    assert load_policy(str(path)).state == "invalid"


def test_a_non_regular_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1}), "utf-8")
    real = os.fstat

    def fifo(fd: int) -> Any:
        found = real(fd)
        return types.SimpleNamespace(st_size=10, st_mode=0o010644, st_mtime_ns=found.st_mtime_ns)

    monkeypatch.setattr(policy_module.os, "fstat", fifo)
    assert load_policy(str(path)).state == "invalid"


def test_an_edit_during_the_life_of_the_process_is_still_picked_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "applications": {"approved": ["Zoom"]}}), "utf-8")
    monkeypatch.setenv(POLICY_FILE_ENV, str(path))
    assert policy_from_environment().application_approval("Zoom") == "approved"
    path.write_text(json.dumps({"version": 1, "applications": {"unapproved": ["Zoom"]}}), "utf-8")
    assert policy_from_environment().application_approval("Zoom") == "unapproved"
    path.unlink()
    assert policy_from_environment().state == "invalid"


# --- working hours ending at 24:00 -----------------------------------------------------------------


def test_working_hours_may_end_at_the_end_of_the_day(tmp_path: Path) -> None:
    policy = policy_of(tmp_path, {"version": 1, "working_hours": UTC_HOURS})
    monday = datetime(2026, 10, 5, 0, tzinfo=UTC)
    assert policy.working_hours_state == "configured"
    assert policy.outside_working_hours(monday + timedelta(hours=7)) is True
    assert policy.outside_working_hours(monday + timedelta(hours=8)) is False
    assert policy.outside_working_hours(monday + timedelta(hours=22)) is False
    assert policy.outside_working_hours(monday + timedelta(hours=23)) is False  # 23:00-24:00
    assert policy.outside_working_hours(monday + timedelta(hours=24)) is True  # Tuesday 00:00


def test_end_of_day_is_the_policy_zones_midnight_not_utc(tmp_path: Path) -> None:
    hours = {"timezone": "Africa/Johannesburg", "days": ["mon"], "start": "00:00", "end": "24:00"}
    policy = policy_of(tmp_path, {"version": 1, "working_hours": hours})
    # Monday 23:00 local is Monday 21:00 UTC; Tuesday 00:00 local is Monday 22:00 UTC.
    assert policy.outside_working_hours(datetime(2026, 10, 5, 21, tzinfo=UTC)) is False
    assert policy.outside_working_hours(datetime(2026, 10, 5, 22, tzinfo=UTC)) is True


def test_24_00_is_an_end_but_never_a_start(tmp_path: Path) -> None:
    for hours in (
        {**UTC_HOURS, "start": "24:00"},
        {**UTC_HOURS, "end": "24:01"},
        {**UTC_HOURS, "end": "24:30"},
    ):
        assert policy_of(tmp_path, {"version": 1, "working_hours": hours}).state == "invalid"


# --- daylight saving ---------------------------------------------------------------------------------

CLOCKS_FORWARD = datetime(2026, 3, 29, tzinfo=UTC)  # 01:00 UTC: UK summer time begins
CLOCKS_BACK = datetime(2026, 10, 25, tzinfo=UTC)  # UK summer time ends


def test_a_daylight_saving_change_between_two_instants_is_reported(tmp_path: Path) -> None:
    london = policy_of(tmp_path, {"version": 1, "working_hours": london_hours()})
    day = timedelta(days=1)
    assert (
        london.daylight_saving_change(CLOCKS_FORWARD - 10 * day, CLOCKS_FORWARD + 10 * day) is True
    )
    assert london.daylight_saving_change(CLOCKS_FORWARD + day, CLOCKS_FORWARD + 30 * day) is False
    assert london.daylight_saving_change(CLOCKS_FORWARD - 30 * day, CLOCKS_FORWARD - day) is False
    assert london.daylight_saving_change(CLOCKS_BACK - 35 * day, CLOCKS_BACK + day) is True


def test_a_change_inside_a_single_day_is_not_missed(tmp_path: Path) -> None:
    london = policy_of(tmp_path, {"version": 1, "working_hours": london_hours()})
    assert (
        london.daylight_saving_change(CLOCKS_FORWARD, CLOCKS_FORWARD + timedelta(hours=3)) is True
    )


def test_a_zone_without_daylight_saving_never_reports_a_change(tmp_path: Path) -> None:
    hours = {"timezone": "Africa/Johannesburg", "days": ["mon"], "start": "08:00", "end": "17:00"}
    joburg = policy_of(tmp_path, {"version": 1, "working_hours": hours})
    assert joburg.daylight_saving_change(datetime(2026, 1, 1, tzinfo=UTC), CLOCKS_BACK) is False


def test_no_zone_means_daylight_saving_is_not_applicable(tmp_path: Path) -> None:
    without_zone = policy_of(tmp_path, {"version": 1, "applications": {"approved": ["Zoom"]}})
    start, end = datetime(2026, 3, 1, tzinfo=UTC), datetime(2026, 4, 30, tzinfo=UTC)
    assert without_zone.daylight_saving_change(start, end) is None
    assert load_policy(None).daylight_saving_change(start, end) is None
