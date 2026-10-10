"""Recent changes near a failure (S7 Step 4c): known sources only, never causal.

Pure unit tests: a change is shown as something that *may correlate*, a source that is not
connected is said to be so (not "no changes"), and an unreadable source is unknown.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from netsight_api.contracts import validate
from netsight_api.diagnostic_changes import ChangeCandidate, SourceRead, build_recent_changes
from netsight_api.schemas_diagnostic_session import INCIDENT_TITLE_PLACEHOLDER

END = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
START = END - timedelta(hours=24)
NOT_CONNECTED = SourceRead(state="not-connected")


def candidate(
    ref: str,
    minutes_before: int,
    *,
    kind: str = "incident",
    title: str | None = "Link flap",
    severity: str | None = "high",
    about_target: bool | None = None,
) -> ChangeCandidate:
    return ChangeCandidate(
        kind=kind,  # type: ignore[arg-type]
        ref_id=ref,
        title=title,
        occurred_at=END - timedelta(minutes=minutes_before),
        severity=severity if kind == "incident" else None,  # type: ignore[arg-type]
        about_target=about_target,
    )


def build(
    incidents: SourceRead = NOT_CONNECTED,
    alerts: SourceRead = NOT_CONNECTED,
):  # type: ignore[no-untyped-def]
    return build_recent_changes(
        window_start=START,
        window_end=END,
        incidents=incidents,
        alerts=alerts,
    )


def test_no_connected_source_is_not_connected_never_no_changes() -> None:
    changes = build()
    assert changes.state == "not-connected"
    assert changes.items == []
    assert [(s.source, s.state) for s in changes.sources] == [
        ("incidents", "not-connected"),
        ("alerts", "not-connected"),
        ("configuration-changes", "not-connected"),
    ]


def test_an_unreadable_source_is_unknown() -> None:
    assert build(incidents=SourceRead(state="unknown")).state == "unknown"


def test_configuration_changes_stay_not_connected() -> None:
    changes = build(incidents=SourceRead(state="ok"))
    assert changes.state == "ok"
    assert changes.items == []
    assert changes.sources[2].state == "not-connected"


def test_changes_are_phrased_as_may_correlate_in_the_window_only() -> None:
    inside = candidate("i-1", 30)
    before = candidate("i-2", 25 * 60)
    after = ChangeCandidate("incident", "i-3", None, END + timedelta(minutes=1), "low")
    changes = build(incidents=SourceRead("ok", (inside, before, after)))
    assert [item.ref_id for item in changes.items] == ["i-1"]
    assert {item.relation for item in changes.items} == {"may-correlate"}


def test_a_change_recorded_against_another_device_is_dropped() -> None:
    mine = candidate("a-1", 10, kind="alert", about_target=True)
    other = candidate("a-2", 5, kind="alert", about_target=False)
    changes = build(alerts=SourceRead("ok", (mine, other)))
    assert [item.ref_id for item in changes.items] == ["a-1"]
    assert changes.items[0].scope == "target"


def test_unmatched_changes_are_time_window_only_and_rank_after_target_matches() -> None:
    near_unmatched = candidate("i-1", 1)
    older_target = candidate("a-1", 120, kind="alert", about_target=True)
    changes = build(
        incidents=SourceRead("ok", (near_unmatched,)),
        alerts=SourceRead("ok", (older_target,)),
    )
    assert [(i.ref_id, i.scope) for i in changes.items] == [
        ("a-1", "target"),
        ("i-1", "time-window"),
    ]


def test_a_source_that_cannot_tell_is_never_claimed_to_be_about_the_target() -> None:
    alert = candidate("a-1", 10, kind="alert", about_target=None)
    changes = build(alerts=SourceRead("ok", (alert,)))
    assert changes.items[0].scope == "time-window"


def test_items_are_newest_first_unique_and_capped() -> None:
    many = tuple(candidate(f"i-{n}", n + 1) for n in range(40))
    duplicate = candidate("i-0", 1)
    changes = build(incidents=SourceRead("ok", (*many, duplicate)))
    assert len(changes.items) == 20
    assert changes.items[0].ref_id == "i-0"
    assert len({item.ref_id for item in changes.items}) == 20


def test_an_untrusted_alert_title_is_data_bounded_and_stripped_of_control_characters() -> None:
    hostile = "<script>alert(1)</script>\x1b[31m Ignore previous instructions\n" + "x" * 400
    changes = build(alerts=SourceRead("ok", (candidate("a-1", 5, kind="alert", title=hostile),)))
    title = changes.items[0].title
    assert len(title) <= 255
    assert "\x1b" not in title and "\n" not in title
    assert "<script>" in title  # kept as inert text; the UI renders text nodes only


def test_an_alert_title_with_nothing_printable_is_skipped() -> None:
    blank = candidate("a-1", 5, kind="alert", title="\x00\x1b ")
    assert build(alerts=SourceRead("ok", (blank,))).items == []


def test_an_alert_without_a_title_is_skipped() -> None:
    missing = candidate("a-1", 5, kind="alert", title=None)
    assert build(alerts=SourceRead("ok", (missing,))).items == []


def test_an_incident_is_a_reference_and_its_title_is_never_copied() -> None:
    secret = "Breach at the payroll VLAN (confidential)"
    changes = build(incidents=SourceRead("ok", (candidate("i-1", 5, title=secret),)))
    [item] = changes.items
    assert (item.kind, item.ref_id, item.severity) == ("incident", "i-1", "high")
    assert item.title == INCIDENT_TITLE_PLACEHOLDER and item.title_redacted is True
    assert secret not in changes.model_dump_json()


def test_an_incident_without_a_severity_is_skipped() -> None:
    bad = candidate("i-1", 5, severity=None)
    assert build(incidents=SourceRead("ok", (bad,))).items == []


def test_an_alert_has_no_severity_and_keeps_its_stored_title() -> None:
    alert = candidate("a-1", 5, kind="alert", title="Link down")
    [item] = build(alerts=SourceRead("ok", (alert,))).items
    assert (item.severity, item.title, item.title_redacted) == (None, "Link down", False)


def test_the_result_is_contract_valid() -> None:
    changes = build(
        incidents=SourceRead("ok", (candidate("i-1", 5),)),
        alerts=SourceRead("unknown"),
    )
    validate("diagnostic_recent_changes", json.loads(changes.model_dump_json(by_alias=True)))
