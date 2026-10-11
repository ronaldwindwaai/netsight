"""Link status and failover derivation (Step 5a): pure rules over source-reported state.

Both are labelled "inferred" in the API. They read only the interface state and the latest probe
round; routing and the gateway are never read, so nothing here claims which link carries traffic.
Silent, stale or unreachable sources contribute no evidence: with nothing current the status is
``unknown``, never ``up``.
"""

from __future__ import annotations

import pytest

from netsight_api.wan.status import failover, link_status


@pytest.mark.parametrize(
    ("oper", "probe", "expected"),
    [
        ("up", "up", "up"),
        ("up", None, "up"),  # no probe evidence: the interface alone says up
        (None, "up", "up"),  # no interface evidence: the probes alone say up
        ("up", "down", "down"),  # link up but upstream unreachable: the Internet is down
        ("down", "up", "down"),
        ("down", None, "down"),
        (None, "down", "down"),
        ("up", "degraded", "degraded"),
        ("dormant", "up", "degraded"),
        ("testing", None, "degraded"),
        ("lowerLayerDown", "up", "down"),
        ("notPresent", None, "down"),
        (None, None, "unknown"),
        ("unknown", None, "unknown"),
        ("unknown", "unknown", "unknown"),
        (None, "unknown", "unknown"),
    ],
)
def test_status_combines_only_current_evidence(
    oper: str | None, probe: str | None, expected: str
) -> None:
    assert link_status(oper, probe) == expected


def test_the_worst_evidence_wins() -> None:
    assert link_status("down", "degraded") == "down"
    assert link_status("dormant", "down") == "down"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([("primary", "up")], ("single-link", "inferred")),
        ([("backup", "down")], ("single-link", "inferred")),
        ([("primary", "unknown")], ("single-link", "inferred")),
        ([("primary", "up"), ("backup", "up")], ("normal", "inferred")),
        ([("primary", "up"), ("backup", "down")], ("normal", "inferred")),
        ([("primary", "up"), ("backup", "unknown")], ("normal", "inferred")),
        ([("primary", "degraded"), ("backup", "up")], ("normal", "inferred")),
        ([("primary", "down"), ("backup", "up")], ("failed-over", "inferred")),
        ([("primary", "down"), ("backup", "degraded")], ("failed-over", "inferred")),
        ([("primary", "down"), ("backup", "down")], ("all-down", "inferred")),
        ([("primary", "down"), ("backup", "unknown")], ("unknown", "unknown")),
        ([("primary", "unknown"), ("backup", "up")], ("unknown", "unknown")),
        ([("primary", "unknown"), ("backup", "down")], ("unknown", "unknown")),
        (
            [("primary", "down"), ("backup", "down"), ("backup", "up")],
            ("failed-over", "inferred"),
        ),
        (
            [("primary", "down"), ("backup", "down"), ("backup", "unknown")],
            ("unknown", "unknown"),
        ),
        ([("backup", "up"), ("backup", "up")], ("unknown", "unknown")),  # no primary declared
        ([], ("unknown", "unknown")),
    ],
)
def test_failover_is_inferred_from_link_status_and_unknown_when_a_link_is_silent(
    statuses: list[tuple[str, str]], expected: tuple[str, str]
) -> None:
    assert failover(statuses) == expected


def test_failover_never_reads_the_order_of_the_links() -> None:
    forward = [("primary", "down"), ("backup", "up")]
    assert failover(list(reversed(forward))) == failover(forward)
