"""Review fixes for S6 step 2: the leader lease is re-checked inside the apply phase (a lease lost
mid-cycle stops further sends and incident writes), the deferred-notification backlog drops
entries of rules that are no longer live, and observations are visited in a stable order.

In-memory stores, a scripted source and an injected clock only.
"""

from __future__ import annotations

import pytest
from evaluation_support import DEVICE_A, DEVICE_B, observation
from test_evaluation_followups import DEVICE_C
from test_evaluation_runner import Rig, down

from netsight_api.evaluation.runner import RunnerLimits
from netsight_api.evaluation.source import ObservationBatch


def rig_with_lease_lost_after_first_send() -> tuple[Rig, list[int]]:
    """A lease that holds until the first notification has gone out, then is lost."""
    checks: list[int] = []
    holder: list[Rig] = []

    def lease() -> bool:
        checks.append(1)
        return len(holder[0].sender.calls) < 1

    rig = Rig(lease=lease)
    holder.append(rig)
    return rig, checks


@pytest.mark.asyncio
async def test_a_lease_lost_mid_cycle_stops_the_remaining_sends() -> None:
    rig, _ = rig_with_lease_lost_after_first_send()
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C)
    report = await rig.cycle()
    assert len(rig.sender.calls) == 1  # the one in flight when the lease went; nothing after it
    assert report.lease_lost is True
    assert report.notifications_sent <= 1


@pytest.mark.asyncio
async def test_a_lease_lost_mid_cycle_drops_state_so_a_later_takeover_starts_clean() -> None:
    rig, _ = rig_with_lease_lost_after_first_send()
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C)
    await rig.cycle()
    assert len(rig.runner._states) == 0 and len(rig.runner._backlog) == 0


@pytest.mark.asyncio
async def test_the_lease_is_checked_before_each_send_not_only_once_per_cycle() -> None:
    checks: list[int] = []
    rig = Rig(lease=lambda: checks.append(1) or True)
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C)
    report = await rig.cycle()
    assert report.notifications_sent == 3
    assert len(checks) >= 1 + 3  # once before applying, then before every send


@pytest.mark.asyncio
async def test_a_lease_lost_before_the_incident_writes_creates_no_incident() -> None:
    state = {"calls": 0}

    def lease() -> bool:
        state["calls"] += 1
        return state["calls"] == 1  # fine for the pre-apply check only

    rig = Rig(lease=lease)
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert report.lease_lost is True
    assert rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
async def test_a_lease_lost_before_applying_reports_what_was_evaluated_like_a_mid_cycle_loss() -> None:
    rig = Rig(lease=lambda: False)
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert report.lease_lost is True
    assert (report.rules_loaded, report.evaluations, report.fired) == (1, 2, 2)
    assert rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
async def test_an_unverifiable_lease_check_mid_cycle_counts_as_lost() -> None:
    state = {"calls": 0}

    def lease() -> bool:
        state["calls"] += 1
        if state["calls"] > 1:
            raise RuntimeError("database unreachable")
        return True

    rig = Rig(lease=lease)
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.lease_lost is True and rig.sender.calls == []


# --- backlog entries of rules that are no longer live -----------------------------------------------


@pytest.mark.asyncio
async def test_a_deferred_notification_of_a_disabled_rule_is_never_sent() -> None:
    rig = Rig(limits=RunnerLimits(max_notifications=1))
    rule = rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B)
    first = await rig.cycle()
    assert first.notifications_sent == 1 and first.notifications_backlog == 1
    rig.stack.rules.disable_rule(rule.id, actor_id="seed:admin")
    second = await rig.cycle(advance=60)
    assert second.notifications_sent == 0
    assert second.notifications_skipped == 1  # the pruned backlog entry is counted
    assert second.notifications_backlog == 0
    assert len(rig.sender.calls) == 1


@pytest.mark.asyncio
async def test_a_deferred_notification_of_an_edited_rule_version_is_dropped() -> None:
    rig = Rig(limits=RunnerLimits(max_notifications=1))
    rule = rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B)
    await rig.cycle()
    from evaluation_support import definition

    rig.stack.rules.disable_rule(rule.id, actor_id="seed:admin")
    rig.stack.rules.update_rule(
        rule.id, definition(name="Renamed"), expected_version=3, actor_id="seed:admin"
    )  # the edit returns the rule to draft: no version of it is live
    report = await rig.cycle(advance=60)
    assert report.notifications_sent == 0 and report.notifications_backlog == 0


# --- stable entity order ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_round_robin_cursor_is_stable_when_the_source_order_changes() -> None:
    """One evaluation per cycle. Unsorted, the cursor (a position) would revisit A in cycle 2
    (the source lists B,A,C) and B in cycle 3 (C,A,B); sorted, A, B, C are reached in turn."""
    rig = Rig(limits=RunnerLimits(max_evaluations=1))
    rig.stack.active_rule(for_seconds=0)
    orders = [
        (DEVICE_A, DEVICE_B, DEVICE_C),
        (DEVICE_B, DEVICE_A, DEVICE_C),
        (DEVICE_C, DEVICE_A, DEVICE_B),
    ]
    reached: list[str] = []
    for order, expected in zip(orders, (DEVICE_A, DEVICE_B, DEVICE_C), strict=True):
        rig.source.batches["device.status"] = ObservationBatch(
            "ok", tuple(observation(entity, 0.0) for entity in order)
        )
        before = {i.title for i in rig.incidents}
        report = await rig.cycle(advance=60)
        (new,) = {i.title for i in rig.incidents} - before  # exactly one new incident
        assert report.evaluations == 1 and expected in new
        reached.append(expected)
    assert reached == [DEVICE_A, DEVICE_B, DEVICE_C]
