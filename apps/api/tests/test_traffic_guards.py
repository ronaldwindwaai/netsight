"""Heavy flow-store reads: one at a time per identity, and a slot kept back for the detail tier.

The per-identity rate limit stops a fast caller; it does not stop one caller (or one stolen session)
from holding every slot with slow reads. These pin the two admission rules: an identity may run one
heavy read at a time, and the last slot is reserved for callers holding ``traffic:read-detail`` so the
aggregate tier can never starve the investigation work.
"""

from __future__ import annotations

import asyncio

import pytest

from netsight_api.errors import ApiError
from netsight_api.traffic import guards


async def _hold(
    identity: str, *, detail: bool, release: asyncio.Event, entered: asyncio.Event
) -> None:
    async with guards.heavy_read(identity, detail=detail):
        entered.set()
        await release.wait()


async def _start(identity: str, *, detail: bool) -> tuple[asyncio.Task[None], asyncio.Event]:
    release, entered = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(_hold(identity, detail=detail, release=release, entered=entered))
    await entered.wait()
    return task, release


async def _finish(*pairs: tuple[asyncio.Task[None], asyncio.Event]) -> None:
    for _, release in pairs:
        release.set()
    await asyncio.gather(*(task for task, _ in pairs))


@pytest.mark.asyncio
async def test_a_second_concurrent_read_by_the_same_identity_is_refused() -> None:
    first = await _start("alice", detail=True)
    with pytest.raises(ApiError) as refused:
        async with guards.heavy_read("alice", detail=True):
            pytest.fail("a second read by the same identity must not start")
    assert refused.value.status_code == 429
    assert refused.value.code == "TRAFFIC_CONCURRENCY"
    assert refused.value.headers == {"Retry-After": "5"}
    await _finish(first)


@pytest.mark.asyncio
async def test_the_identity_may_read_again_once_its_read_has_finished() -> None:
    first = await _start("alice", detail=False)
    await _finish(first)
    async with guards.heavy_read("alice", detail=False):
        pass


@pytest.mark.asyncio
async def test_different_identities_run_side_by_side() -> None:
    a = await _start("alice", detail=False)
    b = await _start("bob", detail=False)
    await _finish(a, b)


@pytest.mark.asyncio
async def test_a_refused_read_does_not_release_the_slot_of_the_one_running() -> None:
    first = await _start("alice", detail=True)
    with pytest.raises(ApiError):
        async with guards.heavy_read("alice", detail=True):
            pass
    with pytest.raises(ApiError):  # still held: a third attempt is refused too
        async with guards.heavy_read("alice", detail=True):
            pass
    await _finish(first)
    async with guards.heavy_read("alice", detail=True):
        pass


@pytest.mark.asyncio
async def test_the_last_slot_is_reserved_for_the_detail_tier() -> None:
    assert guards.MAX_CONCURRENT_HEAVY == 3 and guards.RESERVED_FOR_DETAIL == 1
    held = [await _start(name, detail=False) for name in ("m1", "m2")]
    with pytest.raises(ApiError) as refused:  # a third aggregate read finds only the reserved slot
        async with guards.heavy_read("m3", detail=False):
            pytest.fail("the reserved slot belongs to the detail tier")
    assert refused.value.status_code == 503 and refused.value.code == "TRAFFIC_BUSY"
    assert refused.value.headers == {"Retry-After": "5"}
    detail = await _start("analyst", detail=True)  # the detail tier still gets in
    await _finish(*held, detail)


@pytest.mark.asyncio
async def test_the_detail_tier_can_use_every_slot_when_the_aggregate_tier_is_idle() -> None:
    held = [await _start(name, detail=True) for name in ("a", "b", "c")]
    with pytest.raises(ApiError) as refused:
        async with guards.heavy_read("d", detail=True):
            pass
    assert refused.value.status_code == 503
    await _finish(*held)


@pytest.mark.asyncio
async def test_a_cancelled_read_releases_both_the_slot_and_the_identity() -> None:
    task, _ = await _start("alice", detail=True)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with guards.heavy_read("alice", detail=True):
        pass


@pytest.mark.asyncio
async def test_a_failing_read_releases_both_the_slot_and_the_identity() -> None:
    with pytest.raises(RuntimeError):
        async with guards.heavy_read("alice", detail=True):
            raise RuntimeError("source failed")
    async with guards.heavy_read("alice", detail=True):
        pass


@pytest.mark.asyncio
async def test_a_zero_capacity_refuses_everyone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guards, "MAX_CONCURRENT_HEAVY", 0)
    for detail in (True, False):
        with pytest.raises(ApiError) as refused:
            async with guards.heavy_read("alice", detail=detail):
                pass
        assert refused.value.status_code == 503
