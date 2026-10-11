"""Opaque evidence ids for callers who may not learn who is behind an address (review LOW).

A source's record id can embed a user name or an account id, and most are guessable. An unkeyed
hash of a guessable value is a membership oracle (hash a guess, compare), so the id is a keyed HMAC
under a server secret the caller never sees.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

import pytest

from netsight_api.identity import api_models, id_key
from netsight_api.identity.id_key import ID_KEY_ENV, IdKeyUnavailable, evidence_id_key
from netsight_api.identity.model import EvidenceKind, EvidenceRef

GOOD = "k" * 40


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ID_KEY_ENV, "NETSIGHT_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(id_key, "_DEVELOPMENT_KEY", None)


def test_the_id_is_stable_keeps_the_source_and_hides_the_native_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ID_KEY_ENV, GOOD)
    first = api_models.opaque_evidence_id("radius:session-alice@example.org")
    assert first == api_models.opaque_evidence_id("radius:session-alice@example.org")
    assert first.startswith("radius:") and "alice" not in first
    assert api_models.opaque_evidence_id("radius:other") != first


def test_the_id_cannot_be_recomputed_without_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ID_KEY_ENV, GOOD)
    guess = "netbox:owner-7-12"
    unkeyed = f"netbox:{hashlib.sha256(guess.encode()).hexdigest()[:16]}"
    assert api_models.opaque_evidence_id(guess) != unkeyed


def test_a_different_key_gives_a_different_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ID_KEY_ENV, GOOD)
    one = api_models.opaque_evidence_id("netbox:owner-7-12")
    monkeypatch.setenv(ID_KEY_ENV, "j" * 40)
    assert api_models.opaque_evidence_id("netbox:owner-7-12") != one


@pytest.mark.parametrize("value", ["", "   ", "short", "x" * 31])
def test_a_missing_or_weak_key_fails_closed_in_production(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(ID_KEY_ENV, value)
    with pytest.raises(IdKeyUnavailable):
        evidence_id_key()
    with pytest.raises(IdKeyUnavailable):
        api_models.opaque_evidence_id("radius:x")
    monkeypatch.setenv("NETSIGHT_ENV", "staging")  # only "development" relaxes this
    with pytest.raises(IdKeyUnavailable):
        evidence_id_key()


def test_development_generates_a_per_process_key_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    caplog.set_level(logging.WARNING)
    first = evidence_id_key()
    assert first == evidence_id_key() and len(first) >= 32
    warnings = [r for r in caplog.records if "evidence id key" in r.getMessage()]
    assert len(warnings) == 1  # said once, not per call
    assert ID_KEY_ENV in warnings[0].getMessage()
    assert first.hex() not in caplog.text


def test_a_configured_key_wins_over_the_development_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv(ID_KEY_ENV, GOOD)
    assert evidence_id_key() == GOOD.encode()


def test_the_full_view_does_not_need_the_key() -> None:
    stamp = datetime(2026, 10, 11, 12, tzinfo=UTC)
    ref = EvidenceRef("radius:abc", "radius", EvidenceKind.RADIUS_SESSION, stamp, stamp, None, 0.9)
    assert api_models.evidence(ref).id == "radius:abc"
    with pytest.raises(IdKeyUnavailable):
        api_models.evidence(ref, opaque=True)
