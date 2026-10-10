"""Session store, signed cookie and CSRF tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netsight_api.auth.session import (
    SessionManager,
    SessionStore,
    session_manager,
)
from netsight_api.auth.settings import SessionPolicy


def test_session_policy_rejects_invalid_same_site_value() -> None:
    with pytest.raises(ValidationError):
        SessionPolicy(same_site="invalid")  # type: ignore[arg-type]


def test_store_create_and_get() -> None:
    store = SessionStore()
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["administrator"], "a@example.com")

    got = store.get(session.id, policy)
    assert got is not None
    assert got.subject == "sub1"
    assert got.provider == "microsoft"
    assert "administrator" in got.roles
    assert got.email == "a@example.com"
    assert got.identity_id == "microsoft:sub1"


def test_store_unknown_id_returns_none() -> None:
    assert SessionStore().get("unknown", SessionPolicy()) is None


def test_store_inactivity_expiry_revoke() -> None:
    store = SessionStore()
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["management"])
    session.last_activity -= 61

    assert store.get(session.id, policy) is None
    assert session.id not in store._sessions


def test_store_absolute_expiry() -> None:
    store = SessionStore()
    policy = SessionPolicy(inactivity_timeout=3600, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["management"])
    session.created_at -= 601
    session.last_activity -= 601

    assert store.get(session.id, policy) is None


def test_store_sliding_inactivity_updates_last_activity() -> None:
    # Uses an injected clock: platform timer resolution makes a short sleep
    # unreliable on some platforms, and session expiry is security-critical.
    now = [1000.0]
    store = SessionStore(clock=lambda: now[0])
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["management"])
    before = session.last_activity
    now[0] += 10.0

    got = store.get(session.id, policy)
    assert got is not None
    assert got.last_activity > before
    assert got.last_activity == now[0]


def test_store_sliding_inactivity_keeps_active_session_alive() -> None:
    now = [1000.0]
    store = SessionStore(clock=lambda: now[0])
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["management"])

    # Advance past the inactivity window but touch the session each step.
    for _ in range(10):
        now[0] += 50.0
        assert store.get(session.id, policy) is not None

    # Once access stops, the same window expires the session.
    now[0] += 61.0
    assert store.get(session.id, policy) is None


def test_store_absolute_lifetime_ignores_activity() -> None:
    now = [1000.0]
    store = SessionStore(clock=lambda: now[0])
    policy = SessionPolicy(inactivity_timeout=600, absolute_lifetime=100)
    session = store.create("sub1", "microsoft", ["management"])

    # Continuous access must not extend a session past its absolute lifetime.
    for _ in range(10):
        now[0] += 50.0
        store.get(session.id, policy)

    now[0] += 60.0
    assert store.get(session.id, policy) is None


def test_store_revoke() -> None:
    store = SessionStore()
    policy = SessionPolicy()
    session = store.create("sub1", "microsoft", ["management"])
    store.revoke(session.id)
    assert store.get(session.id, policy) is None


def test_store_revoke_subject_only_matching() -> None:
    store = SessionStore()
    policy = SessionPolicy()
    a = store.create("sub1", "microsoft", ["management"])
    b = store.create("sub1", "microsoft", ["management"])
    other = store.create("sub2", "google", ["management"])

    store.revoke_subject("microsoft", "sub1")

    assert store.get(a.id, policy) is None
    assert store.get(b.id, policy) is None
    assert store.get(other.id, policy) is not None


def test_store_prune_expired() -> None:
    store = SessionStore()
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    live = store.create("sub1", "microsoft", ["management"])
    stale = store.create("sub2", "microsoft", ["management"])
    stale.last_activity -= 61

    pruned = store.prune(policy)
    assert pruned == 1
    assert store.get(live.id, policy) is not None
    assert store.get(stale.id, policy) is None


def test_cookie_sign_verify_roundtrip() -> None:
    manager = SessionManager(
        SessionStore(),
        SessionPolicy(secret="test-secret", secure_cookie=False),
    )
    session = manager.create_session("sub1", "microsoft", ["management"])
    value = manager.cookie_value(session)

    got = manager.validate_cookie(value)
    assert got is not None
    assert got.id == session.id


def test_cookie_tamper_rejected() -> None:
    manager = SessionManager(
        SessionStore(),
        SessionPolicy(secret="test-secret", secure_cookie=False),
    )
    session = manager.create_session("sub1", "microsoft", ["management"])
    value = manager.cookie_value(session)
    flipped = value[:-1] + ("A" if not value.endswith("A") else "B")

    assert manager.validate_cookie(flipped) is None


def test_cookie_wrong_secret_rejected() -> None:
    signer = SessionManager(SessionStore(), SessionPolicy(secret="secret-a"))
    verifier = SessionManager(SessionStore(), SessionPolicy(secret="secret-b"))
    session = signer.create_session("sub1", "microsoft", ["management"])

    assert verifier.validate_cookie(signer.cookie_value(session)) is None


def test_cookie_attributes() -> None:
    policy = SessionPolicy(
        secret="s",
        cookie_name="netsight_session",
        secure_cookie=True,
        same_site="lax",
    )
    manager = SessionManager(SessionStore(), policy)
    attrs = manager.cookie_attributes()

    assert attrs["key"] == "netsight_session"
    assert attrs["httponly"] is True
    assert attrs["secure"] is True
    assert attrs["samesite"] == "lax"
    assert attrs["path"] == "/"


def test_global_session_manager_is_singleton() -> None:
    assert session_manager() is session_manager()


# --- MFA recency (step-up) ------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_session_has_no_mfa_stamp_unless_the_sign_in_proved_one() -> None:
    manager = SessionManager(SessionStore(), SessionPolicy(secret="s" * 32))
    session = manager.create_session("sub", "microsoft", ["administrator"])
    assert session.mfa_verified_at is None
    assert manager.mfa_age(session) is None


def test_mfa_age_is_measured_from_the_sign_in_on_the_store_clock() -> None:
    clock = _Clock()
    manager = SessionManager(SessionStore(clock), SessionPolicy(secret="s" * 32))
    session = manager.create_session("sub", "local", ["administrator"], mfa_age_seconds=0.0)
    assert manager.mfa_age(session) == 0.0
    clock.now += 125.5
    assert manager.mfa_age(session) == 125.5


def test_a_stamp_from_the_future_is_unknown_not_fresh() -> None:
    clock = _Clock()
    manager = SessionManager(SessionStore(clock), SessionPolicy(secret="s" * 32))
    session = manager.create_session("sub", "local", ["administrator"], mfa_age_seconds=0.0)
    session.mfa_verified_at = clock.now + 50
    assert manager.mfa_age(session) is None
