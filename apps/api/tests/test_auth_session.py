"""Session store, signed cookie and CSRF tests."""

from __future__ import annotations

import time

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
    store = SessionStore()
    policy = SessionPolicy(inactivity_timeout=60, absolute_lifetime=600)
    session = store.create("sub1", "microsoft", ["management"])
    before = session.last_activity
    time.sleep(0.01)

    got = store.get(session.id, policy)
    assert got is not None
    assert got.last_activity > before


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
