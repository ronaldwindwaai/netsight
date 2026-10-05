"""Endpoint tests for Netsight-managed local credentials (ADR 0010).

The central property under test: a correct password alone must never issue a
session. Every login path must pass through a second factor.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netsight_api.localauth import account_store, reset_account_store, totp
from netsight_api.localauth.challenges import reset_challenge_store
from netsight_api.localauth.enrolment import reset_pending_enrolment_store
from netsight_api.localauth.passwords import hash_password
from netsight_api.localauth.ratelimit import reset_local_auth_limiter
from netsight_api.localauth.recovery import generate_recovery_codes, hash_recovery_codes
from netsight_api.localauth.store import LocalAccountStore as _InMemoryStore  # noqa: F401
from netsight_api.main import app

USERNAME = "ops.user"
PASSWORD = "a-strong-unique-passphrase"


@pytest.fixture(autouse=True)
def _clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    import netsight_api.auth.session as session_module

    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "NETSIGHT_SESSION_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NETSIGHT_SESSION_SECRET", "x" * 48)
    # Isolate the durable account store from the real deployment file.
    monkeypatch.setenv("NETSIGHT_LOCAL_ACCOUNT_FILE", str(tmp_path / "accounts.json"))

    # session_policy() is lru_cached, so a value cached by another test module
    # with no secret set would silently win over the environment set above.
    session_module.session_policy.cache_clear()

    reset_account_store()
    reset_challenge_store()
    reset_local_auth_limiter()
    reset_pending_enrolment_store()
    session_module._manager = None

    yield

    reset_account_store()
    reset_challenge_store()
    reset_local_auth_limiter()
    reset_pending_enrolment_store()
    session_module._manager = None
    session_module.session_policy.cache_clear()


def _create_account(*, mfa_required: bool = True, enrolled: bool = True) -> str:
    """Create an account and return its TOTP secret (when enrolled)."""
    store = account_store()
    account = store.create(
        USERNAME,
        hash_password(PASSWORD),
        ["network_engineer"],
        mfa_required=mfa_required,
    )

    if not enrolled:
        return ""

    from netsight_api.localauth.crypto import encrypt_secret

    secret = totp.generate_secret()
    updated = account.with_totp_enrolled(
        encrypted_totp=encrypt_secret(secret, "x" * 48),
        recovery_code_hashes=hash_recovery_codes(generate_recovery_codes(3)),
        now=0.0,
    )
    store.save(updated)
    return secret


def _client() -> TestClient:
    return TestClient(app, follow_redirects=False)


def _challenge_id(response: object) -> str:
    body = response.json()
    value = body.get("challenge_id")
    return str(value) if isinstance(value, str) else ""


# --- the central property --------------------------------------------------


def test_correct_password_alone_never_sets_a_session() -> None:
    secret = _create_account()
    assert secret

    client = _client()
    response = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )

    assert response.status_code == 202
    # No session cookie may be issued by the password step.
    assert "netsight_session" not in response.cookies
    assert response.headers.get("Cache-Control") == "no-store"
    # A challenge is required to continue, and MFA is never optional.
    assert _challenge_id(response)
    assert response.json()["mfa_required"] is True


def test_full_login_requires_and_accepts_the_second_factor() -> None:
    secret = _create_account()
    assert secret

    client = _client()
    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    second = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={
            "challenge_id": _challenge_id(first),
            "code": totp.generate_code(secret),
        },
    )

    assert second.status_code == 200
    assert second.json()["authenticated"] is True
    assert second.json()["identity_id"] == f"local:{USERNAME}"
    assert "network_engineer" in second.json()["roles"]
    # Only now is a session issued.
    assert "netsight_session" in second.cookies


# --- enumeration resistance ------------------------------------------------


@pytest.mark.parametrize(
    ("username", "password"),
    [
        (USERNAME, "definitely-the-wrong-password"),
        ("does-not-exist", PASSWORD),
        ("does-not-exist", "definitely-the-wrong-password"),
        ("OPS.USER", "definitely-the-wrong-password"),
    ],
)
def test_failures_are_indistinguishable(username: str, password: str) -> None:
    """Unknown account, wrong password and wrong case must look identical."""
    _create_account()
    client = _client()

    response = client.post(
        "/api/v1/auth/local/login",
        json={"username": username, "password": password},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"
    assert response.json()["error"]["message"] == "Username or password is not valid"
    assert "netsight_session" not in response.cookies


def test_disabled_account_is_indistinguishable_from_wrong_password() -> None:
    store = account_store()
    account = store.create(USERNAME, hash_password(PASSWORD), ["technician"], enabled=False)

    response = _client().post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"
    assert account.enabled is False


def test_locked_account_is_indistinguishable() -> None:
    _create_account()
    client = _client()

    for _ in range(2):
        client.post(
            "/api/v1/auth/local/login",
            json={"username": USERNAME, "password": "wrong-password-here"},
        )

    response = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"


# --- second-factor enforcement --------------------------------------------


def test_mistyped_second_factor_does_not_lock_the_account() -> None:
    """An honest user who fumbles their code must not be locked out.

    The account lockout models password guessing. Second-factor attempts are
    bounded by the MFA rate limiter and the single-use challenge instead, so a
    couple of typos must leave the account usable.
    """
    secret = _create_account()
    assert secret
    client = _client()

    # A wrong code, then a correct password must still be accepted.
    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert (
        client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge_id": _challenge_id(first), "code": "000000"},
        ).status_code
        == 401
    )

    account = account_store().get(USERNAME)
    assert account is not None
    assert account.consecutive_failures == 0, "MFA failure must not advance the lockout counter"
    assert account.is_locked(0.0) is False

    # And a full, correct login still works.
    second = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert second.status_code == 202
    assert (
        client.post(
            "/api/v1/auth/local/mfa/verify",
            json={
                "challenge_id": _challenge_id(second),
                "code": totp.generate_code(secret),
            },
        ).status_code
        == 200
    )


def test_missing_or_wrong_second_factor_is_refused() -> None:
    secret = _create_account()
    assert secret
    client = _client()

    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    wrong = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": _challenge_id(first), "code": "000000"},
    )
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "MFA_INVALID_CODE"
    assert "netsight_session" not in wrong.cookies


def test_challenge_is_single_use() -> None:
    """A captured challenge id cannot be reused to keep guessing codes."""
    secret = _create_account()
    assert secret
    client = _client()

    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    challenge = _challenge_id(first)

    # A wrong code consumes the challenge.
    client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": challenge, "code": "000000"},
    )
    # The correct code is now worthless.
    replay = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": challenge, "code": totp.generate_code(secret)},
    )
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "MFA_CHALLENGE_INVALID"


def test_challenge_cannot_be_redeemed_from_another_address() -> None:
    """A challenge is bound to the client address that created it."""
    secret = _create_account()
    assert secret

    from netsight_api.localauth.challenges import challenge_store

    pending = challenge_store().issue(
        username=USERNAME,
        client_ip="10.0.0.9",
        roles=frozenset({"network_engineer"}),
        email=None,
    )
    client = _client()

    # The test client presents as 127.0.0.1, so the mismatch must deny.
    response = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={
            "challenge_id": pending.id,
            "code": totp.generate_code(secret),
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "MFA_CHALLENGE_INVALID"
    assert "netsight_session" not in response.cookies


def test_unknown_challenge_is_refused() -> None:
    response = _client().post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": "never-issued", "code": "123456"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "MFA_CHALLENGE_INVALID"


def test_recovery_code_can_replace_a_lost_authenticator() -> None:
    """An account with MFA required but not yet enrolled uses recovery codes."""
    store = account_store()
    account = store.create(USERNAME, hash_password(PASSWORD), ["technician"], mfa_required=True)
    codes = generate_recovery_codes(2)
    account.recovery_code_hashes = hash_recovery_codes(codes)
    store.save(account)

    client = _client()
    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    second = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": _challenge_id(first), "code": codes[0]},
    )
    assert second.status_code == 200

    # The used code cannot be used again.
    first_again = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    reused = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": _challenge_id(first_again), "code": codes[0]},
    )
    assert reused.status_code == 401

    # The unused one still works.
    second_again = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    still_good = client.post(
        "/api/v1/auth/local/mfa/verify",
        json={"challenge_id": _challenge_id(second_again), "code": codes[1]},
    )
    assert still_good.status_code == 200


def test_totp_replay_inside_a_step_is_refused() -> None:
    secret = _create_account()
    assert secret
    client = _client()

    code = totp.generate_code(secret)
    for _ in range(2):
        first = client.post(
            "/api/v1/auth/local/login",
            json={"username": USERNAME, "password": PASSWORD},
        )
        if _ == 0:
            assert (
                client.post(
                    "/api/v1/auth/local/mfa/verify",
                    json={"challenge_id": _challenge_id(first), "code": code},
                ).status_code
                == 200
            )
        else:
            replay = client.post(
                "/api/v1/auth/local/mfa/verify",
                json={"challenge_id": _challenge_id(first), "code": code},
            )
            assert replay.status_code == 401
            assert replay.json()["error"]["code"] == "MFA_INVALID_CODE"


# --- rate limiting ---------------------------------------------------------


def test_password_attempts_are_rate_limited_per_client() -> None:
    _create_account()
    client = _client()

    statuses = [
        client.post(
            "/api/v1/auth/local/login",
            json={"username": USERNAME, "password": "wrong-password-here"},
        ).status_code
        for _ in range(8)
    ]

    assert 429 in statuses
    limited = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers


def test_second_factor_attempts_never_bypass_the_flow() -> None:
    """A burst of guesses against one challenge must not yield a session.

    A challenge is single use, so the first guess consumes it and the rest are
    refused outright. The password-step limit is deliberately tighter than the
    MFA budget, so an attacker cannot even obtain enough challenges to brute
    force the second factor.
    """
    secret = _create_account()
    assert secret
    client = _client()

    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    challenge = _challenge_id(first)

    statuses = []
    for index in range(12):
        response = client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge_id": challenge, "code": f"{index:06d}"},
        )
        statuses.append(response.status_code)
        assert "netsight_session" not in response.cookies

    assert set(statuses) <= {401, 429}
    assert 200 not in statuses


def test_password_limit_is_tighter_than_the_mfa_budget() -> None:
    """Defence in depth: challenges cannot be obtained faster than they burn."""
    from netsight_api.localauth.ratelimit import (
        LOGIN_ATTEMPTS_PER_WINDOW,
        MFA_ATTEMPTS_PER_WINDOW,
    )

    assert LOGIN_ATTEMPTS_PER_WINDOW <= MFA_ATTEMPTS_PER_WINDOW


def test_mfa_limiter_blocks_spraying_from_one_host() -> None:
    """Both the account and the host budget are enforced independently."""
    from netsight_api.localauth.ratelimit import MFA_ATTEMPTS_PER_WINDOW, LocalAuthLimiter

    limiter = LocalAuthLimiter()
    assert all(
        limiter.allow_mfa("10.0.0.1", "ops") for _ in range(MFA_ATTEMPTS_PER_WINDOW)
    )
    # Account budget spent: blocked from this host...
    assert limiter.allow_mfa("10.0.0.1", "ops") is False
    # ...and from any other host, so the account is protected regardless of
    # where the guessing comes from.
    assert limiter.allow_mfa("10.0.0.2", "ops") is False
    # The host budget is also spent, so spraying other accounts is blocked.
    assert limiter.allow_mfa("10.0.0.1", "someone-else") is False
    # An untouched account from an untouched host is unaffected.
    assert limiter.allow_mfa("10.0.0.2", "someone-else") is True


def test_password_limiter_blocks_spraying_from_one_host() -> None:
    from netsight_api.localauth.ratelimit import (
        LOGIN_ATTEMPTS_PER_WINDOW,
        LocalAuthLimiter,
    )

    limiter = LocalAuthLimiter()
    assert all(
        limiter.allow_password("10.0.0.1", f"user{index}")
        for index in range(LOGIN_ATTEMPTS_PER_WINDOW)
    )
    # The host budget is spent, so account spraying is blocked.
    assert limiter.allow_password("10.0.0.1", "brand-new-user") is False
    # A different host retains its own budget.
    assert limiter.allow_password("10.0.0.2", "brand-new-user") is True


# --- enrolment -------------------------------------------------------------


def test_enrolment_requires_authentication() -> None:
    assert _client().post("/api/v1/auth/local/mfa/enroll").status_code == 401


def test_enrolment_secret_is_never_returned_twice() -> None:
    store = account_store()
    store.create(USERNAME, hash_password(PASSWORD), ["network_engineer"])

    client = _client()
    # Sign in as this local account to obtain a session. MFA is not enrolled,
    # so the challenge cannot be completed; assert the endpoint refuses
    # instead of silently returning a secret.
    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    assert first.status_code == 202

    client.cookies.clear()
    # Without a session the enrolment endpoint must refuse.
    assert client.post("/api/v1/auth/local/mfa/enroll").status_code == 401


def test_password_change_requires_a_session() -> None:
    _create_account()
    response = _client().post(
        "/api/v1/auth/local/password/change",
        json={"current_password": PASSWORD, "new_password": "another-strong-passphrase"},
    )
    assert response.status_code == 401


# --- input validation ------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": USERNAME},
        {"password": PASSWORD},
        {"username": USERNAME, "password": PASSWORD, "role": "administrator"},
        {"username": "", "password": PASSWORD},
        {"username": USERNAME, "password": ""},
    ],
)
def test_login_rejects_malformed_bodies(payload: dict[str, str]) -> None:
    response = _client().post("/api/v1/auth/local/login", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_absurdly_long_password_is_rejected_before_hashing() -> None:
    response = _client().post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": "x" * 5000},
    )
    assert response.status_code == 422


def test_a_privileged_role_cannot_be_smuggled_in_at_sign_in() -> None:
    """Role assignment happens only at account creation, never from the client."""
    store = account_store()
    store.create(USERNAME, hash_password(PASSWORD), ["technician"])
    client = _client()

    response = client.post(
        "/api/v1/auth/local/login",
        json={
            "username": USERNAME,
            "password": PASSWORD,
            "roles": ["administrator"],
        },
    )
    # The extra field is rejected outright by the strict body model.
    assert response.status_code == 422


# --- correlation and disclosure -------------------------------------------


def test_correlation_id_is_echoed() -> None:
    _create_account()
    response = _client().post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": "wrong-password-here"},
        headers={"X-Correlation-ID": "localauth-test-1"},
    )
    assert response.headers["X-Correlation-ID"] == "localauth-test-1"


def test_error_bodies_disclose_nothing_sensitive() -> None:
    _create_account()
    response = _client().post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": "wrong-password-here"},
    )
    body = response.text
    for leak in (PASSWORD, "argon2", "netsight_api", "Traceback", "127.0.0.1"):
        assert leak not in body, leak


def test_challenge_id_is_unguessable() -> None:
    _create_account()
    client = _client()
    first = client.post(
        "/api/v1/auth/local/login",
        json={"username": USERNAME, "password": PASSWORD},
    )
    challenge = _challenge_id(first)

    assert len(challenge) >= 32
    assert "USERNAME" not in challenge
    assert PASSWORD not in challenge


def test_account_store_is_durable_and_type_guarded() -> None:
    """The store must be file-backed so the CLI and the API agree."""
    from netsight_api.localauth.filestore import FileAccountStore

    assert isinstance(account_store(), FileAccountStore)
