"""Smoke test for the E2E harness fixtures themselves.

Before any Playwright spec runs, prove the pieces it depends on work against the
real API process and the stub LibreNMS:

- the stub satisfies the adapter's contract (a `count` mismatch would 502);
- local sign-in with mandatory MFA issues a session;
- the session reaches a protected route;
- a forbidden role is denied.

These are integration tests for the harness, not duplicates of the route tests
in tests/. They exist because a silent harness failure looks like a product bug.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from conftest import E2EAccount


def _request(
    url: str,
    *,
    method: str = "GET",
    body: Any = None,
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str]:
    """Perform one request; return (status, parsed body, raw set-cookie)."""

    data = None
    request_headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    if cookie:
        request_headers["Cookie"] = cookie

    request = urllib.request.Request(
        url, data=data, method=method, headers=request_headers
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode()
            parsed = json.loads(raw) if raw else None
            return response.status, parsed, response.headers.get("set-cookie", "")
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        parsed = json.loads(raw) if raw else None
        return error.code, parsed, error.headers.get("set-cookie", "")


def _session_cookie(set_cookie: str) -> str | None:
    for part in set_cookie.split(";"):
        if part.strip().startswith("netsight_session="):
            return part.strip()
    return None


# A TOTP code is single-use per 30-second step (localauth/totp.py:98-99). The
# suite signs in more than once inside a single window, so each call hands out
# the next unconsumed step. Verification tolerates one step of drift either way,
# so a step slightly ahead of the clock is still accepted.
_CONSUMED_STEPS: set[int] = set()


def _totp_code(secret: str) -> str:
    """Return a TOTP code that has not been consumed in this process.

    A code is single-use per 30-second step and verification only tolerates one
    step of drift, so this cannot simply hand out "now" repeatedly: the first
    sign-in consumes the current step and any later one in the same window is
    rejected as a replay. Rather than sleeping through the window (and burning
    the shared rate limit), sign in once per session and reuse the cookie.
    """

    from netsight_api.localauth.totp import PERIOD_SECONDS, generate_code

    step = int(time.time() // PERIOD_SECONDS)
    if step in _CONSUMED_STEPS:
        pytest.fail(
            "the TOTP step for this window was already consumed; "
            "reuse the session-scoped session fixture instead of signing in twice"
        )
    _CONSUMED_STEPS.add(step)
    return generate_code(secret, for_time=step * PERIOD_SECONDS)


@dataclass(frozen=True)
class SignIn:
    """The observable result of one real two-step sign-in."""

    cookie: str
    challenge_status: int
    challenge: dict[str, Any]
    verify_status: int
    verified: dict[str, Any]


@pytest.fixture(scope="session")
def signed_in(e2e_api: dict[str, str], e2e_account: E2EAccount) -> Iterator[SignIn]:
    """One real sign-in for the whole session; every test reuses this cookie.

    Signing in per test is not viable: a TOTP code is single-use within its
    30-second window and local sign-in is rate-limited, so a second sign-in
    inside the same window is rejected as a replay. Tests assert on the
    recorded `SignIn` instead of authenticating again.
    """

    challenge_status, challenge, _ = _request(
        f"{e2e_api['apiUrl']}/api/v1/auth/local/login",
        method="POST",
        body={"username": e2e_account.username, "password": e2e_account.password},
    )
    verify_status: int
    verified: dict[str, Any]
    set_cookie: str
    if challenge_status == 202:
        verify_status, verified, set_cookie = _request(
            f"{e2e_api['apiUrl']}/api/v1/auth/local/mfa/verify",
            method="POST",
            body={
                "challenge_id": challenge["challenge_id"],
                "code": _totp_code(e2e_account.totp_secret),
            },
        )
    else:
        # Surface the failure through the assertions below, not here, so the
        # report names the actual status and body.
        verify_status, verified, set_cookie = challenge_status, challenge, ""

    yield SignIn(
        cookie=_session_cookie(set_cookie) or "",
        challenge_status=challenge_status,
        challenge=challenge,
        verify_status=verify_status,
        verified=verified,
    )


def test_stub_librenms_satisfies_the_adapter_contract(
    e2e_api: dict[str, str], signed_in: str
) -> None:
    """The stub must yield canonical devices, not a 502 contract violation."""

    status, body, _ = _request(f"{e2e_api['apiUrl']}/api/v1/devices", cookie=signed_in.cookie)

    assert status == 200, body
    assert isinstance(body, dict)
    assert body["total"] == 2, "stub count must match the array it returns"
    hostnames = {item["hostname"] for item in body["items"]}
    assert hostnames == {"core-sw-01.example.test", "edge-rt-02.example.test"}


def test_local_sign_in_with_mandatory_mfa_issues_a_session(signed_in: SignIn) -> None:
    """Two-step sign-in returns 202 then 200, and grants the assigned role."""

    assert signed_in.challenge_status == 202, signed_in.challenge
    assert signed_in.challenge["mfa_required"] is True
    assert signed_in.verify_status == 200, signed_in.verified
    assert signed_in.verified["authenticated"] is True
    assert "administrator" in signed_in.verified["roles"]
    assert signed_in.cookie, "a session cookie must be issued"


def test_session_reaches_a_protected_route(e2e_api: dict[str, str], signed_in: str) -> None:
    """A cookie from MFA verification authorises the session route."""

    status, session, _ = _request(
        f"{e2e_api['apiUrl']}/api/v1/auth/session", cookie=signed_in.cookie
    )
    assert status == 200, session
    assert session["authenticated"] is True


def test_unauthenticated_protected_route_is_denied(e2e_api: dict[str, str]) -> None:
    """No cookie, no data: the API must fail closed."""

    status, body, _ = _request(f"{e2e_api['apiUrl']}/api/v1/devices")

    assert status == 401, body
    assert body["error"]["code"] in {"AUTHENTICATION_REQUIRED", "FORBIDDEN"}