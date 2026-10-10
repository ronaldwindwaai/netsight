"""Smoke test for the E2E harness fixtures themselves.

Before any scenario runs, prove the pieces it depends on work against the real
API process and the stub LibreNMS:

- the stub satisfies the adapter's contract (a `count` mismatch would 502);
- local sign-in with mandatory MFA issues a session;
- the session reaches a protected route;
- a forbidden role is denied.

These are integration tests for the harness, not duplicates of the route tests
in tests/. They exist because a silent harness failure looks like a product bug.
The two-step sign-in harness itself lives in ``conftest.py`` (see ``signed_in``)
so every scenario shares one real sign-in.
"""

from __future__ import annotations

from conftest import SignIn, http_request


def test_stub_librenms_satisfies_the_adapter_contract(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    """The stub must yield canonical devices, not a 502 contract violation."""

    status, body, _ = http_request(f"{e2e_api['apiUrl']}/api/v1/devices", cookie=signed_in.cookie)

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


def test_session_reaches_a_protected_route(e2e_api: dict[str, str], signed_in: SignIn) -> None:
    """A cookie from MFA verification authorises the session route."""

    status, session, _ = http_request(
        f"{e2e_api['apiUrl']}/api/v1/auth/session", cookie=signed_in.cookie
    )
    assert status == 200, session
    assert session["authenticated"] is True


def test_unauthenticated_protected_route_is_denied(e2e_api: dict[str, str]) -> None:
    """No cookie, no data: the API must fail closed."""

    status, body, _ = http_request(f"{e2e_api['apiUrl']}/api/v1/devices")

    assert status == 401, body
    assert body["error"]["code"] in {"AUTHENTICATION_REQUIRED", "FORBIDDEN"}
