"""End-to-end: a real API process runs a real probe through the diagnostics route.

The route tests (``tests/test_diagnostics_api.py``) use a declarative fake probe so no test opens a
socket from the API; the adapter tests open loopback sockets directly. This scenario closes the
remaining gap: the API process is configured with a probe allow-list, a signed-in operator posts
``/api/v1/diagnostics`` over real HTTP with a real session cookie and CSRF token, and the request
runs the real allowlisted adapter end to end.

``dns`` of ``localhost`` resolves from the hosts file, so it passes without a privileged port and
without traffic leaving the machine.
"""

from __future__ import annotations

from conftest import SignIn, http_request


def _csrf(api_url: str, cookie: str) -> str:
    status, body, _ = http_request(f"{api_url}/api/v1/auth/csrf", cookie=cookie)
    assert status == 200, body
    return body["csrf_token"]


def _run(
    api_url: str, cookie: str, body: dict[str, object]
) -> tuple[int, object, str]:
    token = _csrf(api_url, cookie)
    return http_request(
        f"{api_url}/api/v1/diagnostics",
        method="POST",
        body=body,
        cookie=cookie,
        headers={"X-CSRF-Token": token},
    )


def test_diagnostic_run_executes_a_real_probe_end_to_end(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    status, body, _ = _run(
        e2e_api["apiUrl"],
        signed_in.cookie,
        {
            "target": "localhost",
            "symptom": "synthetic check of the harness",
            "vantage": "internal",
            "requested_checks": ["dns"],
        },
    )
    assert status == 200, body
    assert isinstance(body, dict)
    assert body["state"] == "ok", body
    run = body["run"]
    assert isinstance(run, dict)
    check = run["checks"][0]
    assert check["kind"] == "dns"
    assert check["status"] == "pass", check
    assert check["latency_ms"] is not None
    assert "resolved to" in (check["detail"] or "")
    # A passing round is not a fault: the engine must not name a domain.
    assert run["probable_fault_domain"] is None
    assert run["confidence"] == "unknown"
    assert run["target"] == "localhost"


def test_an_unconfigured_target_is_unknown_not_a_guess(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    status, body, _ = _run(
        e2e_api["apiUrl"],
        signed_in.cookie,
        {
            "target": "not-on-the-allow-list.example",
            "symptom": None,
            "vantage": "internal",
            "requested_checks": ["dns"],
        },
    )
    assert status == 200, body
    assert isinstance(body, dict)
    assert body["state"] == "ok", body
    run = body["run"]
    assert isinstance(run, dict)
    check = run["checks"][0]
    # Deny by default: a non-allow-listed target is never resolved, so the check is an honest
    # unknown rather than a guessed pass or fail.
    assert check["status"] == "unknown"
    assert check["detail"] and "allow-list" in check["detail"]
    assert run["probable_fault_domain"] is None
    assert run["confidence"] == "unknown"


def test_a_requested_vantage_without_a_prober_is_unknown(
    e2e_api: dict[str, str], signed_in: SignIn
) -> None:
    # The harness API is deployed as `internal`; no internet prober is connected, so a request for
    # that vantage is an honest unknown and the run still reports where the check actually ran.
    status, body, _ = _run(
        e2e_api["apiUrl"],
        signed_in.cookie,
        {
            "target": "localhost",
            "symptom": None,
            "vantage": "internet",
            "requested_checks": ["dns"],
        },
    )
    assert status == 200, body
    assert isinstance(body, dict)
    assert body["state"] == "ok", body
    run = body["run"]
    assert isinstance(run, dict)
    check = run["checks"][0]
    assert check["status"] == "unknown"
    assert check["vantage"] == "internal"
    assert "vantage" in (check["detail"] or "")
    assert run["vantage"] == "internal"
