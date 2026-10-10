"""Shared E2E fixture: a real API process pointed at a stub LibreNMS.

Deliberately thin. It provisions a local account through the same code path an
operator uses (`netsight_api.localauth.cli.main`) and exposes the resulting TOTP
secret, so the Playwright specs exercise the genuine two-step sign-in including
mandatory MFA rather than a bypass.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

# .../netsight/apps/api/tests/e2e/conftest.py -> repo root is four levels up.
REPO_ROOT = Path(__file__).resolve().parents[4]
E2E_DIR = Path(__file__).resolve().parent

# Fixed for the session so the provisioning step and the API process agree.
# Both live under the system temp directory; neither is a credential.
E2E_WORK_DIR = Path(tempfile.gettempdir()) / "netsight-e2e"
E2E_ACCOUNT_FILE = E2E_WORK_DIR / "local-accounts.json"
# Generated per run: never a literal secret in the tree, and never reused across runs.
E2E_SESSION_SECRET = secrets.token_urlsafe(48)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
        time.sleep(0.25)
    raise TimeoutError(f"{url} did not become ready: {last}")


class E2EAccount:
    """Credentials for the provisioned local account."""

    def __init__(self, username: str, password: str, totp_secret: str) -> None:
        self.username = username
        self.password = password
        self.totp_secret = totp_secret


@pytest.fixture(scope="session")
def e2e_account(tmp_path_factory: pytest.TempPathFactory) -> E2EAccount:
    """Create one local account with MFA and return its credentials.

    Uses the CLI's own `main()` so the fixture cannot drift from the operator
    workflow. `_read_passwords` is patched because the CLI reads the password
    from the controlling terminal by design (never argv); that is the same seam
    the CLI's unit tests use.
    """

    username = "e2e.admin"
    # >=12 chars and not on the policy denylist (localauth/passwords.py:28-30).
    password = "e2e-only-not-a-real-secret-4711"

    # The CLI and the API must read the same store: provisioning writes here and
    # the running service authenticates against it. The fixture that owns the
    # API process reads the same path, so it is fixed for the session.
    # Reset it first so repeated runs are idempotent: `add` refuses to clobber
    # an existing account, and leftover lockout counters would poison the suite.
    E2E_WORK_DIR.mkdir(parents=True, exist_ok=True)
    E2E_ACCOUNT_FILE.unlink(missing_ok=True)

    env = {
        **os.environ,
        "NETSIGHT_SESSION_SECRET": E2E_SESSION_SECRET,
        "NETSIGHT_LOCAL_ACCOUNT_FILE": str(E2E_ACCOUNT_FILE),
    }

    script = (
        "import sys\n"
        "import netsight_api.localauth.cli as cli\n"
        f"cli._read_passwords = lambda *_: {password!r}\n"
        f"code = cli.main(['add', {username!r}, '--roles', 'administrator'])\n"
        "sys.exit(code)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
    )
    if result.returncode != 0:  # pragma: no cover - surfaced as a test error
        raise RuntimeError(
            f"local account provisioning failed ({result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )

    # `add` prints the enrolment JSON on stdout when MFA is active.
    payload = json.loads(result.stdout)
    return E2EAccount(
        username=payload["created"],
        password=password,
        totp_secret=payload["totp_secret"],
    )


@pytest.fixture(scope="session")
def e2e_api(e2e_account: E2EAccount, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """Run the real API against the stub LibreNMS; yield the endpoint map."""

    api_port = _free_port()
    stub_port = _free_port()

    # Same account store the provisioning fixture wrote to.
    env = {
        **os.environ,
        "NETSIGHT_SESSION_SECRET": E2E_SESSION_SECRET,
        "NETSIGHT_LOCAL_ACCOUNT_FILE": str(E2E_ACCOUNT_FILE),
        "NETSIGHT_SESSION_COOKIE_SECURE": "false",
        "LIBRENMS_BASE_URL": f"http://127.0.0.1:{stub_port}",
        "LIBRENMS_TIMEZONE": "UTC",
        # A non-empty token is required for the adapter to be configured at all
        # (main.py:200); the stub never checks it. Generated per run so no
        # literal credential sits in the source tree, which
        # scripts/security-verify.sh would fail on.
        "LIBRENMS_TOKEN": secrets.token_urlsafe(24),
        # Enable the read-only probe capability so the diagnostics scenario exercises the real
        # allowlisted adapter end to end. `localhost` resolves from the hosts file, so the `dns`
        # check passes without a privileged port and without traffic leaving the machine.
        "BLACKBOX_ALLOWED_TARGETS": "localhost",
        "BLACKBOX_VANTAGE": "internal",
    }

    stub = subprocess.Popen(
        [sys.executable, str(E2E_DIR / "stub_librenms.py"), "--port", str(stub_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "netsight_api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
        ],
        cwd=str(REPO_ROOT / "apps" / "api"),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base = f"http://127.0.0.1:{api_port}"
    try:
        _wait_for(f"{base}/api/v1/health")
        yield {
            "apiUrl": base,
            "stubUrl": f"http://127.0.0.1:{stub_port}",
            "port": str(api_port),
        }
    finally:
        for process in (api, stub):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()


# --- shared HTTP sign-in harness ---------------------------------------------------------------
#
# Lives here (not in a single test module) so every E2E scenario reuses one real sign-in: a TOTP
# code is single-use within its 30-second window and local sign-in is rate-limited, so a second
# sign-in inside the same window is rejected as a replay.


def http_request(
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

    message = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(message, timeout=15) as response:
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


# A TOTP code is single-use per 30-second step (localauth/totp.py); the suite signs in once per
# session, so this hands out the current step at most once and fails loudly on a second attempt.
_CONSUMED_STEPS: set[int] = set()


def _totp_code(secret: str) -> str:
    from netsight_api.localauth.totp import PERIOD_SECONDS, generate_code

    step = int(time.time() // PERIOD_SECONDS)
    if step in _CONSUMED_STEPS:
        pytest.fail(
            "the TOTP step for this window was already consumed; "
            "reuse the session-scoped `signed_in` fixture instead of signing in twice"
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
    """One real sign-in for the whole session; every test reuses this cookie."""

    challenge_status, challenge, _ = http_request(
        f"{e2e_api['apiUrl']}/api/v1/auth/local/login",
        method="POST",
        body={"username": e2e_account.username, "password": e2e_account.password},
    )
    verify_status: int
    verified: dict[str, Any]
    set_cookie: str
    if challenge_status == 202:
        verify_status, verified, set_cookie = http_request(
            f"{e2e_api['apiUrl']}/api/v1/auth/local/mfa/verify",
            method="POST",
            body={
                "challenge_id": challenge["challenge_id"],
                "code": _totp_code(e2e_account.totp_secret),
            },
        )
    else:
        # Surface the failure through the assertions below, not here, so the report names the
        # actual status and body.
        verify_status, verified, set_cookie = challenge_status, challenge, ""

    yield SignIn(
        cookie=_session_cookie(set_cookie) or "",
        challenge_status=challenge_status,
        challenge=challenge,
        verify_status=verify_status,
        verified=verified,
    )
