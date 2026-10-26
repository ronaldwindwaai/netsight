"""Local demo environment: a throwaway account plus fixture data, on loopback only.

Starts the loopback LibreNMS and Oxidized stubs (fixture devices, ports and config
backups) and the real API pointed at them, with seeded in-memory incidents, and provisions one local administrator account through the same
CLI an operator uses. Nothing here talks to a real monitoring system, and every
listener binds to 127.0.0.1.

    python scripts/demo-local.py            # run from the repo root
    python scripts/demo-local.py --reset    # forget the demo account and start clean

The first run prints the username, password and TOTP secret ONCE, in this
terminal. Only a password hash and an encrypted TOTP secret are stored (under
`.demo/`, which is git-ignored). Add the TOTP secret or the provisioning URI to
an authenticator app, then sign in at the web app.

Then, in a second terminal:

    cd apps/web && npm run dev          # http://localhost:3000
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "apps" / "api"
STUB = API_DIR / "tests" / "e2e" / "stub_librenms.py"
OXIDIZED_STUB = API_DIR / "tests" / "e2e" / "stub_oxidized.py"
NETBOX_STUB = API_DIR / "tests" / "e2e" / "stub_netbox.py"
WAZUH_STUB = API_DIR / "tests" / "e2e" / "stub_wazuh.py"
CLICKHOUSE_STUB = API_DIR / "tests" / "e2e" / "stub_clickhouse.py"
E2E_DIR = (
    API_DIR / "tests" / "e2e"
)  # holds demo_app.py: the API with seeded demo incidents
DEMO_DIR = Path(os.environ.get("NETSIGHT_DEMO_DIR", REPO_ROOT / ".demo"))
ACCOUNT_FILE = DEMO_DIR / "local-accounts.json"
SECRET_FILE = DEMO_DIR / "session-secret"

HOST = "127.0.0.1"
API_PORT = 8000  # the web app's default NETSIGHT_API_URL
STUB_PORT = 8081
OXIDIZED_PORT = 8082
NETBOX_PORT = 8083
WAZUH_PORT = 8084
CLICKHOUSE_PORT = 8085
USERNAME = "demo.admin"


def _session_secret() -> str:
    """A stable per-checkout secret, so the stored TOTP envelope stays readable."""
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:  # pragma: no cover - not supported on every filesystem
        pass
    return value


def _provision(env: dict[str, str]) -> dict[str, str] | None:
    """Create the account through the operator CLI; None if it already exists."""
    if ACCOUNT_FILE.exists():
        return None
    password = secrets.token_urlsafe(18)
    # The CLI reads the password from the terminal by design (never argv); patch
    # that one seam, exactly as the E2E harness does.
    script = (
        "import sys\n"
        "import netsight_api.localauth.cli as cli\n"
        f"cli._read_passwords = lambda *_: {password!r}\n"
        f"sys.exit(cli.main(['add', {USERNAME!r}, '--roles', 'administrator']))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(API_DIR),
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"account provisioning failed ({result.returncode}); see the API logs"
        )
    payload = json.loads(result.stdout)
    return {
        "username": payload["created"],
        "password": password,
        "totp_secret": payload["totp_secret"],
        "uri": payload.get("provisioning_uri", ""),
        "recovery_codes": ", ".join(payload.get("recovery_codes", [])),
    }


def _wait_for(url: str, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.3)
    raise SystemExit(f"{url} did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--reset", action="store_true", help="delete the demo account and secret"
    )
    args = parser.parse_args()

    if args.reset:
        shutil.rmtree(DEMO_DIR, ignore_errors=True)
        print("Demo account removed. Run again to create a new one.")
        return 0

    env = {
        **os.environ,
        "NETSIGHT_ENV": "development",
        # Required by tests/e2e/demo_app.py, which refuses to install its fixtures without it.
        "NETSIGHT_DEMO": "1",
        "NETSIGHT_SESSION_SECRET": _session_secret(),
        "NETSIGHT_LOCAL_ACCOUNT_FILE": str(ACCOUNT_FILE),
        # DEMO ONLY: plain http on loopback, so the browser must be allowed to keep the cookie.
        # Never set NETSIGHT_SESSION_COOKIE_SECURE=false outside this demo.
        "NETSIGHT_SESSION_COOKIE_SECURE": "false",
        "LIBRENMS_BASE_URL": f"http://{HOST}:{STUB_PORT}",
        "LIBRENMS_TIMEZONE": "UTC",
        # Fixture configuration backups (loopback Oxidized stub) and a volatile action store.
        "OXIDIZED_BASE_URL": f"http://{HOST}:{OXIDIZED_PORT}",
        # Fixture NetBox (loopback stub): topology map, inventory and IPAM. The stub never checks the token.
        "NETBOX_BASE_URL": f"http://{HOST}:{NETBOX_PORT}",
        "NETBOX_TOKEN": secrets.token_urlsafe(24),
        # Fixture Wazuh indexer (loopback stub, no credentials): the Security screen.
        "WAZUH_INDEXER_URL": f"http://{HOST}:{WAZUH_PORT}",
        # Fixture ClickHouse flows (loopback stub, synthetic traffic): the Traffic screens.
        "CLICKHOUSE_DSN": f"http://{HOST}:{CLICKHOUSE_PORT}",
        # DEMO ONLY: turns the action workflow on against a throwaway store; keep off in production.
        "NETSIGHT_ACTIONS_ENABLED": "1",
        # The adapter needs a non-empty token to count as configured; the stub never checks it.
        "LIBRENMS_TOKEN": secrets.token_urlsafe(24),
    }

    created = _provision(env)

    stub = subprocess.Popen(
        [sys.executable, str(STUB), "--port", str(STUB_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    oxidized = subprocess.Popen(
        [sys.executable, str(OXIDIZED_STUB), "--port", str(OXIDIZED_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    netbox = subprocess.Popen(
        [sys.executable, str(NETBOX_STUB), "--port", str(NETBOX_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wazuh = subprocess.Popen(
        [sys.executable, str(WAZUH_STUB), "--port", str(WAZUH_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    clickhouse = subprocess.Popen(
        [sys.executable, str(CLICKHOUSE_STUB), "--port", str(CLICKHOUSE_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "demo_app:build_app",
            "--factory",
            "--app-dir",
            str(E2E_DIR),
            "--host",
            HOST,
            "--port",
            str(API_PORT),
        ],
        cwd=str(API_DIR),
        env=env,
    )
    try:
        _wait_for(f"http://{HOST}:{API_PORT}/api/v1/health")
        print("\n=== Netsight demo ===")
        print(f"API   http://{HOST}:{API_PORT}   (fixture LibreNMS on :{STUB_PORT})")
        print("Web   cd apps/web && npm run dev   ->  http://localhost:3000")
        if created:
            print("\nSign-in (shown once; store them now):")
            print(f"  username     {created['username']}")
            print(f"  password     {created['password']}")
            print(f"  TOTP secret  {created['totp_secret']}")
            if created["uri"]:
                print(f"  TOTP URI     {created['uri']}")
            if created["recovery_codes"]:
                print(f"  recovery     {created['recovery_codes']}")
        else:
            print(
                f"\nAccount '{USERNAME}' already exists (credentials were shown at creation)."
            )
            print("Run with --reset to create a fresh one.")
        print(
            "\nFixture data: LibreNMS devices and ports, NetBox topology/IPAM, Wazuh/Suricata events, ClickHouse flows, Oxidized backups, and seeded"
        )
        print(
            "incidents (in memory; reset on restart). Actions are on, with a volatile store."
        )
        print("The other sources show 'Not connected'.")
        print("Ctrl+C to stop.\n")
        api.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for process in (api, stub, oxidized, netbox, wazuh, clickhouse):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
