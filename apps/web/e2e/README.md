# Netsight end-to-end harness

End-to-end coverage for the critical scenarios in
`docs/09-testing/E2E-SCENARIOS.md`. Scenarios 1-4 (S1 identity and the network
overview chain) are implemented.

## What runs where

| Layer | Location | Runner |
| --- | --- | --- |
| Harness self-test | `apps/api/tests/e2e/` | pytest |
| Browser scenarios | `apps/web/e2e/` | node:test + Playwright |

The pytest side proves the moving parts work against the real API process:
the LibreNMS stub satisfies the adapter contract, local sign-in with mandatory
MFA issues a session, that session authorises a protected route, and an
unauthenticated request is denied. Run it before trusting a browser failure.

```bash
python -m pytest apps/api/tests/e2e -q
```

## Why there is a LibreNMS stub

The platform refuses to invent telemetry (AGENTS.md), so a scenario showing real
device data needs a source that answers. `apps/api/tests/e2e/stub_librenms.py`
serves the smallest surface the adapter reads, with payloads matching the
adapter's own contract tests. It is a real HTTP source, not a mocked adapter, so
URL construction, bearer handling, status mapping and JSON-Schema validation all
execute for real.

Its `count` field always matches the array length. A mismatch is invalid source
data, and the API answers 502 — a trap worth knowing about before editing it.

## Standing up a local stack

The API needs no database. Postgres, Redis and ClickHouse appear in
`infrastructure/compose/docker-compose.dev.yml`, but nothing in `apps/api/src`
imports a database driver; the local-account store is a JSON file. Do not start
the compose stack for E2E.

Three processes: the stub, the API, and the web app.

```bash
# 1. LibreNMS stub
python apps/api/tests/e2e/stub_librenms.py --port 8080

# 2. Platform API (loopback only)
cd apps/api
NETSIGHT_SESSION_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
LIBRENMS_BASE_URL=http://127.0.0.1:8080 \
LIBRENMS_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(24))')" \
LIBRENMS_TIMEZONE=UTC \
python -m uvicorn netsight_api.main:app --host 127.0.0.1 --port 8000

# 3. Web app
NETSIGHT_API_URL=http://127.0.0.1:8000 pnpm --dir apps/web dev
```

Readiness probes: `GET /api/v1/health` on the API (no auth) and `/login` on the
web app.

## Provisioning the local account

`python -m netsight_api.localauth.cli add <username> --roles administrator`
reads the password from the controlling terminal by design, never from argv, so
it cannot be piped. For an unattended run, drive the CLI's `main()` in-process
and patch `_read_passwords` — the seam `apps/api/tests/test_localauth_cli.py`
uses. The `e2e_account` fixture does exactly this and prints the enrolment JSON,
which contains the TOTP secret.

`add` prints `totp_secret`, `provisioning_uri` and ten `recovery_codes`.

## Constraints the specs must respect

These are properties of the security model, not incidental friction. A spec that
works around them is testing the wrong thing.

- **A TOTP code is single-use per 30-second step** (`localauth/totp.py`), and
  verification tolerates only one step of drift. Two sign-ins inside one window
  mean the second is rejected as a replay. Sign in once per browser context and
  reuse the session.
- **Local sign-in is rate-limited**: 5 password attempts and 8 MFA attempts per
  300 seconds, keyed on both client IP and username
  (`localauth/ratelimit.py`). Every spec shares `127.0.0.1`. Never assert a
  failure path by brute force; restart the API between such specs.
- **Complete both credential steps in one uninterrupted context.** The pending
  challenge id is held in `sessionStorage` (`local-signin.tsx`), so a reload
  loses it. Do not reload between the two steps.
- **Assert on the session cookie or the MFA 200**, not on shell markup, while
  checking auth state. The dashboard layout renders the signed-out shell when
  the session read fails.
- **Scope locators to application classes** (`local-signin__*`,
  `identity-avatar`), never AdminLTE shell classes: the route `loading.tsx` and
  `error.tsx` render a full shell with the same markup.

## Asserting source states

Scenario 4 (LibreNMS unavailable) must stop the stub rather than mock a
response, so the real 503 `SOURCE_UNAVAILABLE` path runs and the UI's
source-unavailable state is reached honestly. No panel may render `0` or a
fabricated value in its place.