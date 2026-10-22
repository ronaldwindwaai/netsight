"""Route/permission table: every API route is authenticated and permission-gated, or is listed.

The table is built from the live FastAPI app (``app.openapi()``), so a route added tomorrow is
covered without anyone remembering to register it here. Two behavioural probes run per route:

* **Anonymous** (no session): every route must answer 401 unless it is in
  ``PUBLIC_ROUTES`` (with the reason it is public).
* **Authenticated, zero permissions** (a valid human identity that holds no role): every route
  must answer 403 unless it is in ``ANY_AUTHENTICATED_ROUTES`` (identity-only endpoints such as
  ``/auth/session``). A route that authenticates but never checks a permission answers 200 here
  and fails the test. A mutating route whose handler validates the body before it checks the
  permission answers 422 for the empty probe body; those are accepted only when the route takes a
  request body, and the per-area ``test_rbac_*`` suites cover their permission checks.

Adding a route without an auth dependency (or without a permission check) fails this test; the
fix is to guard the route, or to add it to an allowlist below *with a reason* in review.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.deps import get_current_identity
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind

API = "/api/v1"
METHODS = ("get", "post", "put", "patch", "delete")
ZERO_UUID = "00000000-0000-0000-0000-000000000000"

# Intentionally unauthenticated: liveness, the sign-in flow itself (it creates the session), and
# the session-dependent logout (it only acts on the caller's own cookie).
PUBLIC_ROUTES: dict[str, str] = {
    f"GET {API}/health": "liveness probe, no data",
    f"GET {API}/auth/providers": "login page needs the provider list before any session exists",
    f"GET {API}/auth/login/{{provider}}": "starts the OIDC redirect",
    f"GET {API}/auth/callback": "OIDC redirect target; validates state/nonce itself",
    f"POST {API}/auth/logout": "acts only on the caller's own session cookie",
    f"POST {API}/auth/local/login": "password step of local sign-in; never grants a session alone",
    f"POST {API}/auth/local/mfa/verify": "MFA step of local sign-in, bound to a challenge",
    f"POST {API}/auth/local/mfa/activate": "enrolment bound to a challenge",
    f"POST {API}/auth/local/password/change": "forced password change bound to a challenge",
}

# Authenticated but deliberately not permission-gated: they describe the caller's own session.
ANY_AUTHENTICATED_ROUTES: dict[str, str] = {
    f"GET {API}/auth/session": "the caller's own identity",
    f"GET {API}/auth/csrf": "the caller's own CSRF token",
}


def _operations() -> Iterator[tuple[str, str, str, dict[str, Any]]]:
    for path, ops in app.openapi()["paths"].items():
        for method, operation in ops.items():
            if method in METHODS:
                yield f"{method.upper()} {path}", method, path, operation


def _path_value(schema: dict[str, Any]) -> str:
    """A value that satisfies the parameter's declared pattern/length, so the probe reaches auth."""
    pattern = schema.get("pattern")
    if not pattern:
        return ZERO_UUID
    prefix = re.split(r"[\[(]", pattern.lstrip("^"), maxsplit=1)[0]
    for candidate in (ZERO_UUID, f"{prefix}{ZERO_UUID}"):
        if re.fullmatch(pattern, candidate):
            return candidate
    return ZERO_UUID


def _url(path: str, operation: dict[str, Any]) -> str:
    values = {
        p["name"]: _path_value(p.get("schema", {}))
        for p in operation.get("parameters", [])
        if p.get("in") == "path"
    }
    return re.sub(r"\{([^}]+)\}", lambda m: values.get(m.group(1), ZERO_UUID), path)


def _call(client: TestClient, method: str, path: str, operation: dict[str, Any]) -> int:
    kwargs: dict[str, Any] = {}
    if method != "get":
        kwargs["json"] = {}
        kwargs["headers"] = {"Origin": "http://localhost:3000", "X-CSRF-Token": "probe"}
    return client.request(method.upper(), _url(path, operation), **kwargs).status_code


@pytest.fixture
def anonymous_client() -> Iterator[TestClient]:
    app.dependency_overrides.clear()
    yield TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def zero_permission_client() -> Iterator[TestClient]:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "nobody", frozenset(), PrincipalKind.HUMAN
    )
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def test_the_route_table_is_not_empty() -> None:
    assert len(list(_operations())) > 50


def test_every_route_requires_authentication_unless_listed_public(
    anonymous_client: TestClient,
) -> None:
    unauthenticated = [
        f"{key} -> {status}"
        for key, method, path, operation in _operations()
        if key not in PUBLIC_ROUTES
        and (status := _call(anonymous_client, method, path, operation)) != 401
    ]
    assert unauthenticated == [], (
        "routes answered an anonymous caller with something other than 401; add an auth "
        f"dependency or an explicit PUBLIC_ROUTES entry: {unauthenticated}"
    )


def test_public_allowlist_has_no_stale_entries() -> None:
    known = {key for key, *_ in _operations()}
    stale = sorted((set(PUBLIC_ROUTES) | set(ANY_AUTHENTICATED_ROUTES)) - known)
    assert stale == []


def test_every_route_checks_a_permission_unless_listed(
    zero_permission_client: TestClient,
) -> None:
    ungated = []
    for key, method, path, operation in _operations():
        if key in PUBLIC_ROUTES or key in ANY_AUTHENTICATED_ROUTES:
            continue
        status = _call(zero_permission_client, method, path, operation)
        validation_first = status == 422 and "requestBody" in operation
        if status != 403 and not validation_first:
            ungated.append(f"{key} -> {status}")
    assert ungated == [], (
        "an authenticated caller with no permissions got through; add a permission check "
        f"(and an RBAC-MATRIX row): {ungated}"
    )


def test_interactive_docs_are_not_served_without_authentication(
    anonymous_client: TestClient,
) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert anonymous_client.get(path).status_code in {401, 404}, path
