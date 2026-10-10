"""Step-up authentication: a recent second factor for high-consequence writes.

Incident resolve and reopen record a human judgement and can rewrite the record, so a
session that signed in long ago (or whose sign-in cannot show a second factor) is not
enough. The decision is made against the very session object the request authenticated
with (``request.state.auth``) and on the session store's clock.

Fails closed: an unknown MFA time (the sign-in did not assert one, the stamp is from the
future, or the identity has no session) is a refusal. The one exception is the
development identity bridge, which has no session at all and exists only for local
development (see ``auth/deps.py``); it can never be enabled in production.
"""

from __future__ import annotations

from fastapi import Request

from netsight_api.auth.csrf import Refusal
from netsight_api.auth.deps import get_request_auth
from netsight_api.auth.session import session_manager
from netsight_api.auth.settings import auth_settings

STEP_UP_CODE = "STEP_UP_REQUIRED"
_STEP_UP_REFUSAL = Refusal(
    "step-up",
    STEP_UP_CODE,
    "Recent multi-factor authentication is required for this action; sign in again",
)


def step_up_refusal(request: Request) -> Refusal | None:
    """None when the caller proved a second factor recently enough; otherwise the refusal."""
    auth = get_request_auth(request)
    if auth is None or auth.session is None:
        # The development bridge is the only auth source without a session.
        return None if auth is not None and auth.source == "dev-bridge" else _STEP_UP_REFUSAL
    age = session_manager().mfa_age(auth.session)
    if age is None or age > auth_settings().step_up_max_age_seconds:
        return _STEP_UP_REFUSAL
    return None
