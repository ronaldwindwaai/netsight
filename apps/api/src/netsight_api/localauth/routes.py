"""HTTP endpoints for Netsight-managed local credentials (ADR 0010).

Login is deliberately two-step. A verified password only ever produces a
short-lived challenge; the session cookie is issued when the second factor is
redeemed. Every failure path returns an identical envelope so an attacker
cannot distinguish an unknown account from a wrong password.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.session import session_manager
from netsight_api.auth.settings import session_policy
from netsight_api.errors import ApiError
from netsight_api.localauth import account_store, totp
from netsight_api.localauth.audit import record as audit
from netsight_api.localauth.challenges import challenge_store
from netsight_api.localauth.crypto import (
    SecretEncryptionError,
    decrypt_secret,
    encrypt_secret,
)
from netsight_api.localauth.enrolment import pending_enrolment_store
from netsight_api.localauth.passwords import (
    check_password_policy,
    hash_password,
    verify_password,
)
from netsight_api.localauth.ratelimit import local_auth_limiter
from netsight_api.localauth.recovery import (
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_codes,
)
from netsight_api.rbac import Identity, Permission, is_allowed

router = APIRouter(prefix="/auth/local", tags=["auth-local"])

# Every credential failure returns this identical code and message.
_INVALID_CREDENTIALS = (401, "AUTH_INVALID_CREDENTIALS", "Username or password is not valid")
_INVALID_SECOND_FACTOR = (401, "MFA_INVALID_CODE", "The verification code is not valid")
_CHALLENGE_INVALID = (401, "MFA_CHALLENGE_INVALID", "Sign-in could not be completed")
_RATE_LIMITED = (429, "RATE_LIMITED", "Too many attempts. Try again later.")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class MfaVerifyRequest(StrictModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=32)


class EnrollActivateRequest(StrictModel):
    code: str = Field(min_length=1, max_length=32)


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _session_secret() -> str:
    secret = session_policy().secret
    if not secret:
        raise ApiError(
            503,
            "MFA_UNAVAILABLE",
            "Local credentials are unavailable until a session secret is configured",
        )
    return secret


def _issue_session(
    request: Request, response: Response, username: str, roles: frozenset[str], email: str | None
) -> None:
    manager = session_manager()
    session = manager.create_session(
        subject=f"local:{username}",
        provider="local",
        roles=roles,
        email=email,
        # Only reachable after a redeemed challenge and a verified second factor.
        mfa_age_seconds=0.0,
    )
    # Rotation: the session the browser presented (if any) must not outlive the new one.
    manager.revoke_cookie(request.cookies.get(manager.policy.cookie_name))
    response.set_cookie(value=manager.cookie_value(session), **manager.cookie_attributes())


@router.post("/login")
async def login(body: LoginRequest, request: Request) -> Response:
    """Verify a password and return a second-factor challenge.

    Never sets a session cookie: a password alone is not authentication.
    """
    client_ip = _client_ip(request)
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    username = body.username.strip().lower()
    limiter = local_auth_limiter()

    if not limiter.allow_password(client_ip, username):
        audit(
            "login",
            outcome="denied",
            correlation_id=correlation_id,
            username=username,
            reason="rate_limited",
        )
        raise ApiError(
            *_RATE_LIMITED,
            headers={"Retry-After": str(limiter.password_retry_after(client_ip, username))},
        )

    store = account_store()
    challenge_result = store.authenticate_password(username, body.password)

    if not challenge_result.ok or challenge_result.account is None:
        audit("login", outcome="failure", correlation_id=correlation_id, username=username)
        # Identical response whether the account is unknown, disabled, locked
        # or the password was simply wrong.
        raise ApiError(*_INVALID_CREDENTIALS)

    account = challenge_result.account
    pending = challenge_store().issue(
        username=account.username,
        client_ip=client_ip,
        roles=account.roles,
        email=None,
    )

    audit(
        "password_verified",
        outcome="success",
        correlation_id=correlation_id,
        username=account.username,
        mfa_enrolled=account.is_mfa_active(),
    )

    return JSONResponse(
        status_code=202,
        content={
            "challenge_id": pending.id,
            "mfa_required": True,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/mfa/verify")
async def verify_second_factor(
    body: MfaVerifyRequest,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Redeem a challenge with a second factor and issue the session."""
    client_ip = _client_ip(request)
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    limiter = local_auth_limiter()

    challenge = challenge_store().redeem(body.challenge_id, client_ip)
    if challenge is None:
        audit("mfa", outcome="failure", correlation_id=correlation_id, reason="invalid_challenge")
        raise ApiError(*_CHALLENGE_INVALID)

    username = challenge.username
    if not limiter.allow_mfa(client_ip, username):
        audit(
            "mfa",
            outcome="denied",
            correlation_id=correlation_id,
            username=username,
            reason="rate_limited",
        )
        raise ApiError(
            *_RATE_LIMITED,
            headers={"Retry-After": str(limiter.mfa_retry_after(client_ip, username))},
        )

    store = account_store()
    account = store.get(username)
    if account is None or not account.enabled:
        audit("mfa", outcome="failure", correlation_id=correlation_id, username=username)
        raise ApiError(*_CHALLENGE_INVALID)

    verified = _verify_second_factor(account, body.code)
    if not verified:
        # Deliberately does NOT advance the account's password lockout counter:
        # that counter models password guessing. A mistyped second factor is
        # already bounded by the per-account and per-client MFA rate limit and
        # by the single-use challenge, and charging it to the lockout would
        # lock an honest user out after two typos.
        audit("mfa", outcome="failure", correlation_id=correlation_id, username=username)
        raise ApiError(*_INVALID_SECOND_FACTOR)

    store.register_success(username)
    _issue_session(request, response, account.username, account.roles, challenge.email)
    audit(
        "login",
        outcome="success",
        correlation_id=correlation_id,
        username=account.username,
        factor="totp",
    )

    return {
        "authenticated": True,
        "identity_id": f"local:{account.username}",
        "provider": "local",
        "roles": sorted(account.roles),
    }


def _verify_second_factor(account: Any, code: str) -> bool:
    """Verify a TOTP code, or fall back to a recovery code."""
    if account.encrypted_totp is None:
        # No enrolled factor: a recovery code is the only way in.
        consumed = consume_recovery_code(account.recovery_code_hashes, code)
        if consumed is None:
            return False
        account.recovery_code_hashes = [
            stored for stored in account.recovery_code_hashes if stored != consumed
        ]
        account.last_totp_counter = None
        account_store().save(account)
        return True

    try:
        secret = decrypt_secret(account.encrypted_totp, _session_secret())
    except SecretEncryptionError:
        return False

    counter = totp.verify_code(
        secret,
        code,
        last_used_counter=account.last_totp_counter,
    )
    if counter is not None:
        account.last_totp_counter = counter
        account_store().save(account)
        return True

    # Fall back to a recovery code so a lost authenticator is recoverable.
    consumed = consume_recovery_code(account.recovery_code_hashes, code)
    if consumed is None:
        return False
    account.recovery_code_hashes = [
        stored for stored in account.recovery_code_hashes if stored != consumed
    ]
    account_store().save(account)
    return True


# --- enrolment -------------------------------------------------------------


class EnrollResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret: str
    provisioning_uri: str
    qr_svg: str
    message: str


@router.post("/mfa/enroll", response_model=EnrollResponse, status_code=201)
async def begin_enrolment(
    request: Request,
    _identity: Annotated[Identity, Depends(get_current_identity)],
) -> EnrollResponse:
    """Issue a TOTP secret for an authenticated identity.

    Reachable by any signed-in identity, including a federated administrator
    provisioning a local account; the secret is returned exactly once here and
    only after :func:`activate_enrolment` is stored encrypted.
    """
    identity = _identity
    if not is_allowed(identity, Permission.DEVICES_READ.value):
        raise ApiError(403, "FORBIDDEN", "Permission is required")

    correlation_id = getattr(request.state, "correlation_id", "unknown")
    subject = identity.id.split(":", 1)[-1]
    secret = totp.generate_secret()
    # Held only until activation; a half-finished enrolment expires.
    pending_enrolment_store().put(identity.id, secret)
    audit("mfa_enrol_started", outcome="success", correlation_id=correlation_id, subject=subject)

    return EnrollResponse(
        secret=secret,
        provisioning_uri=totp.provisioning_uri(secret, subject),
        qr_svg=totp.qr_code_svg(secret, subject),
        message="Scan the code, then confirm with a generated code to finish.",
    )


class ActivateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activated: bool
    recovery_codes: list[str]


@router.post("/mfa/activate", response_model=ActivateResponse)
async def activate_enrolment(
    body: EnrollActivateRequest,
    request: Request,
    _identity: Annotated[Identity, Depends(get_current_identity)],
) -> ActivateResponse:
    """Confirm possession of the generated secret and issue recovery codes.

    The pending secret is consumed on the first attempt, whether or not the
    supplied code is correct, so it cannot be brute-forced.
    """
    identity = _identity
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    store = account_store()

    account = store.get(identity.id.split(":", 1)[-1])
    if account is None:
        raise ApiError(404, "ACCOUNT_NOT_FOUND", "No local account is linked to this identity")

    secret = pending_enrolment_store().take(identity.id)
    if secret is None:
        raise ApiError(
            409,
            "MFA_ENROLMENT_NOT_STARTED",
            "Start enrolment before activating",
        )

    if totp.verify_code(secret, body.code) is None:
        audit(
            "mfa_activated",
            outcome="failure",
            correlation_id=correlation_id,
            username=account.username,
        )
        raise ApiError(*_INVALID_SECOND_FACTOR)

    codes = generate_recovery_codes()
    updated = account.with_totp_enrolled(
        encrypted_totp=encrypt_secret(secret, _session_secret()),
        recovery_code_hashes=hash_recovery_codes(codes),
        now=0.0,
    )
    store.save(updated)

    audit(
        "mfa_activated", outcome="success", correlation_id=correlation_id, username=account.username
    )
    return ActivateResponse(activated=True, recovery_codes=codes)


# --- password change -------------------------------------------------------


def _local_account_for(identity: Identity) -> Any:
    """Return the local account behind a session identity, or fail closed."""
    account = account_store().get(identity.id.split(":", 1)[-1])
    if account is None:
        raise ApiError(404, "ACCOUNT_NOT_FOUND", "No local account is linked to this identity")
    return account


@router.post("/password/change")
async def change_password(
    body: PasswordChangeRequest,
    request: Request,
    identity: Annotated[Identity, Depends(get_current_identity)],
) -> dict[str, Any]:
    """Change a local account password, requiring the current password."""
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    store = account_store()
    account = _local_account_for(identity)

    if not verify_password(account.password_hash, body.current_password):
        store.register_failure(account.username)
        audit(
            "password_change",
            outcome="failure",
            correlation_id=correlation_id,
            username=account.username,
        )
        raise ApiError(*_INVALID_CREDENTIALS)

    policy = check_password_policy(body.new_password)
    if not policy.ok:
        raise ApiError(422, policy.code or "PASSWORD_POLICY", policy.message or "Password rejected")

    if verify_password(account.password_hash, body.new_password):
        raise ApiError(
            422,
            "PASSWORD_REUSED",
            "The new password must differ from the current one",
        )

    account.password_hash = hash_password(body.new_password)
    account.password_changed_at = 0.0
    account.record_success()
    store.save(account)

    audit(
        "password_change",
        outcome="success",
        correlation_id=correlation_id,
        username=account.username,
    )
    return {"changed": True}
