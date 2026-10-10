"""Server-side session management.

Sessions are opaque, stored server-side, and referenced by an HMAC-signed
random identifier in a Secure/HttpOnly/SameSite cookie. Access and refresh
tokens are never exposed to the browser. Enforces sliding inactivity and
absolute lifetime policies and supports explicit revocation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal, TypedDict

from netsight_api.auth.settings import SessionPolicy, session_policy


class CookieAttributes(TypedDict):
    key: str
    max_age: int
    path: str
    domain: str | None
    secure: bool
    httponly: bool
    samesite: Literal["lax", "strict", "none"]


@dataclass
class Session:
    id: str
    subject: str
    provider: str
    roles: frozenset[str] = field(default_factory=frozenset)
    email: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    # Store-clock time at which the sign-in proved a second factor; None when it did not or
    # when that cannot be established (step-up checks then fail closed).
    mfa_verified_at: float | None = None

    @property
    def identity_id(self) -> str:
        return f"{self.provider}:{self.subject}"


def _now() -> float:
    return time.monotonic()


class SessionStore:
    """Thread-safe in-memory session store.

    Production deployments should back this with a shared store (for example
    Redis) so sessions survive restarts and work across API workers. The
    interface is deliberately narrow to make that swap mechanical.

    ``clock`` is injectable so expiry behaviour is testable deterministically
    instead of with sleeps (platform timer resolution makes sleeps unreliable).
    """

    def __init__(self, clock: Callable[[], float] = _now) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._clock = clock

    def now(self) -> float:
        """The store clock; MFA ages are measured on it, never on a different clock."""
        return self._clock()

    def create(
        self,
        subject: str,
        provider: str,
        roles: Iterable[str],
        email: str | None = None,
        *,
        mfa_age_seconds: float | None = None,
    ) -> Session:
        session_id = secrets.token_urlsafe(32)
        stamped_at = self._clock()
        session = Session(
            id=session_id,
            subject=subject,
            provider=provider,
            roles=frozenset(roles),
            email=email,
            created_at=stamped_at,
            last_activity=stamped_at,
            mfa_verified_at=None if mfa_age_seconds is None else stamped_at - mfa_age_seconds,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str, policy: SessionPolicy) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            now = self._clock()
            if now - session.created_at > policy.absolute_lifetime:
                del self._sessions[session_id]
                return None
            if now - session.last_activity > policy.inactivity_timeout:
                del self._sessions[session_id]
                return None
            session.last_activity = now
            return session

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def revoke_subject(self, provider: str, subject: str) -> None:
        identity_id = f"{provider}:{subject}"
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.identity_id == identity_id]
            for sid in expired:
                del self._sessions[sid]

    def prune(self, policy: SessionPolicy) -> int:
        now = self._clock()
        with self._lock:
            expired = [
                sid
                for sid, s in self._sessions.items()
                if now - s.created_at > policy.absolute_lifetime
                or now - s.last_activity > policy.inactivity_timeout
            ]
            for sid in expired:
                del self._sessions[sid]
        return len(expired)


class SessionManager:
    """Owns the session store, cookie signing and CSRF tokens."""

    def __init__(self, store: SessionStore, policy: SessionPolicy) -> None:
        self.store = store
        self.policy = policy
        self._signing_key = self._resolve_signing_key(policy)

    @staticmethod
    def _resolve_signing_key(policy: SessionPolicy) -> bytes:
        if policy.secret:
            return policy.secret.encode("utf-8")
        # Development-only: derive an ephemeral key so no secret is embedded and
        # sessions do not survive a restart. Production must set an explicit secret.
        return secrets.token_bytes(32)

    def create_session(
        self,
        subject: str,
        provider: str,
        roles: Iterable[str],
        email: str | None = None,
        *,
        mfa_age_seconds: float | None = None,
    ) -> Session:
        """``mfa_age_seconds``: how long ago the sign-in's second factor happened (the token's
        own ``auth_time``), mapped onto the store clock; None when it is not proven."""
        return self.store.create(
            subject, provider, roles, email, mfa_age_seconds=mfa_age_seconds
        )

    def mfa_age(self, session: Session) -> float | None:
        """Seconds since the second factor; None when unknown (never, or a stamp from the future)."""
        stamped_at = session.mfa_verified_at
        if stamped_at is None:
            return None
        age = self.store.now() - stamped_at
        return age if age >= 0 else None

    def cookie_value(self, session: Session) -> str:
        """Return the signed, opaque cookie value for a session."""
        return self._sign(session.id)

    def validate_cookie(self, cookie_value: str | None) -> Session | None:
        if not cookie_value:
            return None
        session_id = self._verify_signed_id(cookie_value)
        if session_id is None:
            return None
        return self.store.get(session_id, self.policy)

    def revoke(self, session_id: str) -> None:
        self.store.revoke(session_id)

    def revoke_subject(self, provider: str, subject: str) -> None:
        self.store.revoke_subject(provider, subject)

    def prune(self) -> int:
        return self.store.prune(self.policy)

    def _sign(self, session_id: str) -> str:
        mac = hmac.new(self._signing_key, session_id.encode("utf-8"), hashlib.sha256).digest()
        raw = f"{session_id}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode('ascii')}"
        return base64.urlsafe_b64encode(raw.encode("ascii")).rstrip(b"=").decode("ascii")

    def _verify_signed_id(self, value: str) -> str | None:
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("ascii")
        except (ValueError, UnicodeError):
            return None
        session_id, separator, _signature = raw.partition(".")
        if not separator or not session_id:
            return None
        expected = self._sign(session_id)
        if not hmac.compare_digest(expected, value):
            return None
        return session_id

    def cookie_attributes(self) -> CookieAttributes:
        """Return Starlette ``set_cookie`` keyword arguments for the session cookie."""
        return {
            "key": self.policy.cookie_name,
            "max_age": self.policy.absolute_lifetime,
            "path": "/",
            "domain": self.policy.cookie_domain or None,
            "secure": self.policy.secure_cookie,
            "httponly": True,
            "samesite": self.policy.same_site,
        }


_manager: SessionManager | None = None


def session_manager() -> SessionManager:
    global _manager
    if _manager is None:
        _manager = SessionManager(SessionStore(), session_policy())
    return _manager


def new_csrf_token(session: Session) -> str:
    session.csrf_token = secrets.token_urlsafe(24)
    return session.csrf_token


def constant_time_equals(left: str, right: str) -> bool:
    """Compare as UTF-8 bytes: ``hmac.compare_digest`` raises TypeError on non-ASCII ``str``."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
