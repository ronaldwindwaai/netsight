"""Storage-layer errors.

Validation problems on caller input surface as ``ValueError`` (pydantic's
``ValidationError`` is one); the classes below describe domain outcomes the
route layer maps to HTTP statuses. Messages never contain connection strings.
"""

from __future__ import annotations


class StorageError(Exception):
    """Base class for storage-domain failures."""


class NotFoundError(StorageError):
    """The referenced entity does not exist (or its id is malformed)."""


class IllegalTransitionError(StorageError):
    """The requested state change or mutation is not allowed from the current state."""


class InvalidOperationError(StorageError):
    """The request is well-formed but violates a domain rule (for example no reopen reason)."""


class LimitExceededError(StorageError):
    """A configuration capacity cap (rules, live windows) is reached; nothing was written.

    Raised inside the write, under the same lock as the insert, so concurrent creators cannot
    jointly exceed a cap (HTTP 409 at the route layer).
    """


class ScopeViolationError(StorageError):
    """The caller's scope does not cover the locked row (assigned-incidents-only callers on an
    incident, callers without ``maintenance:write-organisation`` on an organisation window).

    Raised from inside the write, under the same row lock as the change, so a reassignment or
    scope change between authorisation and write cannot be raced (HTTP 403 at the route layer).
    """


class StorageConfigurationError(StorageError):
    """Storage settings are missing or invalid."""


class StorageConflictError(StorageError):
    """A concurrent or stale write lost: unique key taken, stale version, serialization failure.

    Retryable after the caller re-reads the current state (HTTP 409 at the route layer).
    """


class StorageUnavailableError(StorageError):
    """The database could not serve the request in time: unreachable, lock or statement timeout.

    Transient; the route layer degrades or answers 503. Never carries connection details.
    """
