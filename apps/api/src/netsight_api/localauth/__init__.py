"""Netsight-managed local credentials with mandatory MFA (ADR 0010).

Optional per deployment and always secondary to the federated providers
approved by ADR 0002. A password alone never yields a session.
"""

from __future__ import annotations

from netsight_api.localauth.filestore import FileAccountStore
from netsight_api.localauth.store import LocalAccount, LocalAccountStore

__all__ = ["LocalAccount", "LocalAccountStore", "account_store", "reset_account_store"]


# The API and the operator CLI are separate processes, so the store must be
# durable rather than per-process memory. A file-backed store keeps them
# consistent; Postgres is the multi-node target.
_account_store: FileAccountStore | None = None


def account_store() -> FileAccountStore:
    """Return the process-wide account store, loading it on first use."""
    global _account_store
    if _account_store is None:
        store = FileAccountStore()
        store.load()
        _account_store = store
    return _account_store


def reset_account_store() -> None:
    """Drop the cached store. Test-only helper; never call from request handling."""
    global _account_store
    _account_store = None
