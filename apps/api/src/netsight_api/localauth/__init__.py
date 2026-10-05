"""Netsight-managed local credentials with mandatory MFA (ADR 0010).

Optional per deployment and always secondary to the federated providers
approved by ADR 0002. A password alone never yields a session.
"""

from __future__ import annotations

from netsight_api.localauth.store import LocalAccount, LocalAccountStore

__all__ = ["LocalAccount", "LocalAccountStore", "account_store", "reset_account_store"]


_account_store = LocalAccountStore()


def account_store() -> LocalAccountStore:
    """Return the process-wide account store."""
    return _account_store


def reset_account_store() -> None:
    """Drop all accounts. Test-only helper; never call from request handling."""
    global _account_store
    _account_store = LocalAccountStore()