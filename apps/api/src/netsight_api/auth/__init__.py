"""Netsight authentication package (OIDC, sessions, RBAC wiring)."""

from __future__ import annotations

from netsight_api.auth.deps import get_current_identity, get_session
from netsight_api.auth.routes import router

__all__ = ["get_current_identity", "get_session", "router"]
