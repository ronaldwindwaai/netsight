"""Storage for PostgreSQL-owned incident and alert-rule entities (S6-1).

Import the PostgreSQL implementation explicitly from
``netsight_api.storage.postgres``; nothing here opens a database connection.
"""

from netsight_api.storage.errors import (
    IllegalTransitionError,
    InvalidOperationError,
    NotFoundError,
    ScopeViolationError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
)
from netsight_api.storage.memory import InMemoryAlertRuleRepository, InMemoryIncidentRepository
from netsight_api.storage.repository import AlertRuleRepository, IncidentRepository, NoteKind

__all__ = [
    "AlertRuleRepository",
    "IllegalTransitionError",
    "InMemoryAlertRuleRepository",
    "InMemoryIncidentRepository",
    "IncidentRepository",
    "InvalidOperationError",
    "NotFoundError",
    "NoteKind",
    "ScopeViolationError",
    "StorageConfigurationError",
    "StorageConflictError",
    "StorageError",
    "StorageUnavailableError",
]
