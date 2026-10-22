"""Storage for PostgreSQL-owned incident and alert-rule entities (S6-1).

Import the PostgreSQL implementation explicitly from
``netsight_api.storage.postgres``; nothing here opens a database connection.
"""

from netsight_api.storage.alert_incidents import (
    AlertIncidentStore,
    InMemoryAlertIncidentStore,
    LinkClaim,
    OpenedIncident,
)
from netsight_api.storage.errors import (
    IllegalTransitionError,
    InvalidOperationError,
    LimitExceededError,
    NotFoundError,
    ScopeViolationError,
    StaleEvidenceError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
)
from netsight_api.storage.links import (
    AlertIncidentLinkRepository,
    InMemoryAlertIncidentLinkRepository,
    LinkKind,
)
from netsight_api.storage.memory import InMemoryAlertRuleRepository, InMemoryIncidentRepository
from netsight_api.storage.repository import AlertRuleRepository, IncidentRepository, NoteKind

__all__ = [
    "AlertIncidentLinkRepository",
    "AlertIncidentStore",
    "AlertRuleRepository",
    "IllegalTransitionError",
    "InMemoryAlertIncidentLinkRepository",
    "InMemoryAlertIncidentStore",
    "InMemoryAlertRuleRepository",
    "InMemoryIncidentRepository",
    "IncidentRepository",
    "InvalidOperationError",
    "LimitExceededError",
    "LinkClaim",
    "LinkKind",
    "NotFoundError",
    "NoteKind",
    "OpenedIncident",
    "ScopeViolationError",
    "StaleEvidenceError",
    "StorageConfigurationError",
    "StorageConflictError",
    "StorageError",
    "StorageUnavailableError",
]
