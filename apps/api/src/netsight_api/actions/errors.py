"""Refusals of the action engine. Each carries a static ``code`` and the HTTP status it maps to.

Messages never include request content: they are fixed sentences the API can send as they are.
"""

from __future__ import annotations


class ActionError(Exception):
    """Base of every refusal. ``code`` is stable and safe to log, audit and return."""

    code = "ACTION_ERROR"
    status = 409
    message = "The action request could not be changed"

    def __init__(self) -> None:
        super().__init__(self.message)


class ActionNotFound(ActionError):
    code, status, message = "NOT_FOUND", 404, "Action request not found"


class StaleRequest(ActionError):
    code, status = "STALE_REQUEST", 409
    message = "The request changed since you looked at it; reload and review it again"


class IllegalTransition(ActionError):
    code, status = "ILLEGAL_STATE", 409
    message = "The request is not in a state that allows this"


class SelfApproval(ActionError):
    code, status = "SELF_APPROVAL", 409
    message = "A request cannot be approved by the person who made it"


class ApproverNotHuman(ActionError):
    code, status = "APPROVER_NOT_HUMAN", 403
    message = "Only a person can approve an action"


class AlreadyApproved(ActionError):
    code, status = "ALREADY_APPROVED", 409
    message = "You have already approved this request"


class ApprovalExpired(ActionError):
    code, status = "EXPIRED", 409
    message = "The request expired"


class IdempotencyConflict(ActionError):
    code, status = "IDEMPOTENCY_CONFLICT", 409
    message = "That idempotency key was already used for a different request"


class DuplicateOpenRequest(ActionError):
    code, status = "ALREADY_OPEN", 409
    message = "An open request for this action and target already exists"


class TooManyOpenRequests(ActionError):
    code, status = "TOO_MANY_OPEN", 409
    message = "You have too many open action requests; resolve some first"


class StoreFull(ActionError):
    code, status = "STORE_FULL", 503
    message = "The action store is full"


class TargetLocked(ActionError):
    code, status = "TARGET_LOCKED", 409
    message = "Another action is running on this target"


class KillSwitchEngaged(ActionError):
    code, status = "KILL_SWITCH", 503
    message = "Remote actions are stopped by the kill switch"


class KillSwitchLocked(ActionError):
    code, status = "KILL_SWITCH_LOCKED", 409
    message = "The kill switch is set in the environment and cannot be released here"


class NotOwner(ActionError):
    code, status, message = "FORBIDDEN", 403, "Permission is required"


class FindingsUnavailable(ActionError):
    code, status = "FINDINGS_UNAVAILABLE", 503
    message = "Finding storage is temporarily unavailable"


class InvalidOutcome(ActionError):
    code, status = "INVALID_OUTCOME", 500
    message = "The executor reported an outcome the request cannot accept"
