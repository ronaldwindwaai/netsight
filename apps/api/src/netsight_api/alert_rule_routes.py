"""Alert-rule API (S6-3): list, get, create, update, approve, disable and a read-only dry-run.

Behaviour, in the order a request meets it:

* Authentication (401), then per-operation authorisation (403, deny-by-default, ``rbac.py``):
  every write is a human-only permission, so no service or AI principal can change monitoring
  configuration, and only administrators may approve (activate) a rule.
* Cookie-authenticated writes present the session CSRF token and an allow-listed origin (403,
  ``auth/csrf.py``), then a per identity write rate limit applies (429).
* Rules start as drafts. ``approve`` activates exactly the version the reviewer saw
  (``expected_version``; a rule changed since is a 409), and a rule that cannot be evaluated
  on this host is refused (422 ``RULE_INVALID``) at create, update and approve: an invalid
  rule never activates. An edit returns the rule to draft and an active rule must be
  disabled before it is edited.
* Reads answer an explicit state: ``not-connected`` (no store), ``unknown`` (store failure),
  ``ok`` (rows). Non-ok states never carry rows. Writes answer 503 instead.
* Every mutation, refused or not, emits an audit record naming the actor, rule id, version
  and action (closing the S6-2 gate item that rule edits and disables carry an actor);
  free-form values (the rule name) are logged as a length and a short hash only.
* ``POST /alert-rules/evaluate`` replays supplied observations through a supplied definition
  with no store access and no external effect.
* Rule text (names, labels, exception entries) is stored and returned verbatim as data.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool

from netsight_api.alerting.dryrun import dry_run
from netsight_api.alerting.engine import definition_of
from netsight_api.alerting.validation import check_definition
from netsight_api.alerting_audit import attribution_details, definition_sha256, rule_disable_details
from netsight_api.alerting_route_support import (
    CREATE_ERRORS,
    ITEM_READ_ERRORS,
    READ_ERRORS,
    WRITE_ERRORS,
    EvaluationSlot,
    OptionalAlertRuleStore,
    RuleId,
    RuleInvalidError,
    claim_evaluation_slot,
    collection_writer,
    evaluate_guard,
    log_read_failure,
    mutate,
    reader,
    rule_writer,
)
from netsight_api.audit import fingerprint
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission
from netsight_api.schemas import AlertRule, AlertRuleDefinition, AlertRuleStatus, StoreState
from netsight_api.schemas_alerting import (
    MAX_RULE_LIST_OFFSET,
    MAX_RULE_PAGE_SIZE,
    AlertRuleApproveRequest,
    AlertRuleDetailResponse,
    AlertRuleEvaluateRequest,
    AlertRuleEvaluateResponse,
    AlertRuleListResponse,
    AlertRuleUpdateRequest,
)
from netsight_api.storage import AlertRuleRepository, NotFoundError

router = APIRouter(prefix="/alert-rules", tags=["alert-rules"])
_NOUN = "Alert rule"

_RuleReader = Annotated[Identity, Depends(reader(Permission.ALERT_RULES_READ, "alert-rules"))]
_CreateActor = Annotated[
    Identity,
    Depends(collection_writer(Permission.ALERT_RULES_WRITE, action="alert_rule.create")),
]
_UpdateActor = Annotated[
    Identity, Depends(rule_writer(Permission.ALERT_RULES_WRITE, action="alert_rule.update"))
]
_ApproveActor = Annotated[
    Identity, Depends(rule_writer(Permission.ALERT_RULES_APPROVE, action="alert_rule.approve"))
]
_DisableActor = Annotated[
    Identity, Depends(rule_writer(Permission.ALERT_RULES_DISABLE, action="alert_rule.disable"))
]
_EvaluateActor = Annotated[Identity, Depends(evaluate_guard)]


def _run_dry_run(body: AlertRuleEvaluateRequest, slot: EvaluationSlot) -> AlertRuleEvaluateResponse:
    """The worker owns the claimed slot from its first statement until its ``finally``."""
    slot.worker_started()
    try:
        return dry_run(body)
    finally:
        slot.worker_finished()


def _require_valid(definition: AlertRuleDefinition) -> None:
    """Fail closed: a definition that cannot be evaluated here is never stored or activated."""
    problems = check_definition(definition)
    if problems:
        raise RuleInvalidError(tuple(problem.code for problem in problems))


def _name_details(definition: AlertRuleDefinition) -> dict[str, object]:
    """Audit details for the free-form rule name: a length and a short hash, never the text."""
    return {"name_hash": fingerprint(definition.name), "name_length": len(definition.name)}


def _version_details(rule: AlertRule) -> dict[str, object]:
    return {"version": rule.version, "status": rule.status}


def _changed_details(rule: AlertRule, actor_id: str) -> dict[str, object]:
    """Version, the stored definition's SHA-256 and the editing actor next to the creator."""
    return {**_version_details(rule), **attribution_details(rule, actor_id=actor_id)}


def _checked[M: AlertRuleListResponse | AlertRuleDetailResponse](name: str, body: M) -> M:
    """Canonical contract validation on every successful *read* return path.

    Write responses leave ``mutate`` straight from the store; they are checked against the
    same contracts by ``test_success_responses_are_contract_valid_everywhere`` (create,
    update, approve, disable) and its maintenance counterpart (create, cancel).
    """
    validate(name, body.model_dump(mode="json", by_alias=True))
    return body


# --- reads ---------------------------------------------------------------------------------------------


@router.get(
    "",
    response_model=AlertRuleListResponse,
    responses=READ_ERRORS,
    operation_id="listAlertRules",
)
async def list_alert_rules(
    request: Request,
    _identity: _RuleReader,
    store: OptionalAlertRuleStore,
    status: Annotated[AlertRuleStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_RULE_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_RULE_LIST_OFFSET)] = 0,
) -> AlertRuleListResponse:
    """Rules newest first with an explicit store state.

    not-connected without a store; unknown when the read fails; ok only with stored rules.
    ``next_offset`` is set when the page was full and the capped offset allows another page.
    """

    def empty(state_name: StoreState) -> AlertRuleListResponse:
        return _checked(
            "alert_rule_list",
            AlertRuleListResponse(
                state=state_name, rules=[], limit=limit, offset=offset, next_offset=None
            ),
        )

    if store is None:
        return empty("not-connected")
    repository = store
    try:
        rows = await run_in_threadpool(
            lambda: repository.list_rules(status=status, limit=limit, offset=offset)
        )
        following = offset + limit
        more = len(rows) == limit and following <= MAX_RULE_LIST_OFFSET
        return _checked(
            "alert_rule_list",
            AlertRuleListResponse(
                state="ok",
                rules=rows,
                limit=limit,
                offset=offset,
                next_offset=following if more else None,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - deliberate store/contract boundary
        log_read_failure(request, exc)
        return empty("unknown")


# The dry-run is declared before the id routes so its fixed path is never read as an id.
@router.post(
    "/evaluate",
    response_model=AlertRuleEvaluateResponse,
    responses={k: v for k, v in WRITE_ERRORS.items() if k in (401, 403, 422, 429, 503)},
    operation_id="evaluateAlertRule",
)
async def evaluate_alert_rule(
    request: Request, body: AlertRuleEvaluateRequest, identity: _EvaluateActor
) -> AlertRuleEvaluateResponse:
    """Replay observations through a definition: read-only, no store, no external effect.

    Bounded: a low per-identity rate, a cap on the combined observation text and at most
    ``EVALUATE_MAX_CONCURRENT`` concurrent runs (503 ``EVALUATE_BUSY``, never queued).
    """
    slot = claim_evaluation_slot(request, identity)
    try:
        response = await run_in_threadpool(_run_dry_run, body, slot)
    except BaseException:
        # The worker releases its own slot from its first statement, so this path only
        # gives one back when dispatch never produced a worker: never stranded, never twice.
        slot.request_failed()
        raise
    validate("alert_rule_evaluate_response", response.model_dump(mode="json", by_alias=True))
    return response


@router.get(
    "/{rule_id}",
    response_model=AlertRuleDetailResponse,
    responses=ITEM_READ_ERRORS,
    operation_id="getAlertRule",
)
async def get_alert_rule(
    request: Request,
    rule_id: RuleId,
    _identity: _RuleReader,
    store: OptionalAlertRuleStore,
) -> AlertRuleDetailResponse:
    """One rule; an unknown id is a 404, never a fabricated record."""
    if store is None:
        return _checked(
            "alert_rule_detail", AlertRuleDetailResponse(state="not-connected", rule=None)
        )
    repository = store
    try:
        rule = await run_in_threadpool(repository.get_rule, rule_id)
    except Exception as exc:  # noqa: BLE001 - deliberate store boundary
        log_read_failure(request, exc)
        return _checked("alert_rule_detail", AlertRuleDetailResponse(state="unknown", rule=None))
    if rule is None:
        raise ApiError(404, "NOT_FOUND", f"{_NOUN} was not found")
    return _checked("alert_rule_detail", AlertRuleDetailResponse(state="ok", rule=rule))


# --- writes ----------------------------------------------------------------------------------------------


@router.post(
    "",
    response_model=AlertRule,
    status_code=201,
    responses=CREATE_ERRORS,
    operation_id="createAlertRule",
)
async def create_alert_rule(
    request: Request,
    body: AlertRuleDefinition,
    actor: _CreateActor,
    store: OptionalAlertRuleStore,
) -> AlertRule:
    """Create a draft. It is never active until a human approves a reviewed version."""
    actor_id = actor.id

    def operation(repository: AlertRuleRepository) -> AlertRule:
        _require_valid(body)
        return repository.create_rule(body, actor_id=actor_id)

    return await mutate(
        request,
        store,
        actor,
        action="alert_rule.create",
        noun=_NOUN,
        operation=operation,
        target=None,
        target_of=lambda rule: rule.id,
        details={**_name_details(body), "definition_sha256": definition_sha256(body)},
        details_of=lambda rule: _changed_details(rule, actor_id),
    )


@router.put(
    "/{rule_id}",
    response_model=AlertRule,
    responses=WRITE_ERRORS,
    operation_id="updateAlertRule",
)
async def update_alert_rule(
    request: Request,
    rule_id: RuleId,
    body: AlertRuleUpdateRequest,
    actor: _UpdateActor,
    store: OptionalAlertRuleStore,
) -> AlertRule:
    """Replace a draft or disabled rule's definition; optimistic on ``expected_version``."""
    actor_id = actor.id

    def operation(repository: AlertRuleRepository) -> AlertRule:
        _require_valid(body.definition)
        return repository.update_rule(
            rule_id,
            body.definition,
            expected_version=body.expected_version,
            actor_id=actor_id,
        )

    return await mutate(
        request,
        store,
        actor,
        action="alert_rule.update",
        noun=_NOUN,
        operation=operation,
        target=rule_id,
        details={**_name_details(body.definition), "expected_version": body.expected_version},
        details_of=lambda rule: _changed_details(rule, actor_id),
    )


@router.post(
    "/{rule_id}/approve",
    response_model=AlertRule,
    responses=WRITE_ERRORS,
    operation_id="approveAlertRule",
)
async def approve_alert_rule(
    request: Request,
    rule_id: RuleId,
    body: AlertRuleApproveRequest,
    actor: _ApproveActor,
    store: OptionalAlertRuleStore,
) -> AlertRule:
    """Activate exactly the reviewed version.

    The version check and the activation are one atomic store operation under the row lock,
    so an edit that lands after the reviewer loaded the rule makes this a 409 and activates
    nothing. The configuration check below is made on the stored rule and only when that rule
    is still the reviewed version; if it changed in between, the store's check refuses.
    """
    approver_id = actor.id

    def operation(repository: AlertRuleRepository) -> AlertRule:
        current = repository.get_rule(rule_id)
        if current is None:
            raise NotFoundError("alert rule not found")
        if current.version == body.expected_version:
            _require_valid(definition_of(current))
        return repository.approve_rule(
            rule_id, approver_id=approver_id, expected_version=body.expected_version
        )

    return await mutate(
        request,
        store,
        actor,
        action="alert_rule.approve",
        noun=_NOUN,
        operation=operation,
        target=rule_id,
        details={"expected_version": body.expected_version},
        details_of=lambda rule: _changed_details(rule, approver_id),
    )


@router.post(
    "/{rule_id}/disable",
    response_model=AlertRule,
    responses=WRITE_ERRORS,
    operation_id="disableAlertRule",
)
async def disable_alert_rule(
    request: Request,
    rule_id: RuleId,
    actor: _DisableActor,
    store: OptionalAlertRuleStore,
) -> AlertRule:
    """Disable an active rule; the actor is audited (S6-2 gate item)."""
    actor_id = actor.id
    return await mutate(
        request,
        store,
        actor,
        action="alert_rule.disable",
        noun=_NOUN,
        operation=lambda repository: repository.disable_rule(rule_id, actor_id=actor_id),
        target=rule_id,
        details_of=lambda rule: {
            **_changed_details(rule, actor_id),
            **rule_disable_details(rule),
        },
    )
