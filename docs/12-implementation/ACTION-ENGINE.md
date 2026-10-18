# Controlled Action Engine (E11, Step 12)

> **Numbering note.** Earlier documents (INVENTORY-IPAM.md, THREAT-MODEL.md, RBAC-MATRIX.md, the Step 8 and
> Step 9 notes in BUILD-PLAN-FROM-PRD.md and the `proposedAction` contract text) call the action engine
> "Step 14". The BUILD-PLAN numbering now makes it **Step 12**. They mean the same thing; those references
> have been updated where the file was in scope of this step.

Requirements: PRD sections 24 (remote operations) and 25 (risk levels), `docs/02-security/REMOTE-ACTION-SECURITY.md`,
`RBAC-MATRIX.md` (Propose / Approve / Execute rows), `THREAT-MODEL.md`, ACCEPTANCE-SCENARIOS ("Disable Port").

## What this step is, and is not

**Built: the framework.** The Action Request lifecycle, a closed allow-list of typed action definitions,
risk classes, two-person approval, step-up, expiry, idempotency, pre-checks, verification and rollback
hooks, a kill switch, audit, rate limits, RBAC, the API, the contracts and the UI.

**Not built: any way to change a device.** The only executor that ships is the **dry-run executor**. It
records what *would* happen and never contacts a device or a network system (its module imports no socket,
HTTP, SSH, SNMP or process library, and a test keeps it that way). A `live` executor slot exists so the
framework has a real shape; it implements nothing and reports `disabled` (default) or `not-connected`
(`NETSIGHT_ACTIONS_LIVE_EXECUTION=true`, still no connector). Selecting an executor therefore always
yields the dry-run executor today. A real executor needs, at minimum: a lab that proves restricted
execution (ACTION-ENGINE design rule from before this step), its own env gate, short-lived credentials
from the secret store, a security review, and a persistent store (see Limitations).

## Design

**No generic command execution API.** `actions/catalog.py` is the whole allow-list:

| Action type | Risk | Approvals | Target | Parameters |
| --- | --- | --- | --- | --- |
| `endpoint.isolate` | C | 1 | `unknown-device-<uuid>` (a finding) or `endpoint:<id>` | `duration_minutes` integer 5-1440, required |
| `switch.port.disable` | D | 2 | `interface:<id>` | none |
| `switch.port.enable` | B | 1 | `interface:<id>` | none |

`service.restart` and `firewall.destination.block` (listed as examples before this step) are deliberately
absent: the design says not to build them until a lab proves restricted execution.

Each definition declares: title, risk, target kind and pattern, typed parameters (integer in a range, boolean
or a value from a fixed list; never a free string), approvals required, approve-within and execute-within
windows, executor timeout, the permission to propose it, rollback guidance and a **fixed plan** (the words a
dry run reports). A request body can name an action type, a target, parameters and a reason, and nothing
else: an unknown key anywhere is a 422, a parameter outside its type or range is a 422 with a static code,
and the plan and the executor context are built from the definition and the *validated* values, never from
request text. The executor interface (`ExecutionContext`) has no field for a reason, a requester or a
command.

### Lifecycle (append-only history)

```
proposed -> pending-approval -> approved -> executing -> succeeded
                 |                 |            |-----> failed
                 |                 |            `-----> rolled-back
                 |-> rejected      `-> expired / cancelled
                 `-> expired / cancelled
```

The table is `schemas_actions.ALLOWED_TRANSITIONS`; the store applies a move only from a legal state, under
one lock. Every move appends a history event (`proposed`, `policy-checked`, `submitted`, `approved`,
`rejected`, `cancelled`, `expired`, `execution-started`, `pre-check-failed`, `executed`,
`verification-passed`, `verification-failed`, `rolled-back`, `rollback-failed`, `failed`) carrying the actor,
the states, a static code and the actor's note for rejections and cancellations. Each event's SHA-256 hash
covers the request id, its own fields and the previous hash, so an edit, a gap, a reorder, a truncated start
or a move to another request fails `verify_chain`; the detail response reports `chain_intact`. The store's verdict
also requires the last event to be the request's current version and state and every step to start where the previous
one ended, so cutting the tail off is detected too. "Intact" means *internally consistent*: the chain has no secret key,
so anyone who can write the process memory could recompute it. This makes tampering *detectable*, not impossible (see
Limitations).

A proposal is created `proposed`, passes the policy checks (catalogue, parameters, target shape, approval
policy; `target-exists` is recorded **unknown**, because nothing here can ask the inventory) and enters
`pending-approval` in the same call (three history events).

### Approval, replay and TOCTOU

* A request carries a **`digest`** (SHA-256 over the id, the content, the deadline) and a **`version`** (the
  sequence number of its last history event). Approve, reject, cancel and execute quote both; a quote that no
  longer matches is `409 STALE_REQUEST`. A person therefore decides on exactly what they saw, and a captured
  approval cannot be replayed on a later state.
* **Requester != approver** for every risk (identity id; two sessions of one person are one identity). One
  person approves once. Risk D needs two distinct approvers, neither the requester; the second approver must
  quote the version that includes the first approval. Only a human approves (`HUMAN_ONLY_PERMISSIONS`,
  re-checked inside the store).
* All of this is decided **inside the store lock**, so concurrent approvals record exactly one (tests fire six
  and eight in parallel).
* **Step-up** (a recent second factor) for approve, execute and releasing the kill switch. Engaging the kill
  switch, proposing, rejecting and cancelling do not need it (stopping must be easy).
* **Expiry.** An unapproved request expires after `approve_within_seconds` (24 h); an approved one must be run
  within `execute_within_seconds` (1 h) or it expires; a run that never reports back is failed after its timeout
  plus 60 s (`executor-timeout`). Deadlines are applied on every touch, by the list sweep and when a request is created or
  a run is started (so an expired request or a timed-out run never keeps blocking new work). Every move made by the clock
  rather than by a person is audited as `actions.system-transition` (actor `system:actions`).
* **Idempotency.** `Idempotency-Key` (16-64 characters of `A-Za-z0-9._-`) is required on create, create-from-finding
  and execute. For create it is scoped to the requester: the same key and body returns the first request
  (`Idempotent-Replay: true`), the same key with another body is `409 IDEMPOTENCY_CONFLICT`. For execute the key
  starts a run once: a retry reports the recorded result and runs nothing again; a different key on a request that
  is not `approved` is refused. A retry replays only for the person who started the run and only with the request's
  digest (another person using the key gets `409 IDEMPOTENCY_CONFLICT`), and answers `Idempotent-Replay: true`. One open
  request per action type and target; at most 25 open per requester; at most 5 000 stored, **bounded by evicting the
  oldest finished requests** (and their idempotency keys) when full, never an open one, so a propose-and-cancel loop cannot
  fill the store; **one execution per target at a time** (`TARGET_LOCKED`).

### Pre-checks, verification, rollback, timeouts

`engine.py` runs, after the store has started the run (the whole run shares **one** time budget, the definition's
`timeout_seconds`, so it always finishes before the store's sweep would fail it; the engine-level pre-checks run under that
budget too; the kill switch is read again immediately before the executor acts; and an unexpected error after the run
started fails the request with `executor-error` instead of leaving it `executing`): re-validation of the stored request against the
catalogue (defence in depth), pre-checks (the executor's own plus the engine's, such as "the finding is still
open and its evidence version has not moved"), the executor under a timeout, verification, and rollback when
verification fails. A failed check stops before the executor acts; an *unknown* check stops a live run but not
a dry run; an exception or an overrun becomes a static failure code and **the exception text is discarded**; an
unverifiable result is `failed`, never assumed good. The framework paths (live success, failed verification with
rollback, failed rollback, timeout, executor error) are exercised by test fakes; no shipped executor takes them.

### Dry-run semantics

A dry run ends `succeeded` with `execution.mode: dry-run`, `effect: none` (a contract invariant: a dry run that
claims to have changed something is rejected by the schema, the model, the store and the parser) and
`verification: not-applicable`. The UI says "Dry run completed ... nothing was changed ... nothing was contacted",
labels the control "Record a dry run" while no live executor is ready, and shows the "Dry run only" notice from
`GET /actions/status` (`dry_run_only` is exactly "no live executor is ready").

### Kill switch

`NETSIGHT_ACTIONS_KILL_SWITCH` (an unreadable value counts as *engaged*) or the runtime switch
(`POST /actions/kill-switch`, Administrator). Engaged: no request can be proposed, approved or run
(`503 KILL_SWITCH`); reads, rejection and cancellation still work. An environment switch cannot be released
through the API (`409 KILL_SWITCH_LOCKED`). The runtime switch is per process (see Limitations).

### Quarantine proposal from a finding (Step 8)

`POST /actions/from-finding` turns a finding's `proposed_action` into an Action Request: it requires
`actions:propose-high` and `unknown-devices:read`, quotes the finding's `evidence_version`, refuses a finding with
no proposal (`NO_PROPOSAL`), a closed one (`FINDING_CLOSED`) or moved evidence (`STALE_EVIDENCE`), uses the opaque
finding id as the target (the MAC, address and name are **not** copied into the action store) and sets the default
duration (60 minutes, pre-filled, not a policy). It is still only a proposal: it waits for another person's
approval, and at run time the `finding-current` pre-check fails if the evidence moved since. The finding page shows
"Create an action request" only to a viewer who may propose high risk; the finding's own contract is unchanged
(`executable` stays `false` there).

## API

All under `/api/v1/actions`, all `no-store`, errors included. Contracts: `contracts/json-schema/actions.schema.json`,
the `step12` blocks of the OpenAPI document, pydantic `schemas_actions.py`, TS parsers `api-contracts-actions.ts`, and
`contracts/test-vectors/actions.vectors.json` driving all four verdicts (the Step 1 placeholder `action-request` schema
and `/action-requests` paths are replaced).

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /status` | `actions:read` | engine state, `dry_run_only`, kill switch, executors, definitions, `store.durable: false` |
| `GET /` | `actions:read` | newest first, `state`, `page`, `page_size` <= 50, unknown parameters refused |
| `GET /{id}` | `actions:read` | request + history + `chain_intact` |
| `POST /` | `actions:propose` (+ `actions:propose-high` for risk C and D) | `Idempotency-Key` |
| `POST /from-finding` | `actions:propose-high` + `unknown-devices:read` | `Idempotency-Key` |
| `POST /{id}/approve` | `actions:approve`, step-up | digest + version |
| `POST /{id}/reject` | `actions:approve` | digest + version + reason |
| `POST /{id}/cancel` | requester (`actions:propose`) or `actions:approve` | digest + version + reason |
| `POST /{id}/execute` | `actions:execute`, step-up | digest + version, `Idempotency-Key` |
| `POST /kill-switch` | `actions:kill-switch`; release needs step-up | |

Guard order for writes: authenticate, authorise (a refusal is audited), CSRF and origin, step-up, per-identity budget
(30/min; execute 10/min; kill switch 5/min; reads 120/min), then the body. Disabled engine: status and list answer
`not-connected`; everything else is `503 ACTIONS_NOT_ENABLED`.

Audit (`actions.create`, `.create-from-finding`, `.approve`, `.reject`, `.cancel`, `.execute`, `.kill-switch`, `.status.read`,
`.list.read`, `.item.read`): actor, outcome, the request id as target and static facts (risk, state, version, lengths,
counts, mode, effect, failure code). Never the reason, a parameter value or a target.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `NETSIGHT_ACTIONS_ENABLED` | off | `1/true/yes/on` enables the engine; garbled fails start-up |
| `NETSIGHT_ACTIONS_KILL_SWITCH` | off | engaged from start-up, not releasable through the API; garbled = engaged |
| `NETSIGHT_ACTIONS_LIVE_EXECUTION` | off | reported `not-connected` when on (no connector ships); garbled fails start-up |

## UI

`/actions` (status card with the dry-run notice, kill switch, executors and storage warning; state filters as links;
table; kill-switch panel for Administrators) and `/actions/{id}` (facts, approvals "x of y", digest and version, checks
with "Not known" never shown as a pass, the result in honest words, the append-only history with the chain verdict, and
the decision panel). The decision panel shows what is being decided, sends the digest and version it showed, marks
step-up actions, explains each disabled control (role, "a different person must approve", already approved, state, kill
switch), keeps one idempotency key per request version, and locks after an unconfirmed result. Reasons, parameters and
targets are rendered as text. Menu entry "Action requests" (`actions:read`); `actions` joins the sign-in return allow-list
(web and API).

## Limitations (read before any live executor)

1. **Volatile store.** Requests, approvals and history are in process memory: lost on restart, not shared between
   workers (a second worker has its own empty store). `store.durable: false` is in the status contract and the UI says
   so. A PostgreSQL store (an `ActionStore` implementation with row locks, an append-only history table with the same
   hash chain and a migration) is the first thing a production deployment needs; the `ActionStore` Protocol is the
   seam. It was not built here because it cannot be verified without a PostgreSQL instance.
2. **Tamper-evident, not tamper-proof.** The hash chain detects edits; the store is in memory and the audit log is an
   operational log sink, not a tamper-evident store (PRD 32 is still open).
3. **Kill switch is per process.** Use the environment variable (and a restart) for a hard stop across workers.
4. Approvals are Administrator-only for now (the matrix says "Policy"); site scoping does not exist.
5. **Gates before any live executor ships** (found in review, harmless with the dry-run executor): (a) a timed-out executor
   call cannot be interrupted, it is abandoned on a daemon thread and the target lock is released, so a second action could
   start while the first is still working: a live executor must honour its own deadline/cancellation, or the engine must
   keep the target locked until the call has actually returned; (b) engaging the kill switch does not abort a run already
   past its last check; (c) the requester may run their own request (separation of duties is enforced at approval only);
   (d) one person holding two identities (for example a local and an OIDC account) is two people to the requester rule;
   (e) a durable store and a tamper-evident audit sink.

## Human decisions needed

(1) Who may approve: the matrix says "Policy" for Network Engineer and Security Analyst; today only the Administrator holds
`actions:approve`, `actions:execute` and `actions:kill-switch` (so a risk D request needs two Administrators). (2) Whether
the requester-may-not-approve rule should be relaxed for risk A and B (it is not). (3) The approval and execution windows
(24 h and 1 h) and the default isolation duration (60 minutes). (4) Which action types, in which order, get a real
executor, and the lab that proves them. (5) Where the durable store lives. (6) Whether Technician may propose risk B
(`switch.port.enable`) at all.

## Rollback

Unregister `actions_router` in `main.py`, drop the `actions` menu entry and the sign-in allow-list entry, remove the
`actions:*` permissions (or leave `NETSIGHT_ACTIONS_ENABLED` unset: the surface answers `not-connected` and stores nothing).
Nothing was persisted and there is no migration.
