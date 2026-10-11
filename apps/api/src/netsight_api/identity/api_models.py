"""Engine results to boundary models: the one place the domain meets the API contract.

Pure mapping. Every value here already satisfies the engine's own invariants; the pydantic models
re-check them (and the canonical JSON Schema is checked again at the route), so a mapping slip is
caught as ``unknown`` rather than reaching a browser.
"""

from __future__ import annotations

import hashlib
import hmac

from netsight_api import schemas_identity as api
from netsight_api.identity import model
from netsight_api.identity.id_key import evidence_id_key


def entity(ref: model.EntityRef) -> api.EntityRef:
    return api.EntityRef(type=ref.type.value, id=ref.id, label=ref.label)


def opaque_evidence_id(identifier: str) -> str:
    """A stable stand-in for a source's record id: same record, same id; nothing of its content.

    A source's native ids can embed a user name or an account id (a RADIUS session keyed by user, a
    lease named for a host), so a caller who may not learn who is behind an address must not be
    handed them either. Keyed (HMAC under a server secret), so a guessed id cannot be confirmed by
    hashing the guess; raises ``IdKeyUnavailable`` rather than fall back to an unkeyed hash.
    """
    source, _, _native = identifier.partition(":")
    digest = hmac.new(evidence_id_key(), identifier.encode(), hashlib.sha256).hexdigest()
    return f"{source}:{digest[:16]}"


def evidence(ref: model.EvidenceRef, *, opaque: bool = False) -> api.EvidenceRef:
    return api.EvidenceRef(
        id=opaque_evidence_id(ref.id) if opaque else ref.id,
        source=ref.source,
        kind=ref.kind.value,
        observed_at=ref.observed_at,
        valid_from=ref.valid_from,
        valid_to=ref.valid_to,
        confidence=ref.confidence,
    )


def candidate(item: model.Candidate, *, opaque: bool = False) -> api.Candidate:
    return api.Candidate(
        entity=entity(item.entity),
        basis=item.basis.value,  # type: ignore[arg-type]
        confidence=item.confidence if item.confidence is not None else 0.0,
        evidence=[evidence(ref, opaque=opaque) for ref in item.evidence],
    )


def link(item: model.Link, *, opaque: bool = False) -> api.IdentityLink:
    return api.IdentityLink(
        relation=item.relation.value,
        source=entity(item.source),
        target=entity(item.target) if item.target is not None else None,
        basis=item.basis.value,
        confidence=item.confidence,
        valid_from=item.valid_from,
        valid_to=item.valid_to,
        as_of=item.as_of,
        reason=item.reason.value if item.reason is not None else None,
        evidence=[evidence(ref, opaque=opaque) for ref in item.evidence],
        ambiguous=item.ambiguous,
        candidates=[candidate(entry, opaque=opaque) for entry in item.candidates],
    )


def session(item: model.Session) -> api.IdentitySession:
    return api.IdentitySession(
        kind=item.kind,  # type: ignore[arg-type]
        basis=item.basis.value,  # type: ignore[arg-type]
        confidence=item.confidence,
        valid_from=item.valid_from,
        valid_to=item.valid_to,
        links=[link(entry) for entry in item.links],
    )


def attribution(item: model.Attribution) -> api.Attribution:
    return api.Attribution(
        basis=item.basis.value,
        reason=item.reason.value if item.reason is not None else None,
        ambiguous=item.ambiguous,
        links=[link(entry) for entry in item.links],
        candidates=[candidate(entry) for entry in item.candidates],
    )


def restricted_attribution() -> api.Attribution:
    """What a caller without ``users:read`` is told: the person is withheld, and that is said."""
    return api.Attribution(
        basis="unknown", reason="restricted", ambiguous=False, links=[], candidates=[]
    )


def unattributed(reason: model.Reason) -> api.Attribution:
    return api.Attribution(
        basis="unknown",
        reason=reason.value,
        ambiguous=False,
        links=[],
        candidates=[],
    )
