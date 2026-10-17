"""Audited, authorized read-only configuration-backup metadata."""
from __future__ import annotations

import os
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Path, Request, Response

from netsight_api.adapters.oxidized import (
    ConfigurationNodeNotFound,
    OxidizedClient,
    OxidizedUnavailable,
)
from netsight_api.contracts import validate
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity, Permission
from netsight_api.read_query import QueryError, integer, single_values
from netsight_api.read_support import no_store, reader, rejected
from netsight_api.schemas_configuration import (
    NODE_ID_PATTERN,
    ConfigurationNodes,
    ConfigurationVersions,
)
from netsight_api.traffic import audit_trail

router = APIRouter(prefix="/config", tags=["configuration"])


def get_configuration_source() -> OxidizedClient | None:
    base = os.environ.get("OXIDIZED_BASE_URL", "").strip()
    return OxidizedClient(base, os.environ.get("OXIDIZED_TOKEN", "")) if base else None


Source = Annotated[OxidizedClient | None, Depends(get_configuration_source)]
Reader = Annotated[Identity, Depends(reader(
    Permission.CONFIGURATION_READ, "configuration.read", "configuration", lambda: 60,
))]
NodeId = Annotated[str, Path(pattern=NODE_ID_PATTERN, min_length=48, max_length=48)]


def pagination(request: Request) -> tuple[int, int]:
    values = single_values(request, {"page", "page_size"})
    return integer(values, "page", 1, 1, 2000), integer(values, "page_size", 50, 1, 100)


def page_of[T: ConfigurationNodes | ConfigurationVersions](snapshot: T, page: int, size: int) -> T:
    available = snapshot.state in {"ok", "partial"}
    start = (page - 1) * size
    return cast(T, snapshot.model_copy(update={
        "items": snapshot.items[start:start + size], "page": page, "page_size": size,
        "total": len(snapshot.items) if available and not snapshot.truncated else None,
        "has_more": available and start + size < len(snapshot.items),
    }))


def audit_result(request: Request, identity: Identity, state: str, count: int) -> None:
    audit_trail.read(request, identity.id, "configuration.read", state=state, row_count=count, failure=state == "unknown")


@router.get("/nodes", response_model=ConfigurationNodes)
async def nodes(
    request: Request, response: Response, identity: Reader, source: Source,
) -> ConfigurationNodes:
    no_store(response)
    try:
        page, size = pagination(request)
    except QueryError as exc:
        raise rejected(request, identity, "configuration.read") from exc
    result = ConfigurationNodes(state="not-connected", observed_at=None)
    if source is not None:
        try:
            result = await source.nodes()
        except OxidizedUnavailable:
            result = ConfigurationNodes(state="unknown", observed_at=None)
    result = page_of(result, page, size)
    validate("configuration_nodes", result.model_dump(mode="json"))
    audit_result(request, identity, result.state, len(result.items))
    return result


@router.get("/nodes/{node_id}/versions", response_model=ConfigurationVersions)
async def versions(
    node_id: NodeId, request: Request, response: Response, identity: Reader, source: Source,
) -> ConfigurationVersions:
    no_store(response)
    try:
        page, size = pagination(request)
    except QueryError as exc:
        raise rejected(request, identity, "configuration.read") from exc
    result = ConfigurationVersions(state="not-connected", observed_at=None)
    if source is not None:
        try:
            result = await source.versions(node_id)
        except ConfigurationNodeNotFound as exc:
            audit_trail.failed(request, identity.id, "configuration.read", "not-found")
            raise ApiError(404, "NOT_FOUND", "Configuration node was not found") from exc
        except OxidizedUnavailable:
            result = ConfigurationVersions(state="unknown", observed_at=None)
    result = page_of(result, page, size)
    validate("configuration_versions", result.model_dump(mode="json"))
    audit_result(request, identity, result.state, len(result.items))
    return result
