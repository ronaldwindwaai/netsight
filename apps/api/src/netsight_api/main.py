import os

from fastapi import Depends, FastAPI, HTTPException

from netsight_api.adapters.librenms import AdapterError, LibrenmsClient
from netsight_api.contracts import ContractViolation, validate
from netsight_api.rbac import Identity, Permission, is_allowed

app = FastAPI(title="Netsight Platform API", version="0.1.0")


def get_client() -> LibrenmsClient:
    return LibrenmsClient(
        base_url=os.environ.get("LIBRENMS_BASE_URL", "http://127.0.0.1:8001"),
        token=os.environ.get("LIBRENMS_TOKEN", ""),
    )


def _dev_identity() -> Identity | None:
    """Development-only identity fallback.

    Enabled ONLY when NETSIGHT_DEV_MODE=true. Exists so the product slice can
    be exercised before NS-010/NS-012 (OIDC + sessions) land. Never enable in
    production; absent the flag, identity is always None (deny).
    """

    if os.environ.get("NETSIGHT_DEV_MODE", "").lower() == "true":
        return Identity("dev-user", frozenset({"administrator"}))
    return None


def _authorise(permission: Permission) -> None:
    identity = _dev_identity()
    if not is_allowed(identity, permission.value):
        raise HTTPException(status_code=403, detail="forbidden")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/sources/librenms/health")
async def librenms_health(client: LibrenmsClient = Depends(get_client)) -> dict:
    result = await client.health()
    return {
        "source": result.source,
        "reachable": result.reachable,
        "latency_ms": result.latency_ms,
        "checked_at": result.checked_at,
        "detail": result.detail,
    }


@app.get("/api/devices")
async def devices(client: LibrenmsClient = Depends(get_client)) -> dict:
    _authorise(Permission.DEVICES_READ)
    try:
        rows = await client.devices()
        for row in rows:
            validate("device", row)
    except AdapterError as exc:
        raise HTTPException(status_code=502, detail=f"{exc.status}: {exc.detail}") from exc
    except ContractViolation as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"items": rows, "freshness": "fresh"}


@app.get("/api/alerts")
async def alerts(client: LibrenmsClient = Depends(get_client)) -> dict:
    _authorise(Permission.ALERTS_READ)
    try:
        rows = await client.alerts()
        for row in rows:
            validate("alert", row)
    except AdapterError as exc:
        raise HTTPException(status_code=502, detail=f"{exc.status}: {exc.detail}") from exc
    except ContractViolation as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"items": rows, "freshness": "fresh"}
