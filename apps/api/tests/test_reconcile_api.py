from datetime import UTC, datetime

from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import DeviceCollection as LibrenmsCollection
from netsight_api.adapters.netbox import DeviceCollection as NetboxCollection
from netsight_api.auth.deps import get_current_identity
from netsight_api.main import app, get_client, get_netbox_client
from netsight_api.rbac import Identity
from netsight_api.schemas import Device, DeviceSourceAlias, Freshness

NB_ID = "device-11111111-1111-1111-1111-111111111111"
DS_ID = "device-33333333-3333-3333-3333-333333333333"


def _device(device_id: str, native_id: str, name: str, status: str, source: str) -> Device:
    return Device(
        id=device_id,
        name=name,
        hostname=name,
        type="router",
        status=status,  # type: ignore[arg-type]
        source_aliases=[DeviceSourceAlias(source=source, native_id=native_id)],
        freshness=Freshness(state="fresh", observed_at=datetime.now(UTC), source=source),
    )


class _Netbox:
    def __init__(self, items: tuple[Device, ...]) -> None:
        self._items = items

    async def devices(self) -> NetboxCollection:
        return NetboxCollection(items=self._items, observed_at=datetime.now(UTC))


class _LibreNMS:
    def __init__(self, items: tuple[Device, ...]) -> None:
        self._items = items

    async def devices(self) -> LibrenmsCollection:
        return LibrenmsCollection(items=self._items, observed_at=datetime.now(UTC))


def _identity() -> Identity:
    return Identity("test-admin", frozenset({"administrator"}))


def test_reconcile_findings_reports_status_mismatch() -> None:
    netbox_items = (_device(NB_ID, "1", "core-sw-01", "offline", "netbox"),)
    discovered_items = (_device(DS_ID, "a", "core-sw-01", "healthy", "librenms"),)

    app.dependency_overrides[get_current_identity] = _identity
    app.dependency_overrides[get_netbox_client] = lambda: _Netbox(netbox_items)
    app.dependency_overrides[get_client] = lambda: _LibreNMS(discovered_items)
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/reconcile/findings")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["kind"] == "status-mismatch"
    assert payload["items"][0]["netbox_device_id"] == NB_ID
    assert payload["items"][0]["discovered_device_id"] == DS_ID
