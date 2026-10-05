from netsight_api.reconcile import reconcile
from netsight_api.schemas import Device, DeviceSourceAlias, Freshness

NB_1 = "device-11111111-1111-1111-1111-111111111111"
NB_2 = "device-22222222-2222-2222-2222-222222222222"
DS_1 = "device-33333333-3333-3333-3333-333333333333"


def _device(
    *,
    device_id: str,
    native_id: str,
    name: str,
    status: str,
    source: str,
    hostname: str | None = None,
) -> Device:
    return Device(
        id=device_id,
        name=name,
        hostname=hostname or name,
        type="router",
        status=status,  # type: ignore[arg-type]
        source_aliases=[DeviceSourceAlias(source=source, native_id=native_id)],
        freshness=Freshness(state="fresh", observed_at=None, source=source),
    )


def test_all_match() -> None:
    netbox = [_device(device_id=NB_1, native_id="1", name="core-sw-01", status="healthy", source="netbox")]
    discovered = [_device(device_id=DS_1, native_id="a", name="core-sw-01", status="healthy", source="librenms")]
    assert reconcile(netbox, discovered) == []


def test_missing_discovered() -> None:
    netbox = [_device(device_id=NB_1, native_id="1", name="core-sw-01", status="healthy", source="netbox")]
    findings = reconcile(netbox, [])
    assert len(findings) == 1
    assert findings[0].kind == "missing-discovered"
    assert findings[0].netbox_device_id is not None


def test_unknown_discovered() -> None:
    discovered = [_device(device_id=DS_1, native_id="a", name="mystery", status="healthy", source="librenms")]
    findings = reconcile([], discovered)
    assert len(findings) == 1
    assert findings[0].kind == "unknown-discovered"


def test_status_mismatch() -> None:
    netbox = [_device(device_id=NB_1, native_id="1", name="core-sw-01", status="offline", source="netbox")]
    discovered = [_device(device_id=DS_1, native_id="a", name="core-sw-01", status="healthy", source="librenms")]
    findings = reconcile(netbox, discovered)
    assert len(findings) == 1
    assert findings[0].kind == "status-mismatch"
