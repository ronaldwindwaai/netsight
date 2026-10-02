"""LibreNMS adapter.

Owns source authentication, retries/timeouts, pagination (single page for the
MVP slice), source-shape mapping, canonical identity aliases, freshness
metadata and source health. Returns the canonical error model — never
silently empty results on upstream failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

import httpx

ADAPTER_VERSION = "librenms/1"

_STATUS_MAP = {
    1: "healthy",
    0: "offline",
}

_ALERT_SEVERITY_MAP = {
    "critical": "critical",
    "warning": "high",
    "notice": "medium",
}


class AdapterStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    FORBIDDEN = "forbidden"
    INVALID_SOURCE_DATA = "invalid-source-data"


class AdapterError(Exception):
    def __init__(self, status: AdapterStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class SourceHealth:
    source: str
    reachable: bool
    latency_ms: float | None
    checked_at: str
    detail: str


@dataclass
class LibrenmsClient:
    base_url: str
    token: str
    timeout_seconds: float = 10.0
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _headers(self) -> dict[str, str]:
        return {"X-Auth-Token": self.token, "Accept": "application/json"}

    async def _get(self, path: str) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self._transport
            ) as client:
                response = await client.get(url, headers=self._headers())
        except httpx.TimeoutException as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "timeout") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, str(exc)) from exc
        if response.status_code in (401, 403):
            raise AdapterError(AdapterStatus.FORBIDDEN, f"http {response.status_code}")
        if response.status_code >= 500:
            raise AdapterError(AdapterStatus.UNAVAILABLE, f"http {response.status_code}")
        if response.status_code >= 400:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"http {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "non-json response") from exc
        if not isinstance(body, dict):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "unexpected payload shape")
        return body

    async def health(self) -> SourceHealth:
        started = datetime.now(timezone.utc)
        try:
            await self._get("/api/v0/system")
        except AdapterError as exc:
            return SourceHealth(
                source="librenms",
                reachable=False,
                latency_ms=None,
                checked_at=started.isoformat(),
                detail=exc.detail,
            )
        elapsed = (datetime.now(timezone.utc) - started).total_seconds() * 1000
        return SourceHealth(
            source="librenms",
            reachable=True,
            latency_ms=round(elapsed, 1),
            checked_at=started.isoformat(),
            detail="ok",
        )

    async def devices(self) -> list[dict[str, Any]]:
        body = await self._get("/api/v0/devices")
        raw = body.get("devices")
        if not isinstance(raw, list):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing devices list")
        observed_at = datetime.now(timezone.utc).isoformat()
        canonical: list[dict[str, Any]] = []
        for row in raw:
            if not isinstance(row, dict) or "device_id" not in row or "hostname" not in row:
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "bad device row")
            canonical.append(
                {
                    "id": f"librenms:{row['device_id']}",
                    "name": row.get("sysName") or row["hostname"],
                    "hostname": row["hostname"],
                    "status": _STATUS_MAP.get(row.get("status"), "unknown"),
                    "site_id": None,
                    "ip_addresses": [row["ip"]] if row.get("ip") else [],
                    "freshness": {
                        "state": "fresh",
                        "observed_at": observed_at,
                        "source": "librenms",
                    },
                }
            )
        return canonical

    async def alerts(self) -> list[dict[str, Any]]:
        body = await self._get("/api/v0/alerts")
        raw = body.get("alerts")
        if not isinstance(raw, list):
            raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "missing alerts list")
        canonical = []
        for row in raw:
            if not isinstance(row, dict) or "id" not in row:
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "bad alert row")
            severity_raw = str(row.get("severity", "")).lower()
            canonical.append(
                {
                    "id": f"librenms:{row['id']}",
                    "severity": _ALERT_SEVERITY_MAP.get(severity_raw, "info"),
                    "state": "open" if row.get("state") in (0, "0", "active") else "acknowledged",
                    "title": row.get("name") or row.get("rule", "alert"),
                    "observed_at": row.get("timestamp")
                    or datetime.now(timezone.utc).isoformat(),
                    "device_id": (
                        f"librenms:{row['device_id']}" if row.get("device_id") is not None else None
                    ),
                }
            )
        return canonical
