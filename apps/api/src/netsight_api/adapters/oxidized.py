"""Bounded, read-only Oxidized metadata adapter. Never fetch configurations or trigger backups."""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore
from typing import Any, Literal
from urllib.parse import unquote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import httpx
from pydantic import ValidationError

from netsight_api.schemas_configuration import (
    ConfigurationNode,
    ConfigurationNodes,
    ConfigurationVersion,
    ConfigurationVersions,
)

_SOURCE_SLOTS = BoundedSemaphore(4)
MAX_ROWS = 2000
MAX_BYTES = 2 * 1024 * 1024
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,254}")


class OxidizedUnavailable(Exception):
    """Sanitized failure. Source URLs, bodies, credentials and exceptions are never returned."""


class ConfigurationNodeNotFound(Exception):
    pass


def canonical_node_id(full_name: str) -> str:
    return f"config-node-{uuid5(NAMESPACE_URL, 'urn:netsight:oxidized:node:' + full_name)}"


def source_time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None
    if result.tzinfo is None or result > datetime.now(UTC) + timedelta(seconds=5):
        return None
    return result


def valid_segment(value: object) -> bool:
    return isinstance(value, str) and _SEGMENT.fullmatch(value) is not None


@dataclass
class OxidizedClient:
    base_url: str
    token: str = field(default="", repr=False)
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def _base(self) -> str:
        try:
            parsed = urlsplit(self.base_url)
            _ = parsed.port
            loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            if (
                parsed.scheme not in {"http", "https"} or not parsed.hostname
                or (parsed.scheme != "https" and not loopback)
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or "\\" in self.base_url
                or any(ord(char) < 33 for char in self.base_url)
                or any(part in {".", ".."} for part in unquote(parsed.path).split("/"))
            ):
                raise ValueError("invalid source configuration")
        except ValueError as exc:
            raise OxidizedUnavailable from exc
        return self.base_url.rstrip("/")

    async def _get(self, endpoint: str, **params: str) -> list[Any]:
        if not _SOURCE_SLOTS.acquire(blocking=False):
            raise OxidizedUnavailable
        try:
            return await self._request(endpoint, **params)
        finally:
            _SOURCE_SLOTS.release()

    async def _request(self, endpoint: str, **params: str) -> list[Any]:
        url = self._base() + endpoint
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            async with asyncio.timeout(12):
                async with httpx.AsyncClient(
                    timeout=5.0, follow_redirects=False, transport=self._transport,
                ) as client:
                    for attempt in range(2):
                        async with client.stream("GET", url, params=params, headers=headers) as response:
                            if response.status_code in {502, 503, 504} and attempt == 0:
                                continue
                            if response.status_code != 200:
                                raise OxidizedUnavailable
                            if response.headers.get("content-encoding", "identity") != "identity":
                                raise OxidizedUnavailable
                            body = bytearray()
                            async for chunk in response.aiter_bytes():
                                body.extend(chunk)
                                if len(body) > MAX_BYTES:
                                    raise OxidizedUnavailable
                            payload: object = json.loads(body)
                            if not isinstance(payload, list):
                                raise OxidizedUnavailable
                            return payload
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, RecursionError, TimeoutError) as exc:
            raise OxidizedUnavailable from exc
        raise OxidizedUnavailable

    async def nodes(self) -> ConfigurationNodes:
        rows = await self._get("/nodes.json")
        items: list[ConfigurationNode] = []
        skipped = 0
        seen: set[str] = set()
        for row in rows[:MAX_ROWS]:
            node = self._node(row)
            if node is None or node.id in seen:
                skipped += 1
                continue
            seen.add(node.id)
            items.append(node)
        truncated = len(rows) > MAX_ROWS
        if skipped and not items:
            raise OxidizedUnavailable
        return ConfigurationNodes(
            state="partial" if skipped or truncated else "ok", observed_at=datetime.now(UTC),
            items=sorted(items, key=lambda item: item.name), skipped=skipped, truncated=truncated,
        )

    @staticmethod
    def _node(row: object) -> ConfigurationNode | None:
        if not isinstance(row, dict) or not valid_segment(row.get("name")):
            return None
        name = str(row["name"])
        group = row.get("group")
        # oxidized-web rewrites a missing group to the display word "default".
        # full_name is the upstream key; do not mistake that display label for
        # a real group when requesting version metadata.
        full = row.get("full_name")
        if full is not None:
            if (
                not isinstance(full, str) or len(full) > 511
                or any(not valid_segment(part) for part in full.split("/"))
                or full.split("/")[-1] != name
            ):
                return None
            group = full.rpartition("/")[0] or None
        elif group == "default":
            return None  # ambiguous without the upstream key: fail closed
        if group is not None and (
            not isinstance(group, str) or len(group) > 255
            or any(not valid_segment(part) for part in group.split("/"))
        ):
            return None
        full_name = f"{group}/{name}" if group else name
        last = row.get("last")
        status = last.get("status") if isinstance(last, dict) else row.get("status", "never")
        attempt_at = source_time(last.get("end") if isinstance(last, dict) else row.get("time"))
        backup_status: Literal["success", "failed", "never", "unknown"] = (
            "success" if status == "success" else "never" if status == "never"
            else "failed" if status in {"failed", "failure", "no_connection"} else "unknown"
        ) if isinstance(status, str) else "unknown"
        freshness: Literal["fresh", "stale", "unknown"] = "unknown"
        if backup_status == "success" and attempt_at is not None:
            freshness = "stale" if datetime.now(UTC) - attempt_at > timedelta(hours=24) else "fresh"
        try:
            return ConfigurationNode(
                id=canonical_node_id(full_name), name=name, group=group, model=row.get("model"),
                backup_status=backup_status, last_attempt_at=attempt_at, backup_freshness=freshness,
            )
        except ValidationError:
            return None

    async def versions(self, node_id: str) -> ConfigurationVersions:
        snapshot = await self.nodes()
        node = next((item for item in snapshot.items if item.id == node_id), None)
        if node is None:
            if snapshot.state == "partial":
                raise OxidizedUnavailable
            raise ConfigurationNodeNotFound
        full_name = f"{node.group}/{node.name}" if node.group else node.name
        rows = await self._get("/node/version.json", node_full=full_name)
        items: list[ConfigurationVersion] = []
        skipped = 0
        seen: set[str] = set()
        for row in rows[:MAX_ROWS]:
            try:
                if not isinstance(row, dict):
                    raise TypeError("invalid row")
                when = source_time(row.get("time", row.get("date")))
                item = ConfigurationVersion.model_validate({"id": row.get("oid"), "saved_at": when})
                if item.id in seen:
                    raise ValueError("duplicate version")
                seen.add(item.id)
                items.append(item)
            except (ValueError, TypeError):
                skipped += 1
        if skipped and not items:
            raise OxidizedUnavailable
        truncated = len(rows) > MAX_ROWS
        return ConfigurationVersions(
            state="partial" if skipped or truncated else "ok", observed_at=datetime.now(UTC),
            items=sorted(items, key=lambda item: item.saved_at, reverse=True),
            skipped=skipped, truncated=truncated,
        )
