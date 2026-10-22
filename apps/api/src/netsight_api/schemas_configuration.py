"""Read-only configuration backup metadata; configuration bodies never cross this boundary."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import ApiModel

NODE_ID_PATTERN = r"^config-node-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
ReadState = Literal["ok", "partial", "not-connected", "unknown"]


class ConfigurationNode(ApiModel):
    id: str = Field(pattern=NODE_ID_PATTERN)
    name: str = Field(min_length=1, max_length=255)
    group: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=128)
    backup_status: Literal["success", "failed", "never", "unknown"]
    last_attempt_at: AwareDatetime | None
    backup_freshness: Literal["fresh", "stale", "unknown"]

    @model_validator(mode="after")
    def valid_freshness(self) -> ConfigurationNode:
        if self.backup_freshness != "unknown" and (
            self.last_attempt_at is None or self.backup_status != "success"
        ):
            raise ValueError("only a timestamped successful backup has known freshness")
        return self


class ConfigurationVersion(ApiModel):
    id: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    saved_at: AwareDatetime


class ConfigurationRead[T: ConfigurationNode | ConfigurationVersion](ApiModel):
    source: Literal["oxidized"] = "oxidized"
    state: ReadState
    observed_at: AwareDatetime | None
    items: list[T] = Field(default_factory=list, max_length=2000)
    skipped: int = Field(default=0, ge=0, le=2000)
    truncated: bool = False
    page: int = Field(default=1, ge=1, le=2000)
    page_size: int = Field(default=2000, ge=1, le=2000)
    total: int | None = Field(default=None, ge=0, le=2000)
    has_more: bool = False

    @model_validator(mode="after")
    def coherent_read(self) -> ConfigurationRead[T]:
        readable = self.state in {"ok", "partial"}
        if readable != (self.observed_at is not None):
            raise ValueError("only a completed source read carries an observation time")
        if not readable and (self.items or self.skipped or self.truncated):
            raise ValueError("unavailable reads carry no rows or counts")
        if readable and ((self.state == "partial") != (self.skipped > 0 or self.truncated)):
            raise ValueError("partial reads explicitly account for incomplete data")
        if not readable and (self.total is not None or self.has_more):
            raise ValueError("unavailable reads carry no pagination counts")
        if len(self.items) > self.page_size:
            raise ValueError("a page must fit the requested size")
        if len({item.id for item in self.items}) != len(self.items):
            raise ValueError("source identifiers must be unique")
        return self


ConfigurationNodes = ConfigurationRead[ConfigurationNode]
ConfigurationVersions = ConfigurationRead[ConfigurationVersion]
