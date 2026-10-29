"""Stable, model-independent contracts for an agent's working memory.

No record in this module is a claim that its content is true.  ``kind`` and
``source`` tell the consumer what evidence, if any, an entry represents.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Literal, Protocol, Sequence


MemoryKind = Literal["observation", "interpretation", "hypothesis"]
PrivacyScope = Literal["private", "session", "shared"]
MemoryOrigin = Literal["direct", "external", "historical"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class SessionKey:
    tenant_id: str
    owner_id: str
    agent_id: str
    session_id: str

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.owner_id, self.agent_id, self.session_id)):
            raise ValueError("tenant, owner, agent, and session IDs must be non-empty")


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    id: str
    scope: SessionKey
    content: str
    role: str
    source: str
    kind: MemoryKind
    privacy: PrivacyScope
    pinned: bool
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    version: int = 1
    origin: MemoryOrigin = "direct"

    def __post_init__(self) -> None:
        if not self.id or not self.content.strip() or not self.source:
            raise ValueError("record id, content, and provenance source must be non-empty")
        if self.kind not in ("observation", "interpretation", "hypothesis"):
            raise ValueError("unsupported evidence kind")
        if self.privacy not in ("private", "session", "shared"):
            raise ValueError("unsupported privacy label")
        if self.version < 1:
            raise ValueError("version must be positive")
        if self.origin not in ("direct", "external", "historical"):
            raise ValueError("unsupported evidence origin")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("timestamps must be timezone aware")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expiration must be timezone aware")

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def corrected(self, content: str, now: datetime) -> "MemoryRecord":
        return replace(self, content=content, updated_at=now, version=self.version + 1)


@dataclass(frozen=True, slots=True)
class RankedRecord:
    record: MemoryRecord
    score: float


@dataclass(frozen=True, slots=True)
class PromptContext:
    text: str
    selected: tuple[MemoryRecord, ...]
    token_count: int
    token_budget: int
    omitted_count: int


class MemoryStore(Protocol):
    def add(self, record: MemoryRecord) -> None: ...
    def get(self, scope: SessionKey, record_id: str, now: datetime) -> MemoryRecord | None: ...
    def list(self, scope: SessionKey, now: datetime) -> list[MemoryRecord]: ...
    def replace(self, scope: SessionKey, record: MemoryRecord, expected_version: int) -> None: ...
    def delete(self, scope: SessionKey, record_id: str) -> bool: ...
    def prune(self, scope: SessionKey, now: datetime) -> int: ...


class ContextRetriever(Protocol):
    def rank(self, query: str, records: Sequence[MemoryRecord], limit: int) -> list[RankedRecord]: ...


class ContextPacker(Protocol):
    def pack(self, records: Sequence[MemoryRecord], token_budget: int) -> PromptContext: ...


class MemoryPolicy(Protocol):
    def validate_admission(self, scope: SessionKey, record: MemoryRecord) -> None: ...
    def validate_read(self, scope: SessionKey, record: MemoryRecord) -> None: ...


class VersionConflict(RuntimeError):
    """The caller attempted to replace a stale version of a record."""


class CapacityExceeded(RuntimeError):
    """Storage cannot admit an entry without silently losing pinned content."""
