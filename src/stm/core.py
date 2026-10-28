"""Public orchestration API for bounded, session-scoped working context.

Backends are injected behind small interfaces.  This coordinator never calls a
model, promotes evidence into long-term memory, or infers a user's identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from typing import Callable
from uuid import uuid4

from .models import (
    ContextPacker,
    ContextRetriever,
    MemoryKind,
    MemoryOrigin,
    MemoryPolicy,
    MemoryRecord,
    MemoryStore,
    PrivacyScope,
    PromptContext,
    SessionKey,
    utc_now,
)

# The governance module owns the authenticated Actor type.  A minimal local
# fallback supports contract tests with an explicitly injected mock policy.
try:
    from .governance import Actor
except ModuleNotFoundError as error:
    if error.name != __package__ + ".governance":
        raise

    @dataclass(frozen=True, slots=True)
    class Actor:
        tenant_id: str
        owner_id: str
        agent_id: str
        session_id: str
        roles: frozenset[str] = frozenset()


class AdmissionRejected(ValueError):
    """An observation cannot enter this working-memory session."""


class AccessDenied(PermissionError):
    """The actor lacks authority to access this memory."""


class STM:
    """Facade wiring independently replaceable working-memory components.

    All memory is scoped by *four* explicit IDs.  A newly created STM instance
    has its own storage; it does not share memory globally.  The default backend
    requires only the Python standard library once the sibling modules are
    integrated in the package.
    """

    def __init__(
        self,
        *,
        store: MemoryStore | None = None,
        retriever: ContextRetriever | None = None,
        packer: ContextPacker | None = None,
        policy: MemoryPolicy | None = None,
        cache: object | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if store is None:
            from .storage import InMemoryStore as StorageBackend

            store = StorageBackend(clock=clock)
        if retriever is None:
            from .retrieval import ContextRetriever as RetrieverBackend

            retriever = RetrieverBackend()
        if packer is None:
            from .context import ContextPacker as PackerBackend

            packer = PackerBackend()
        if policy is None:
            from .governance import GovernancePolicy

            policy = GovernancePolicy()
        self.store = store
        self.retriever = retriever
        self.packer = packer
        self.policy = policy
        self.cache = cache
        self.clock = clock

    def open_session(
        self,
        *,
        owner_id: str,
        agent_id: str,
        tenant_id: str = "local",
        session_id: str | None = None,
    ) -> "MemorySession":
        key = SessionKey(
            tenant_id=tenant_id,
            owner_id=owner_id,
            agent_id=agent_id,
            session_id=session_id or uuid4().hex,
        )
        return MemorySession(self, key)

    create_session = open_session


class MemorySession:
    """An authorization-bound view, never an all-sessions search surface."""

    def __init__(self, stm: STM, key: SessionKey) -> None:
        self._stm = stm
        self.key = key
        self.actor = Actor(key.tenant_id, key.owner_id, key.agent_id, key.session_id)
        self._last_context: PromptContext | None = None

    @property
    def session_id(self) -> str:
        return self.key.session_id

    def _now(self) -> datetime:
        now = self._stm.clock()
        if now.tzinfo is None:
            raise ValueError("clock must provide timezone-aware datetimes")
        return now

    def _admit(self, content: str, source: str, kind: MemoryKind,
               privacy: PrivacyScope, origin: MemoryOrigin) -> None:
        if not isinstance(content, str) or not content.strip():
            raise ValueError("memory content must be a non-empty string")
        if not source:
            raise ValueError("a provenance source is required")
        decision = self._stm.policy.admit(
            self.actor, content, source=source, kind=kind, privacy=privacy,
            origin=origin,
            evidence_is_historical=(origin == "historical"),
        )
        if not decision.allowed or decision.quarantine:
            raise AdmissionRejected(", ".join(decision.reasons) or "memory admission denied")

    def append(
        self,
        content: str,
        *,
        role: str = "user",
        source: str = "conversation",
        kind: MemoryKind = "observation",
        origin: MemoryOrigin = "direct",
        privacy: PrivacyScope = "private",
        pinned: bool = False,
        ttl_seconds: float | None = None,
    ) -> MemoryRecord:
        self._admit(content, source, kind, privacy, origin)
        if not role:
            raise ValueError("role is required")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = self._now()
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds is not None else None
        record = MemoryRecord(
            id=uuid4().hex,
            scope=self.key,
            content=content,
            role=role,
            source=source,
            kind=kind,
            privacy=privacy,
            pinned=pinned,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            origin=origin,
        )
        self._stm.policy.authorize_write(self.actor, record)
        self._stm.store.add(record)
        self._invalidate_cache()
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        record = self._stm.store.get(self.key, record_id, self._now())
        if record is None:
            return None
        if not self._stm.policy.authorize_read(self.actor, record, now=self._now()):
            raise AccessDenied("read refused by memory policy")
        return record

    def correct(self, record_id: str, content: str, *, expected_version: int | None = None) -> MemoryRecord:
        current = self.get(record_id)
        if current is None:
            raise KeyError(record_id)
        self._admit(content, current.source, current.kind, current.privacy, current.origin)
        updated = current.corrected(content, self._now())
        self._stm.policy.authorize_correction(self.actor, current, updated)
        self._stm.store.replace(
            self.key,
            updated,
            expected_version=current.version if expected_version is None else expected_version,
        )
        self._invalidate_cache()
        return updated

    def delete(self, record_id: str) -> bool:
        if self.get(record_id) is None:
            return False
        deleted = self._stm.store.delete(self.key, record_id)
        if deleted:
            self._invalidate_cache()
        return deleted

    def retrieve(self, query: str, *, limit: int = 20) -> list[MemoryRecord]:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        now = self._now()
        records = [
            record for record in self._stm.store.list(self.key, now)
            if self._stm.policy.authorize_read(self.actor, record, now=now)
        ]
        ranked = self._stm.retriever.rank(
            query, records, limit,
            scope=self.key,
            now=now,
        )
        return [result.record for result in ranked]

    def assemble_context(self, query: str, *, token_budget: int, reserved_tokens: int = 0,
                         limit: int = 100,
                         authorized_privacy_scopes: frozenset[str] | None = None) -> PromptContext:
        """Pack attributed *data*, never instructions or asserted truths.

        Selection is deterministic for fixed records/query/token counter.  Both
        item metadata and separators are included in the packer's token count.
        A pinned item that cannot fit causes an explicit budget failure.
        """
        from .context import ContextItem, TokenBudget

        if token_budget < 0 or reserved_tokens < 0:
            raise ValueError("budgets must be nonnegative")
        if limit < 0:
            raise ValueError("limit must be nonnegative")
        if authorized_privacy_scopes is not None and (
            not isinstance(authorized_privacy_scopes, frozenset)
            or not authorized_privacy_scopes
            or any(not isinstance(label, str) or not label.strip()
                   for label in authorized_privacy_scopes)
        ):
            raise ValueError("authorized privacy scopes must be a nonempty frozenset")
        now = self._now()
        records = [
            record for record in self._stm.store.list(self.key, now)
            if (authorized_privacy_scopes is None
                or record.privacy in authorized_privacy_scopes)
            and self._stm.policy.authorize_read(self.actor, record, now=now)
        ]
        ranked = self._stm.retriever.rank(
            query, records, limit,
            scope=self.key,
            now=now,
        )
        # Relevance ranking, deduplication and a finite retrieval limit are
        # allowed to discard optional candidates, but NEVER pinned ones.
        # Include every authorized pinned record from storage before packing.
        pinned = sorted((rec for rec in records if rec.pinned),
                        key=lambda rec: (rec.created_at, rec.id))
        scored = {entry.record.id: entry.score for entry in ranked}
        chosen = [*pinned]
        chosen_ids = {rec.id for rec in pinned}
        chosen.extend(entry.record for entry in ranked if entry.record.id not in chosen_ids)
        items = []
        for rec in chosen:
            # The data boundary and source label are themselves budgeted.
            attributed_text = (
                f"[untrusted working-context data; source={rec.source}; "
                f"kind={rec.kind}; origin={rec.origin}; role={rec.role}]\n{rec.content}"
            )
            items.append(ContextItem(
                id=rec.id, text=attributed_text, score=scored.get(rec.id, 0.0),
                created_at=rec.created_at.timestamp(), pinned=rec.pinned,
            ))
        packed = self._stm.packer.pack(items, TokenBudget(token_budget, reserved_tokens))
        by_id = {rec.id: rec for rec in chosen}
        context = PromptContext(
            text=packed.text,
            selected=tuple(by_id[item_id] for item_id in packed.included_ids),
            token_count=packed.used_tokens,
            token_budget=packed.available_tokens,
            omitted_count=len(records) - len(packed.included_ids),
        )
        self._last_context = context
        return context

    build_context = assemble_context

    def prune(self) -> int:
        removed = self._stm.store.prune(self.key, self._now())
        if removed:
            self._invalidate_cache()
        return removed

    def checkpoint(self, path: str) -> object:
        return self._stm.store.checkpoint(self.key, path)

    def restore(self, path: str) -> object:
        result = self._stm.store.restore(self.key, path)
        self._invalidate_cache()
        return result

    def stats(self) -> dict[str, object]:
        backend_stats = self._stm.store.stats(self.key)
        if isinstance(backend_stats, dict):
            result = dict(backend_stats)
        else:
            result = vars(backend_stats) if hasattr(backend_stats, "__dict__") else {"storage": backend_stats}
        if self._last_context is not None:
            result["last_prompt_tokens"] = self._last_context.token_count
            result["last_prompt_budget"] = self._last_context.token_budget
            result["last_prompt_omitted"] = self._last_context.omitted_count
        if self._stm.cache is not None:
            result["prompt_cache"] = self._stm.cache.stats()
        return result

    def cache_prefix(self, identity: object, prefix: str) -> object:
        """Optional *application-level* prefix cache; not a model KV-cache."""
        if self._stm.cache is None:
            raise RuntimeError("no application prompt-prefix cache configured")
        for attr in ("tenant_id", "owner_id", "agent_id", "session_id"):
            if getattr(identity, attr, None) != getattr(self.key, attr):
                raise AccessDenied("cache identity does not match memory session")
        revision = hashlib.sha256(prefix.encode("utf-8")).hexdigest()
        return self._stm.cache.get_or_store(identity, prefix, revision)

    def _invalidate_cache(self) -> None:
        if self._stm.cache is not None:
            self._stm.cache.invalidate_session(
                self.key.tenant_id, self.key.owner_id,
                self.key.agent_id, self.key.session_id,
            )


__all__ = ["STM", "MemorySession", "Actor", "AdmissionRejected", "AccessDenied"]
