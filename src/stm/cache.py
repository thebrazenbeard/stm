"""Bounded, identity-scoped APPLICATION-LEVEL prompt-prefix cache for STM.

This module does not store model KV tensors and does not claim that an inference
engine reused its internal KV cache. A ``hit`` means only that STM found the
same exact rendered prefix in its own process memory. Backends may report
their own cache use separately through ``OllamaUsage``.

No backend, HTTP library, tokenizer, or hosted service is required.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from threading import RLock
from time import monotonic
from typing import Any, Callable, Literal, Mapping


@dataclass(frozen=True, slots=True)
class CacheIdentity:
    """Exact scope of a rendered prompt prefix.

    ``model_fingerprint`` should identify model weights/revision, not merely a
    mutable display tag. ``tokenizer_fingerprint`` includes tokenizer version;
    ``template_fingerprint`` includes the renderer, system policy and options
    that affect prompt bytes. The application must supply trustworthy identities.
    """

    tenant_id: str
    owner_id: str
    agent_id: str
    session_id: str
    model_fingerprint: str
    tokenizer_fingerprint: str
    template_fingerprint: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a nonempty string")
            if len(value) > 512:
                raise ValueError(f"{name} must have at most 512 characters")


@dataclass(frozen=True, slots=True)
class CacheDecision:
    """Result of an exact rendered-prefix comparison.

    ``status='hit'`` never implies GPU memory, runtime KV reuse, or inference
    speedup. ``prefix`` is returned only because the caller supplied its exact
    value in the lookup call; no lookup-by-identity disclosure is supported.
    """

    status: Literal["hit", "miss"]
    stored: bool
    prefix: str
    prefix_digest: str
    invalidation_reason: str | None = None
    cache_kind: Literal["application_prompt_prefix"] = "application_prompt_prefix"


@dataclass(frozen=True, slots=True)
class CacheStats:
    hits: int
    misses: int
    invalidations: int
    evictions: int
    expired: int
    oversized: int
    entries: int
    payload_bytes: int
    max_entries: int
    max_bytes: int


@dataclass(slots=True)
class _Entry:
    prefix: str
    digest: str
    revision: str
    payload_bytes: int
    created_at: float


class BoundedPromptPrefixCache:
    """Exact-match prompt-prefix reuse with LRU eviction and fixed-age TTL.

    Concurrency: operations and counters are protected by a process-local lock.
    Privacy: entries never share identity scopes, but this is not an
    authentication system; the host must authenticate identity attributes.
    Memory: ``max_bytes`` bounds UTF-8 payload bytes, not Python object or
    dict overhead. ``max_entries`` also bounds entry/metadata count.
    Lifecycle: ephemeral by design, never checkpointed; session deletion must
    call ``invalidate_session`` and context edits should advance ``revision``.
    """

    def __init__(
        self,
        *,
        max_entries: int = 128,
        max_bytes: int = 1_048_576,
        max_prefix_bytes: int = 131_072,
        max_age_seconds: float | None = 300.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if any(type(v) is not int or v < 1 for v in (max_entries, max_bytes, max_prefix_bytes)):
            raise ValueError("capacity limits must be positive integers")
        if max_age_seconds is not None and (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, (int, float))
            or max_age_seconds <= 0
            or not isfinite(max_age_seconds)
        ):
            raise ValueError("max_age_seconds must be positive or None")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.max_prefix_bytes = max_prefix_bytes
        self.max_age_seconds = max_age_seconds
        self._clock = clock
        self._lock = RLock()
        self._entries: OrderedDict[CacheIdentity, _Entry] = OrderedDict()
        self._payload_bytes = 0
        self._hits = 0
        self._misses = 0
        self._invalidations = 0
        self._evictions = 0
        self._expired = 0
        self._oversized = 0

    def _remove(self, identity: CacheIdentity) -> _Entry:
        entry = self._entries.pop(identity)
        self._payload_bytes -= entry.payload_bytes
        return entry

    def _prune_expired_locked(self, now: float) -> int:
        if self.max_age_seconds is None:
            return 0
        expired_keys = [
            key for key, entry in self._entries.items()
            if now - entry.created_at >= self.max_age_seconds
        ]
        for key in expired_keys:
            self._remove(key)
        self._expired += len(expired_keys)
        self._invalidations += len(expired_keys)
        return len(expired_keys)

    def prune_expired(self) -> int:
        """Drop entries past the configured fixed-age limit."""
        with self._lock:
            return self._prune_expired_locked(self._clock())

    def get_or_store(
        self,
        identity: CacheIdentity,
        prefix: str,
        context_revision: str,
    ) -> CacheDecision:
        """Compare exact bytes; if absent, store the new rendered prefix.

        A changed context revision (including a compaction event) invalidates
        the previous entry even when text happens to match. A changed model,
        tokenizer or template fingerprint uses a distinct identity key.
        """
        if not isinstance(identity, CacheIdentity):
            raise TypeError("identity must be a CacheIdentity")
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")
        if not isinstance(context_revision, str) or not context_revision.strip():
            raise ValueError("context_revision must be a nonempty string")
        data = prefix.encode("utf-8")
        size = len(data)
        digest = sha256(data).hexdigest()

        with self._lock:
            self._prune_expired_locked(self._clock())
            existing = self._entries.get(identity)
            reason = None
            if existing is not None:
                if existing.revision != context_revision:
                    reason = "context_revision_changed"
                elif existing.digest != digest or existing.prefix != prefix:
                    reason = "rendered_prefix_changed"
                else:
                    self._hits += 1
                    self._entries.move_to_end(identity)
                    return CacheDecision("hit", True, existing.prefix, existing.digest)
                self._remove(identity)
                self._invalidations += 1

            self._misses += 1
            if size > self.max_prefix_bytes or size > self.max_bytes:
                self._oversized += 1
                return CacheDecision(
                    "miss", False, prefix, digest,
                    invalidation_reason=reason or "prefix_too_large",
                )

            while self._entries and (
                len(self._entries) >= self.max_entries
                or self._payload_bytes + size > self.max_bytes
            ):
                oldest_key = next(iter(self._entries))
                self._remove(oldest_key)
                self._evictions += 1

            self._entries[identity] = _Entry(
                prefix=prefix,
                digest=digest,
                revision=context_revision,
                payload_bytes=size,
                created_at=self._clock(),
            )
            self._payload_bytes += size
            return CacheDecision("miss", True, prefix, digest, reason)

    def invalidate_identity(self, identity: CacheIdentity) -> bool:
        """Discard one scope (e.g. model or tokenizer settings changed)."""
        with self._lock:
            if identity not in self._entries:
                return False
            self._remove(identity)
            self._invalidations += 1
            return True

    def invalidate_session(
        self, tenant_id: str, owner_id: str, agent_id: str, session_id: str,
    ) -> int:
        """Discard every model/renderer variant belonging to one session."""
        if not all(isinstance(v, str) and v.strip() for v in (tenant_id, owner_id, agent_id, session_id)):
            raise ValueError("tenant_id, owner_id, agent_id and session_id must be nonempty")
        with self._lock:
            keys = [
                k for k in self._entries
                if (k.tenant_id, k.owner_id, k.agent_id, k.session_id)
                == (tenant_id, owner_id, agent_id, session_id)
            ]
            for key in keys:
                self._remove(key)
            self._invalidations += len(keys)
            return len(keys)

    def clear(self) -> int:
        """Delete all cached plaintext, e.g. on shutdown or policy change."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._payload_bytes = 0
            self._invalidations += count
            return count

    def stats(self) -> CacheStats:
        """Aggregate observations; excludes session text and identities."""
        with self._lock:
            self._prune_expired_locked(self._clock())
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                invalidations=self._invalidations,
                evictions=self._evictions,
                expired=self._expired,
                oversized=self._oversized,
                entries=len(self._entries),
                payload_bytes=self._payload_bytes,
                max_entries=self.max_entries,
                max_bytes=self.max_bytes,
            )


@dataclass(frozen=True, slots=True)
class OllamaUsage:
    """Observed final-response metrics, not an assertion of internal KV state."""

    prompt_tokens: int | None
    prompt_cached_tokens_reported: int | None
    prompt_eval_nanoseconds: int | None

    @classmethod
    def from_response(cls, data: Mapping[str, Any]) -> "OllamaUsage":
        """Parse a completed Ollama /api/generate or /api/chat response.

        Partial streaming chunks do not contain reliable final usage. Ollama
        versions or routes may omit a metric; that leaves it UNKNOWN.
        """
        if not isinstance(data, Mapping):
            raise TypeError("data must be a mapping")
        if data.get("done") is not True:
            return cls(None, None, None)

        def nonnegative_int(name: str) -> int | None:
            value = data.get(name)
            return value if type(value) is int and value >= 0 else None

        prompt = nonnegative_int("prompt_eval_count")
        cached = nonnegative_int("prompt_eval_cached_count")
        duration = nonnegative_int("prompt_eval_duration")
        if prompt is not None and cached is not None and cached > prompt:
            raise ValueError("backend-reported cached count exceeds prompt count")
        return cls(prompt, cached, duration)

    @property
    def cache_evidence(self) -> Literal["unreported", "zero_cached_tokens_reported", "cached_tokens_reported"]:
        if self.prompt_cached_tokens_reported is None:
            return "unreported"
        return (
            "cached_tokens_reported"
            if self.prompt_cached_tokens_reported > 0
            else "zero_cached_tokens_reported"
        )


@dataclass(frozen=True, slots=True)
class MockResponse:
    text: str
    application_cache: CacheDecision
    backend_cache_evidence: Literal["unverified"] = "unverified"


class MockLocalBackend:
    """Deterministic, offline test double; DOES NOT simulate backend KV reuse."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(
        self,
        *,
        identity: CacheIdentity,
        rendered_prefix: str,
        user_input: str,
        context_revision: str,
        cache: BoundedPromptPrefixCache,
    ) -> MockResponse:
        if not isinstance(user_input, str):
            raise TypeError("user_input must be a string")
        decision = cache.get_or_store(identity, rendered_prefix, context_revision)
        self.calls += 1
        return MockResponse(
            text=f"[mock response {self.calls}] {user_input}",
            application_cache=decision,
        )
