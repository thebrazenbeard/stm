"""Deterministic, scope-first STM retrieval.

No LLM, embedding service, durable historical store, or remote API is required.
Scores indicate *retrieval relevance*, never truth, identity, consent, or authority.

The caller must authorize a session before calling ``rank``. Scoped records without
an explicit owner and session cause an error instead of a broad search.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import ceil, isfinite, log, sqrt
import re
from typing import Any, Callable, Iterable, Protocol, Sequence
import unicodedata


_TOKENS = re.compile(r"[^\W_]+(?:'[^\W_]+)?", re.UNICODE)
_STOP = frozenset({"a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "how",
                   "in", "is", "it", "me", "my", "of", "on", "or", "our", "the", "to",
                   "was", "were", "what", "when", "where", "which", "who", "with"})
_NEGATION = frozenset({"not", "never", "no"})


def _get(record: Any, key: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def _scope(record: Any, key: str) -> Any:
    direct = _get(record, key)
    if direct is not None:
        return direct
    nested = _get(record, "scope")
    return _get(nested, key) if nested is not None else None


def _words(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = normalized.replace("isn't", "is not").replace("aren't", "are not")
    normalized = normalized.replace("wasn't", "was not").replace("weren't", "were not")
    return tuple(_TOKENS.findall(normalized))


def _key(text: str) -> str:
    # Keep punctuation: "x < y" and "x > y" must never be merged merely
    # because both have the same lexical search terms.
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _timestamp(value: Any, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Memory timestamps must be timezone-aware")
        return value.timestamp()
    if isinstance(value, (int, float)) and isfinite(value):
        return float(value)
    raise TypeError("Memory timestamp must be a timezone-aware datetime or epoch seconds")


class Embedder(Protocol):
    """Local or injected semantic model; embedding output is non-authoritative."""

    def embed(self, text: str) -> Sequence[float]: ...


@dataclass(frozen=True)
class RankedRecord:
    record: Any
    score: float
    provenance_ids: tuple[str, ...]
    potential_contradictions: tuple[str, ...] = ()
    matched_terms: tuple[str, ...] = ()
    token_cost: int = 0
    semantic_used: bool = False
    provenance_records: tuple[Any, ...] = ()


@dataclass(frozen=True)
class ContextGroup:
    """Presentation grouping; hierarchy never grants authority or permissions."""

    topic: str
    results: tuple[RankedRecord, ...]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError("Embeddings must have the same nonzero dimensions")
    if any(not isfinite(float(x)) for x in a) or any(not isfinite(float(x)) for x in b):
        raise ValueError("Embeddings must be finite")
    denominator = sqrt(sum(float(x) ** 2 for x in a)) * sqrt(sum(float(x) ** 2 for x in b))
    return max(0.0, sum(float(x) * float(y) for x, y in zip(a, b)) / denominator) if denominator else 0.0


class ContextRetriever:
    """Retrieves current records from one explicitly authorized session.

    The weighted lexical baseline rewards rare overlapping query terms and
    recency. Optional embeddings refine relevance but cannot change visibility.
    Exact normalized duplicate records are grouped *after* authorization and
    their original record objects and IDs remain available for provenance.
    """

    def __init__(
        self,
        *,
        embedder: Embedder | None = None,
        semantic_weight: float = 0.25,
        recency_half_life_hours: float = 72.0,
        embedding_errors: str = "raise",
    ) -> None:
        if not 0 <= semantic_weight <= 1:
            raise ValueError("semantic_weight must be within [0, 1]")
        if recency_half_life_hours <= 0:
            raise ValueError("recency_half_life_hours must be positive")
        if embedding_errors not in ("raise", "fallback"):
            raise ValueError("embedding_errors must be 'raise' or 'fallback'")
        self.embedder = embedder
        self.semantic_weight = semantic_weight
        self.recency_half_life_hours = recency_half_life_hours
        self.embedding_errors = embedding_errors

    def rank(
        self,
        query: str,
        records: Iterable[Any],
        limit: int = 10,
        *,
        owner_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        scope: Any | None = None,
        now: datetime | None = None,
        token_budget: int | None = None,
        token_counter: Callable[[str], int] | None = None,
    ) -> list[RankedRecord]:
        if limit < 0:
            raise ValueError("limit must be nonnegative")
        if token_budget is not None and token_budget < 0:
            raise ValueError("token_budget must be nonnegative")
        if limit == 0 or token_budget == 0:
            return []
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        now_ts = now.timestamp()
        requested = {"tenant_id": tenant_id, "owner_id": owner_id,
                     "agent_id": agent_id, "session_id": session_id}
        if scope is not None:
            for field in requested:
                value = _get(scope, field)
                if requested[field] is not None and requested[field] != value:
                    raise ValueError(f"Explicit {field} conflicts with scope")
                requested[field] = value
        pool: list[Any] = []
        for record in records:
            item_scope = {field: _scope(record, field) for field in requested}
            if any(value is not None and requested[field] is None for field, value in item_scope.items()):
                raise ValueError("Full tenant/owner/agent/session identity is required for scoped retrieval")
            if any(value is not None and value != requested[field] for field, value in item_scope.items()):
                continue
            if _get(record, "deleted", False):
                continue
            expires_at = _get(record, "expires_at")
            if expires_at is not None and _timestamp(expires_at, now_ts) <= now_ts:
                continue
            pool.append(record)

        # Collapse identical content only within one already-authorized scope.
        # Keep all matching objects for traceability; prefer latest representative.
        grouped: dict[str, list[Any]] = {}
        for record in pool:
            grouped.setdefault(_key(str(_get(record, "content", ""))), []).append(record)
        candidates: list[tuple[Any, tuple[Any, ...]]] = []
        for copies in grouped.values():
            copies.sort(key=lambda r: (-_timestamp(_get(r, "updated_at", _get(r, "created_at")), 0), str(_get(r, "id", ""))))
            candidates.append((copies[0], tuple(copies)))

        query_terms = {w for w in _words(query) if w not in _STOP}
        doc_terms = [{w for w in _words(str(_get(r, "content", ""))) if w not in _STOP} for r, _ in candidates]
        frequency: dict[str, int] = {}
        for terms in doc_terms:
            for word in terms:
                frequency[word] = frequency.get(word, 0) + 1
        total = len(candidates)
        query_weights = {term: 1.0 + log((total + 1) / (frequency.get(term, 0) + .5)) for term in query_terms}
        denom = sum(query_weights.values()) or 1.0

        query_vector: Sequence[float] | None = None
        if self.embedder is not None and candidates:
            try:
                query_vector = self.embedder.embed(query)
            except Exception:
                if self.embedding_errors == "raise":
                    raise

        counter = token_counter or (lambda s: max(1, ceil(len(s) / 4)))
        scored: list[RankedRecord] = []
        for (record, copies), terms in zip(candidates, doc_terms):
            match = terms & query_terms
            lexical = sum(query_weights[w] for w in match) / denom
            updated = _timestamp(_get(record, "updated_at", _get(record, "created_at")), now_ts)
            age_hours = max(0.0, (now_ts - updated) / 3600)
            recency = .5 ** (age_hours / self.recency_half_life_hours)
            semantic_used = False
            semantic = 0.0
            if query_vector is not None:
                try:
                    semantic = _cosine(query_vector, self.embedder.embed(str(_get(record, "content", ""))))  # type: ignore[union-attr]
                    semantic_used = True
                except Exception:
                    if self.embedding_errors == "raise":
                        raise
            relevance = (1 - self.semantic_weight) * lexical + self.semantic_weight * semantic if semantic_used else lexical
            score = .85 * relevance + .15 * recency
            text = str(_get(record, "content", ""))
            cost = counter(text)
            if not isinstance(cost, int) or cost < 0:
                raise ValueError("token_counter must return a nonnegative integer")
            scored.append(RankedRecord(record=record, score=score,
                                       provenance_ids=tuple(str(_get(r, "id", "")) for r in copies),
                                       matched_terms=tuple(sorted(match)), token_cost=cost,
                                       semantic_used=semantic_used, provenance_records=copies))

        scored.sort(key=lambda r: (-r.score,
                                   -_timestamp(_get(r.record, "updated_at", _get(r.record, "created_at")), 0),
                                   str(_get(r.record, "id", ""))))
        selected: list[RankedRecord] = []
        remaining = token_budget
        for item in scored:
            if remaining is not None and item.token_cost > remaining:
                continue
            selected.append(item)
            if remaining is not None:
                remaining -= item.token_cost
            if len(selected) >= limit:
                break
        return self._mark_contradictions(selected)

    @staticmethod
    def _mark_contradictions(results: list[RankedRecord]) -> list[RankedRecord]:
        """Conservatively flag near-identical clauses with opposite negation.

        This is a candidate review signal, *not* logical entailment or a claim
        that either record is false. Unrelated clauses are never flagged.
        """
        from dataclasses import replace

        patterns: dict[tuple[str, ...], list[tuple[int, bool]]] = {}
        for i, result in enumerate(results):
            words = _words(str(_get(result.record, "content", "")))
            cleaned = tuple(w for w in words if w not in _NEGATION)
            negated = bool(set(words) & _NEGATION)
            patterns.setdefault(cleaned, []).append((i, negated))
        result_list = list(results)
        for items in patterns.values():
            for i, negated in items:
                opposite_ids = sorted(str(_get(result_list[j].record, "id", "")) for j, opposite in items if opposite != negated)
                if opposite_ids:
                    result_list[i] = replace(result_list[i], potential_contradictions=tuple(opposite_ids))
        return result_list

    @staticmethod
    def group_by_topic(results: Iterable[RankedRecord]) -> list[ContextGroup]:
        groups: dict[str, list[RankedRecord]] = {}
        for result in results:
            topic = str(_get(result.record, "topic", None) or _get(result.record, "parent_id", None) or "ungrouped")
            groups.setdefault(topic, []).append(result)
        return [ContextGroup(topic, tuple(rows)) for topic, rows in groups.items()]
