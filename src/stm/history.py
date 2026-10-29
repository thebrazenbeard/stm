"""Read-only historical evidence boundary for DeepMemoryStorage adapters.

The historical archive is a separate governed evidence plane. This module
does not read it on its own, and intentionally has no write/admission method.
An integration supplies a query callback that has authenticated the caller and
enforced all archive-specific permissions before returning results.

Source research: thebrazenbeard/deepmemorystorage architecture integration
contract at 0cb0a483413728d4b6384a2500d56036a28e66ee. The repository is
source-visible proprietary; this is an independent interface, not a copy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol, Sequence

from .models import SessionKey


HISTORICAL_ONLY = "HISTORICAL_EVIDENCE_ONLY_NOT_CURRENT_MEMORY_OR_AUTHORITY"


@dataclass(frozen=True, slots=True)
class HistoricalEvidence:
    memory_id: str
    excerpt: str
    source_ids: tuple[str, ...]
    privacy_scope: str
    provenance_ceiling: str
    currentness_rule: str
    event_time: str | None
    recorded_at: str | None
    ledger_path: str
    retrieved_at: datetime
    result_semantics: str = HISTORICAL_ONLY

    def __post_init__(self) -> None:
        if not all((self.memory_id, self.source_ids, self.privacy_scope,
                    self.provenance_ceiling, self.currentness_rule,
                    self.ledger_path)):
            raise ValueError("historical evidence must preserve provenance and boundaries")
        if self.result_semantics != HISTORICAL_ONLY:
            raise ValueError("historical evidence may not claim current authority")
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieval time must be timezone-aware")


class HistoricalEvidenceReader(Protocol):
    """Caller-scoped read only; not a long-term-memory admission protocol."""

    def search(
        self,
        query: str,
        *,
        scope: SessionKey,
        authorized_privacy_scopes: frozenset[str],
        limit: int = 8,
    ) -> Sequence[HistoricalEvidence]: ...


class HistoricalEvidenceBridge:
    """Validate a separately authorized archive query and its response.

    ``fetch`` must authenticate ``scope`` and enforce archive privacy on its
    side. The bridge applies additional fail-closed response filtering. Results
    have a different type from live STM records, preventing accidental direct
    insertion via ``InMemoryStore.add`` or session APIs.
    """

    def __init__(
        self,
        fetch: Callable[[str, SessionKey, frozenset[str], int], Sequence[HistoricalEvidence]],
    ) -> None:
        self._fetch = fetch

    def search(
        self,
        query: str,
        *,
        scope: SessionKey,
        authorized_privacy_scopes: frozenset[str],
        limit: int = 8,
    ) -> tuple[HistoricalEvidence, ...]:
        if not query.strip() or limit < 1:
            raise ValueError("query must be non-empty and limit positive")
        if not authorized_privacy_scopes:
            raise PermissionError("historical privacy authorization required")
        if not isinstance(scope, SessionKey):
            raise PermissionError("caller session identity required")
        rows = tuple(self._fetch(query, scope, authorized_privacy_scopes, limit))
        if len(rows) > limit:
            raise ValueError("archive exceeded explicit result limit")
        for row in rows:
            if not isinstance(row, HistoricalEvidence):
                raise TypeError("archive returned a nonhistorical result")
            if row.privacy_scope not in authorized_privacy_scopes:
                raise PermissionError("archive returned a record outside caller privacy grant")
        return rows
