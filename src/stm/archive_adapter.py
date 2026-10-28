"""Read-only, source-attributed bridge from the local conversation archive.

This module maps authenticated, scoped *historical evidence* to the existing
``HistoricalEvidenceReader`` protocol.  A result is never an active STM record,
model instruction, current identity fact, or authorization grant.

The host must authenticate the principal before constructing this reader and
provide the archive with a real authorization callback.  Passing a self-claimed
string identifier or an allow-all callback is not an authentication mechanism.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import quote

from .archive import ArchiveScope
from .history import HistoricalEvidence, HISTORICAL_ONLY
from .models import SessionKey

if TYPE_CHECKING:
    from .archive import ConversationArchive


class ArchiveHistoryReader:
    """A deliberately read-only adapter, bound to an external host principal.

    Searches all archived conversations *within* the current tenant/owner/agent
    scope, but never broadens that scope from the active session's IDs.  The
    archive checks host authorization again for every search operation.
    """

    def __init__(self, archive: ConversationArchive, principal: object) -> None:
        if archive is None or principal is None:
            raise ValueError("archive and authenticated principal are required")
        self._archive = archive
        self._principal = principal

    def search(
        self,
        query: str,
        *,
        scope: SessionKey,
        authorized_privacy_scopes: frozenset[str],
        limit: int = 8,
    ) -> tuple[HistoricalEvidence, ...]:
        if not isinstance(scope, SessionKey):
            raise PermissionError("an active session scope is required")
        if not isinstance(query, str) or not query.strip() or limit < 1:
            raise ValueError("query must be non-empty and limit must be positive")
        if not isinstance(authorized_privacy_scopes, frozenset) or not authorized_privacy_scopes:
            raise PermissionError("explicit historical privacy authorization is required")

        archive_scope = ArchiveScope(scope.tenant_id, scope.owner_id, scope.agent_id)
        hits = tuple(self._archive.search(
            self._principal,
            archive_scope,
            query,
            privacy_scopes=authorized_privacy_scopes,
            limit=limit,
        ))
        if len(hits) > limit:
            raise ValueError("archive returned more than the authorized result limit")

        retrieved_at = datetime.now(timezone.utc)
        rows: list[HistoricalEvidence] = []
        for hit in hits:
            turn = hit.turn
            if turn.privacy not in authorized_privacy_scopes:
                raise PermissionError("archive returned evidence outside the privacy grant")
            if not turn.turn_id or not turn.conversation_id or not turn.source:
                raise ValueError("archive evidence is missing source provenance")
            locator = "stm-conversation://" + "/".join(
                quote(segment, safe="")
                for segment in (
                    archive_scope.tenant_id,
                    archive_scope.owner_id,
                    archive_scope.agent_id,
                    turn.conversation_id,
                    turn.turn_id,
                )
            )
            rows.append(HistoricalEvidence(
                memory_id=turn.turn_id,
                excerpt=turn.content,
                source_ids=(turn.turn_id, turn.source),
                privacy_scope=turn.privacy,
                provenance_ceiling="source-attributed historical conversation evidence only",
                currentness_rule="historical as-of event time; verify corrections/current claims",
                event_time=turn.event_time,
                recorded_at=turn.recorded_at,
                ledger_path=locator,
                retrieved_at=retrieved_at,
                result_semantics=HISTORICAL_ONLY,
            ))
        return tuple(rows)


__all__ = ["ArchiveHistoryReader"]
