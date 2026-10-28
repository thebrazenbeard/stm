"""Fail-closed, host-authenticated bridge for Vera-local conversation events.

The library cannot authenticate a network request, browser session, or a
``conversation_id``. A trusted, separately implemented broker must resolve an
opaque request into a short-lived :class:`VerifiedConversation` and authorize
each verb. In particular, an unauthenticated localhost HTTP endpoint is NOT a
valid broker.

Working records and archived turns are deliberately separate operations: no
implicit persistence, cross-chat lookup, model instruction, identity change,
or long-term-memory promotion occurs on ingestion.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from .archive import ArchiveScope, ArchiveTurn, ConversationArchive
from .archive_adapter import ArchiveHistoryReader
from .core import MemorySession, STM
from .history import HistoricalEvidence
from .models import MemoryRecord, PromptContext, SessionKey
from .retention import MAX_RETENTION


ALLOWED_ROLES = frozenset({"user", "assistant", "tool"})
ALLOWED_LABELS = frozenset({"private", "session", "shared"})


@dataclass(frozen=True, slots=True)
class VerifiedConversation:
    """A broker-issued, expiring scope, not a caller-constructed credential.

    A return value is trusted **only** when it came directly from ``resolve``.
    The broker must independently authenticate the originating request and
    establish the account, agent, conversation, consent and privacy grants.
    """

    principal: object
    session: SessionKey
    conversation_id: str
    privacy_scopes: frozenset[str]
    expires_at: datetime
    max_working_ttl_seconds: float
    archive_consent: bool = False
    archive_retention_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.principal is None or not isinstance(self.session, SessionKey):
            raise ValueError("broker-issued principal and scoped session required")
        if not isinstance(self.conversation_id, str) or not self.conversation_id.strip():
            raise ValueError("broker conversation ID required")
        if (not isinstance(self.privacy_scopes, frozenset)
                or not self.privacy_scopes
                or not self.privacy_scopes <= ALLOWED_LABELS):
            raise ValueError("broker must provide explicit supported privacy labels")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("broker authorization must expire at an aware timestamp")
        if not 0 < self.max_working_ttl_seconds < float("inf"):
            raise ValueError("bounded positive working retention required")
        if self.archive_retention_seconds is not None and not (
            0 < self.archive_retention_seconds <= MAX_RETENTION.total_seconds()
        ):
            raise ValueError("archival retention must be finite and within library cap")


class VerifiedRetentionGate(Protocol):
    """Host retention controller; must enforce expiry independently of reads.

    True is a host assertion, NOT evidence the STM library has operated a
    background sweeper. Deployments must test their concrete implementation
    against live storage, WAL, backups and restart conditions.
    """

    def verify(self, grant: VerifiedConversation, archive: ConversationArchive) -> bool: ...


class VeraConversationBridge:
    """Composed STM port for a trusted Vera broker; never an HTTP auth layer.

    ``resolve(opaque_request)`` must authenticate freshly on every operation.
    ``authorize(grant, action, privacy)`` must return literal ``True`` after
    verifying the caller's scoped capability. All other results fail closed.

    Archive writes are disabled by default. If enabled, they require explicit
    consent, a finite retention duration and a host-supplied *verified* expiry
    controller. Whether that controller actually sweeps at rest must be
    independently audited; a trivial allow-all callback is not verification.
    """

    def __init__(
        self,
        stm: STM,
        *,
        resolve: Callable[[object], VerifiedConversation],
        authorize: Callable[[VerifiedConversation, str, str], bool],
        archive: ConversationArchive | None = None,
        retention_gate: VerifiedRetentionGate | None = None,
        history_gate: Callable[[VerifiedConversation, ConversationArchive,
                                frozenset[str]], bool] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(stm, STM) or not callable(resolve) or not callable(authorize):
            raise TypeError("STM and trusted broker callbacks are required")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if history_gate is not None and not callable(history_gate):
            raise TypeError("history_gate must be a trusted callable")
        self._stm = stm
        self._archive = archive
        self._resolve = resolve
        self._authorize = authorize
        self._retention_gate = retention_gate
        self._history_gate = history_gate
        self._clock = clock

    def _grant(self, request: object, *, action: str, privacy: str) -> VerifiedConversation:
        if request is None:
            raise PermissionError("authenticated broker request required")
        try:
            grant = self._resolve(request)
        except Exception as error:
            raise PermissionError("host authentication failed") from error
        if not isinstance(grant, VerifiedConversation):
            raise PermissionError("trusted host did not issue a verified conversation")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("host clock must be timezone-aware")
        if now >= grant.expires_at:
            raise PermissionError("conversation capability expired")
        self._require_permission(grant, action, privacy)
        return grant

    def _require_permission(self, grant: VerifiedConversation,
                            action: str, privacy: str) -> None:
        if privacy not in grant.privacy_scopes:
            raise PermissionError("privacy label outside current broker grant")
        try:
            decision = self._authorize(grant, action, privacy)
        except Exception as error:
            raise PermissionError("broker operation authorization failed") from error
        if decision is not True:
            raise PermissionError("broker denied conversation operation")

    @staticmethod
    def _role(role: str) -> str:
        if role not in ALLOWED_ROLES:
            raise PermissionError("untrusted conversation input cannot assert a system role")
        return role

    def _session(self, grant: VerifiedConversation) -> MemorySession:
        key = grant.session
        return self._stm.open_session(
            tenant_id=key.tenant_id, owner_id=key.owner_id,
            agent_id=key.agent_id, session_id=key.session_id,
        )

    def remember(
        self,
        request: object,
        content: str,
        *,
        role: str = "user",
        privacy: str = "private",
        ttl_seconds: float | None = None,
    ) -> MemoryRecord:
        """Admit a bounded working observation; **never** archive implicitly."""
        self._role(role)
        grant = self._grant(request, action=f"working_write:{role}", privacy=privacy)
        ttl = grant.max_working_ttl_seconds if ttl_seconds is None else ttl_seconds
        if not isinstance(ttl, (int, float)) or not 0 < ttl <= grant.max_working_ttl_seconds:
            raise PermissionError("working TTL exceeds broker retention policy")
        return self._session(grant).append(
            content, role=role,
            source=f"vera-local-conversation:{grant.conversation_id}",
            privacy=privacy, ttl_seconds=ttl,
        )

    def working_context(
        self,
        request: object,
        query: str,
        *,
        privacy: str = "private",
        token_budget: int,
    ) -> PromptContext:
        grant = self._grant(request, action="working_context", privacy=privacy)
        # Filter BEFORE ranking and packing, including pinned material. A
        # private-only host grant must never require shared/session authority
        # or leak those labels into the packed prompt.
        return self._session(grant).assemble_context(
            query, token_budget=token_budget,
            authorized_privacy_scopes=frozenset({privacy}),
        )

    def archive_turn(
        self,
        request: object,
        content: str,
        *,
        role: str = "user",
        privacy: str = "private",
    ) -> ArchiveTurn:
        """Explicit persistence, blocked unless actual host expiry is certified."""
        self._role(role)
        grant = self._grant(request, action=f"archive_write:{role}", privacy=privacy)
        if self._archive is None or self._retention_gate is None:
            raise PermissionError("archive retention enforcement is unavailable")
        if not grant.archive_consent or grant.archive_retention_seconds is None:
            raise PermissionError("explicit archival consent and retention deadline required")
        try:
            certified = self._retention_gate.verify(grant, self._archive)
        except Exception as error:
            raise PermissionError("archive retention verification failed") from error
        if certified is not True:
            raise PermissionError("archive retention controller did not certify enforcement")
        expiry = self._clock() + timedelta(seconds=grant.archive_retention_seconds)
        if expiry <= self._clock():
            raise PermissionError("archive retention deadline must be in the future")
        return self._archive.append_turn(
            grant.principal,
            ArchiveScope(grant.session.tenant_id, grant.session.owner_id,
                         grant.session.agent_id),
            conversation_id=grant.conversation_id,
            role=role, content=content,
            source=f"vera-local-conversation:{grant.conversation_id}",
            privacy=privacy, expires_at=expiry,
        )

    def recall_history(
        self,
        request: object,
        query: str,
        *,
        privacy_scopes: frozenset[str],
        limit: int = 8,
    ) -> tuple[HistoricalEvidence, ...]:
        """Return source-attributed past evidence, never active STM records."""
        if self._archive is None:
            raise PermissionError("no historical archive is configured")
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes:
            raise PermissionError("explicit historical privacy labels required")
        grant = self._grant(request, action="archive_read", privacy=sorted(privacy_scopes)[0])
        if not grant.archive_consent:
            raise PermissionError("current archival read consent required")
        if not privacy_scopes <= grant.privacy_scopes:
            raise PermissionError("historical read widens privacy grant")
        for label in sorted(privacy_scopes):
            self._require_permission(grant, "archive_read", label)
        if self._history_gate is not None:
            try:
                accepted = self._history_gate(grant, self._archive, privacy_scopes)
            except Exception as error:
                raise PermissionError("current archive read consent verification failed") from error
            if accepted is not True:
                raise PermissionError("current archive read consent denied")
        return ArchiveHistoryReader(
            self._archive, grant.principal, require_expiration=True,
        ).search(
            query, scope=grant.session,
            authorized_privacy_scopes=privacy_scopes, limit=limit,
        )

    def delete_archived(self, request: object, turn_id: str,
                        *, privacy: str = "private") -> bool:
        if self._archive is None:
            raise PermissionError("no historical archive is configured")
        grant = self._grant(request, action="archive_delete", privacy=privacy)
        # The archive delete API takes an ID without exposing its label first.
        # Authorize the complete label set before that lookup, so requesting a
        # different label cannot delete a more sensitive record by its ID.
        if grant.privacy_scopes != ALLOWED_LABELS:
            raise PermissionError("archive deletion requires all-label broker authority")
        for label in sorted(ALLOWED_LABELS):
            self._require_permission(grant, "archive_delete", label)
        return self._archive.delete(
            grant.principal,
            ArchiveScope(grant.session.tenant_id, grant.session.owner_id,
                         grant.session.agent_id), turn_id,
        )


__all__ = ["VerifiedConversation", "VerifiedRetentionGate", "VeraConversationBridge"]
