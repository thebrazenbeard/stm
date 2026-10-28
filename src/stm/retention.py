"""Fail-closed, consent-gated retention policy for conversation evidence.

The trusted host supplies an authenticated principal, archive authorizer,
current consent decision and explicit policy. Expiry must be transactional
inside ConversationArchive, and a host scheduler must call sweep regularly.
Neither SQLite WAL nor backups are guaranteed forensically erased.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from .archive import ArchiveHit, ArchiveScope, ArchiveTurn, ConversationArchive


MAX_RETENTION = timedelta(days=90)  # Library cap, not Vera's chosen policy.
MAX_SWEEP_BATCH = 1000
MAX_READ_RESULTS = 100


class ConsentChecker(Protocol):
    def __call__(
        self, principal: object, scope: ArchiveScope, operation: str, privacy: str
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    maximum_age: timedelta
    privacy_labels: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.maximum_age, timedelta) or not (
            timedelta(0) < self.maximum_age <= MAX_RETENTION
        ):
            raise ValueError("maximum_age must be positive and at most 90 days")
        if not isinstance(self.privacy_labels, frozenset) or not self.privacy_labels or any(
            not isinstance(label, str) or not label.strip()
            for label in self.privacy_labels
        ):
            raise ValueError("privacy_labels must be a nonempty frozenset")


@dataclass(frozen=True, slots=True)
class RetentionAudit:
    """Content-free count summary; no principal or conversation content."""
    candidates: int
    deleted: int
    dry_run: bool
    limit: int


def _aware_utc(moment: datetime) -> datetime:
    if not isinstance(moment, datetime) or moment.tzinfo is None or (
        moment.utcoffset() is None
    ):
        raise ValueError("trusted clock must return a timezone-aware datetime")
    return moment.astimezone(timezone.utc)


class RetainedConversationArchive:
    """Wrapper whose reads, writes and purges enforce an explicit host policy.

    Direct access to the wrapped archive bypasses these checks. Restrict that
    access at the embedding host, and do not treat a scope value as identity.
    """
    def __init__(
        self, archive: ConversationArchive, *, policy: RetentionPolicy,
        consent_check: ConsentChecker,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(policy, RetentionPolicy):
            raise PermissionError("an explicit retention policy is required")
        if not callable(consent_check):
            raise PermissionError("trusted current consent decisions are required")
        if not isinstance(archive, ConversationArchive):
            raise TypeError("a ConversationArchive is required")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._archive = archive
        self._policy = policy
        self._consent_check = consent_check
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        return _aware_utc(self._clock())

    @staticmethod
    def _scope(principal: object, scope: ArchiveScope) -> None:
        if principal is None or not isinstance(scope, ArchiveScope):
            raise PermissionError("authenticated principal and scope required")

    def _consent(
        self, principal: object, scope: ArchiveScope, operation: str, privacy: str
    ) -> None:
        self._scope(principal, scope)
        if privacy not in self._policy.privacy_labels:
            raise PermissionError("privacy label denied by retention policy")
        try:
            decision = self._consent_check(principal, scope, operation, privacy)
        except Exception as error:
            raise PermissionError("trusted consent check failed") from error
        if decision is not True:
            raise PermissionError("explicit current consent required")

    def append_turn(
        self, principal: object, scope: ArchiveScope, *,
        conversation_id: str, role: str, content: str,
        source: str = "conversation", privacy: str = "private",
        requested_age: timedelta | None = None,
        event_time: datetime | None = None,
    ) -> ArchiveTurn:
        self._consent(principal, scope, "archive_write", privacy)
        age = self._policy.maximum_age if requested_age is None else requested_age
        if not isinstance(age, timedelta) or not (
            timedelta(0) < age <= self._policy.maximum_age
        ):
            raise ValueError("requested_age exceeds configured retention cap")
        expires_at = self._now() + age
        return self._archive.append_turn(
            principal, scope, conversation_id=conversation_id, role=role,
            content=content, source=source, privacy=privacy,
            event_time=event_time, expires_at=expires_at,
        )

    def search(
        self, principal: object, scope: ArchiveScope, query: str, *,
        privacy_scopes: frozenset[str], limit: int = 8,
    ) -> tuple[ArchiveHit, ...]:
        self._scope(principal, scope)
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes:
            raise PermissionError("explicit privacy scopes required")
        if isinstance(limit, bool) or not isinstance(limit, int) or not (
            1 <= limit <= MAX_READ_RESULTS
        ):
            raise ValueError("limit must be between 1 and 100")
        for privacy in privacy_scopes:
            self._consent(principal, scope, "archive_read", privacy)
        now = self._now()
        # Scope, policy presence and expiration MUST be filtered in SQL before
        # relevance ranking and its result limit. Filtering a top-N batch in
        # Python can hide relevant live rows behind N expired high-ranked rows.
        hits = self._archive.search(
            principal, scope, query, privacy_scopes=privacy_scopes,
            limit=limit, require_expiration=True, now=now,
        )
        current: list[ArchiveHit] = []
        for hit in hits:
            expiry = hit.turn.expires_at
            if expiry is None:
                # Policy-less historical rows cannot be silently read as if
                # they were consented current-retention records.
                continue
            if _aware_utc(datetime.fromisoformat(expiry)) <= now:
                continue
            current.append(hit)
        return tuple(current)

    def delete(
        self, principal: object, scope: ArchiveScope, turn_id: str
    ) -> bool:
        """Erasure needs archive authorization, but not renewed consent."""
        self._scope(principal, scope)
        return self._archive.delete(principal, scope, turn_id)

    def sweep(
        self, principal: object, scope: ArchiveScope, *,
        privacy_scopes: frozenset[str], limit: int = MAX_SWEEP_BATCH,
        dry_run: bool = False,
    ) -> RetentionAudit:
        """Delete persisted expired rows in scope, or inspect without changes.

        Permission to delete is checked by the archive itself. Consent is not
        required for expiry cleanup, including after consent withdrawal.
        """
        self._scope(principal, scope)
        if (
            not isinstance(privacy_scopes, frozenset)
            or not privacy_scopes
            or not privacy_scopes.issubset(self._policy.privacy_labels)
        ):
            raise PermissionError("sweep labels must be policy-authorized")
        if isinstance(limit, bool) or not isinstance(limit, int) or not (
            1 <= limit <= MAX_SWEEP_BATCH
        ):
            raise ValueError("limit must be between 1 and 1000")
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be boolean")
        count = self._archive.expire_due(
            principal, scope, now=self._now(), privacy_scopes=privacy_scopes,
            limit=limit, dry_run=dry_run,
        )
        if isinstance(count, bool) or not isinstance(count, int) or not (
            0 <= count <= limit
        ):
            raise RuntimeError("archive returned invalid expiry count")
        return RetentionAudit(
            candidates=count, deleted=0 if dry_run else count,
            dry_run=dry_run, limit=limit,
        )


__all__ = [
    "MAX_RETENTION", "RetentionPolicy", "RetentionAudit",
    "RetainedConversationArchive",
]
