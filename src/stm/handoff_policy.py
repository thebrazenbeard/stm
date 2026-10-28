"""Thirty-day *review eligibility*, separate from source expiry and DMS export.

This module does not move, copy, or delete conversational content.  A review
ticket is neither long-term-storage consent nor a transfer credential.  The
embedding host must additionally authorize the destination's retention,
deletion/correction propagation, and actual export at the moment of transfer.

The optional in-process queue is deliberately non-durable and content-free.
Its host callbacks must read the *live* authorized source record, including
its current version; archive IDs or caller-supplied scope strings alone cannot
authenticate a principal or prove source currentness.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hmac
import secrets
from threading import RLock
from typing import Callable

from .archive import ArchiveScope, ArchiveTurn
from .retention import MAX_RETENTION


DEFAULT_REVIEW_AGE = timedelta(days=30)
_ALLOWED_ROLES = frozenset({"user", "assistant", "tool"})


def _utc_aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("handoff timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source timestamp is missing")
    try:
        return _utc_aware(datetime.fromisoformat(value))
    except (TypeError, ValueError) as error:
        raise ValueError("source timestamp is not an aware ISO datetime") from error


def _fingerprint(turn: ArchiveTurn, secret: bytes) -> str:
    """Process-private version check, not truth or authorization evidence."""
    parts = (
        turn.turn_id, turn.conversation_id, turn.role, turn.content,
        turn.source, turn.privacy, turn.event_time, turn.recorded_at,
        turn.supersedes_id or "", turn.expires_at or "",
    )
    digest = hmac.new(secret, digestmod="sha256")
    for part in parts:
        binary = part.encode("utf-8")
        digest.update(len(binary).to_bytes(8, "big"))
        digest.update(binary)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class HandoffEligibility:
    """Policy decision for review only, never authority for export."""

    ready_for_review: bool
    reason: str
    eligible_at: datetime | None
    source_expires_at: datetime | None

    @property
    def eligible(self) -> bool:
        """Compatibility alias: review-eligible, NOT export-authorized."""
        return self.ready_for_review


@dataclass(frozen=True, slots=True)
class HandoffPolicy:
    review_age: timedelta = DEFAULT_REVIEW_AGE
    privacy_labels: frozenset[str] = frozenset({"private"})

    def __post_init__(self) -> None:
        if not isinstance(self.review_age, timedelta) or not (
            timedelta(0) < self.review_age <= MAX_RETENTION
        ):
            raise ValueError("review age must be positive and no longer than 90 days")
        if (
            not isinstance(self.privacy_labels, frozenset)
            or not self.privacy_labels
            or any(not isinstance(label, str) or not label.strip()
                   for label in self.privacy_labels)
        ):
            raise ValueError("explicit, nonempty handoff privacy labels required")

    def evaluate(
        self,
        turn: ArchiveTurn,
        *,
        now: datetime,
        current_consent: bool,
        current_authority: bool,
    ) -> HandoffEligibility:
        """Determine when an *authorized*, still-live turn is ready for review.

        The two booleans MUST come from fresh trusted host checks, never user
        input.  They do not represent destination export permission.  Neither
        `ArchiveTurn` nor this decision encodes whether the turn is active;
        callers MUST resolve/compare the currently active source version.
        Host time may move forward relative to wall clock, not backward.
        """
        if not isinstance(turn, ArchiveTurn):
            raise TypeError("source must be an ArchiveTurn")
        moment = max(_utc_aware(now), datetime.now(timezone.utc))
        if not isinstance(current_consent, bool) or not isinstance(current_authority, bool):
            raise TypeError("consent and authority decisions must be explicit bools")
        if turn.privacy not in self.privacy_labels:
            return HandoffEligibility(False, "privacy_not_allowed", None, None)
        if turn.role not in _ALLOWED_ROLES or not all(
            isinstance(value, str) and value.strip()
            for value in (turn.turn_id, turn.conversation_id, turn.source,
                          turn.recorded_at, turn.event_time)
        ):
            return HandoffEligibility(False, "invalid_provenance", None, None)
        if (len(turn.turn_id.encode("utf-8")) > 256
                or len(turn.conversation_id.encode("utf-8")) > 512
                or len(turn.source.encode("utf-8")) > 2048
                or len(turn.privacy.encode("utf-8")) > 128):
            return HandoffEligibility(False, "oversized_provenance", None, None)
        try:
            recorded = _parse_utc(turn.recorded_at)
            _parse_utc(turn.event_time)
        except ValueError:
            return HandoffEligibility(False, "invalid_provenance", None, None)
        # Event time may be old imported history.  Eligibility is measured
        # from actual source admission, not self-reported event age.
        eligible_at = recorded + self.review_age
        if turn.expires_at is None:
            return HandoffEligibility(False, "source_has_no_retention_policy", eligible_at, None)
        try:
            expires = _parse_utc(turn.expires_at)
        except ValueError:
            return HandoffEligibility(False, "invalid_source_expiry", eligible_at, None)
        if expires <= recorded or expires - recorded > MAX_RETENTION:
            return HandoffEligibility(False, "invalid_source_retention", eligible_at, expires)
        if moment >= expires:
            return HandoffEligibility(False, "source_expired", eligible_at, expires)
        if expires <= eligible_at:
            return HandoffEligibility(False, "review_after_or_at_source_expiry", eligible_at, expires)
        if recorded > moment:
            return HandoffEligibility(False, "future_recorded_at", eligible_at, expires)
        if current_consent is not True:
            return HandoffEligibility(False, "review_consent_required", eligible_at, expires)
        if current_authority is not True:
            return HandoffEligibility(False, "review_authority_required", eligible_at, expires)
        if moment < eligible_at:
            return HandoffEligibility(False, "not_yet_due", eligible_at, expires)
        return HandoffEligibility(True, "ready_for_review_only", eligible_at, expires)


@dataclass(frozen=True, slots=True)
class HandoffReviewTicket:
    """Minimal metadata; a ticket never contains conversational text."""

    scope: ArchiveScope
    turn_id: str
    privacy: str
    recorded_at: str
    supersedes_id: str | None
    eligible_at: datetime
    source_expires_at: datetime
    version_fingerprint: str
    state: str = "pending"


class HandoffReviewQueue:
    """Optional, non-durable, scoped queue with live-source revalidation.

    The host provides `authorize(principal, action, scope)`,
    `consent_check(principal, scope, privacy)` and
    `resolve_live_turn(principal, scope, turn_id)` callbacks from authenticated
    runtime authority.  The resolver must return ONLY a currently active,
    in-scope source turn, never an inactive ancestor.  This queue stores no
    content and makes no outbound calls.
    """

    def __init__(
        self,
        policy: HandoffPolicy,
        *,
        authorize: Callable[[object, str, ArchiveScope], bool],
        consent_check: Callable[[object, ArchiveScope, str], bool],
        resolve_live_turn: Callable[[object, ArchiveScope, str], ArchiveTurn | None],
        max_tickets: int = 10_000,
    ) -> None:
        if not isinstance(policy, HandoffPolicy):
            raise TypeError("explicit handoff review policy required")
        if not all(callable(callback) for callback in
                   (authorize, consent_check, resolve_live_turn)):
            raise TypeError("trusted authorization, consent, and live-source callbacks required")
        if isinstance(max_tickets, bool) or not isinstance(max_tickets, int) or not 1 <= max_tickets <= 100_000:
            raise ValueError("review ticket cap must be between 1 and 100000")
        self._policy = policy
        self._authorize = authorize
        self._consent_check = consent_check
        self._resolve_live_turn = resolve_live_turn
        self._secret = secrets.token_bytes(32)
        self._max_tickets = max_tickets
        self._items: dict[tuple[ArchiveScope, str], HandoffReviewTicket] = {}
        self._lock = RLock()

    def _check_auth(self, principal: object, action: str, scope: ArchiveScope) -> None:
        if principal is None or not isinstance(scope, ArchiveScope):
            raise PermissionError("verified principal and scope required")
        if any(len(part.encode("utf-8")) > 256 for part in
               (scope.tenant_id, scope.owner_id, scope.agent_id)):
            raise PermissionError("handoff scope identifier exceeds resource bound")
        try:
            granted = self._authorize(principal, action, scope)
        except Exception as error:
            raise PermissionError("handoff authorization unavailable") from error
        if granted is not True:
            raise PermissionError("handoff authorization denied")

    def _consented(self, principal: object, scope: ArchiveScope, privacy: str) -> bool:
        try:
            return self._consent_check(principal, scope, privacy) is True
        except Exception:
            return False

    def _live(self, principal: object, scope: ArchiveScope, turn_id: str) -> ArchiveTurn | None:
        try:
            result = self._resolve_live_turn(principal, scope, turn_id)
        except Exception as error:
            raise PermissionError("live source verification unavailable") from error
        if result is not None and not isinstance(result, ArchiveTurn):
            raise PermissionError("live source verification returned invalid type")
        return result

    def offer(
        self, principal: object, scope: ArchiveScope, turn: ArchiveTurn, *, now: datetime
    ) -> HandoffReviewTicket | HandoffEligibility:
        """Queue only live, due, consented records; idempotent per source ID."""
        self._check_auth(principal, "handoff_review_offer", scope)
        if not isinstance(turn, ArchiveTurn):
            raise TypeError("source turn required")
        live = self._live(principal, scope, turn.turn_id)
        if live is None or _fingerprint(live, self._secret) != _fingerprint(turn, self._secret):
            return HandoffEligibility(False, "source_not_current", None, None)
        consented = self._consented(principal, scope, turn.privacy)
        self._check_auth(principal, f"handoff_review_privacy:{turn.privacy}", scope)
        eligibility = self._policy.evaluate(
            turn, now=now, current_consent=consented, current_authority=True,
        )
        if not eligibility.ready_for_review:
            return eligibility
        assert eligibility.eligible_at is not None
        assert eligibility.source_expires_at is not None
        key = (scope, turn.turn_id)
        ticket = HandoffReviewTicket(
            scope, turn.turn_id, turn.privacy, turn.recorded_at,
            turn.supersedes_id, eligibility.eligible_at,
            eligibility.source_expires_at, _fingerprint(turn, self._secret),
        )
        with self._lock:
            existing = self._items.get(key)
            if existing is not None:
                if existing.version_fingerprint != ticket.version_fingerprint:
                    self._items[key] = replace(existing, state="invalidated")
                    raise RuntimeError("source version changed for previously reviewed ID")
                if existing.state != "pending":
                    return existing  # terminal state cannot be silently reopened
                return existing
            if len(self._items) >= self._max_tickets:
                raise MemoryError("bounded handoff review ticket capacity reached")
            # A correction supersedes every queued ancestor (and descendant
            # if an external host later reports deletion of the root).
            if turn.supersedes_id:
                self._invalidate_chain(scope, turn.supersedes_id)
            self._items[key] = ticket
            return ticket

    def _invalidate_chain(self, scope: ArchiveScope, turn_id: str) -> None:
        targets = {turn_id}
        while True:
            additions = {
                item.turn_id for (item_scope, _), item in self._items.items()
                if item_scope == scope and item.supersedes_id in targets
            }
            if additions <= targets:
                break
            targets |= additions
        for key, item in tuple(self._items.items()):
            if key[0] == scope and item.turn_id in targets:
                self._items[key] = replace(item, state="invalidated")

    def invalidate(self, principal: object, scope: ArchiveScope, turn_id: str) -> None:
        """Host correction, deletion or withdrawal notification; no content read."""
        self._check_auth(principal, "handoff_review_invalidate", scope)
        if not isinstance(turn_id, str) or not turn_id.strip():
            raise ValueError("turn ID required")
        with self._lock:
            self._invalidate_chain(scope, turn_id)

    def pending(
        self, principal: object, scope: ArchiveScope, *, now: datetime
    ) -> tuple[HandoffReviewTicket, ...]:
        """Return only live, currently authorized, still-unexpired tickets."""
        self._check_auth(principal, "handoff_review_list", scope)
        moment = max(_utc_aware(now), datetime.now(timezone.utc))
        with self._lock:
            candidates = tuple(item for (item_scope, _), item in self._items.items()
                               if item_scope == scope and item.state == "pending")
        permitted: list[HandoffReviewTicket] = []
        for ticket in candidates:
            if moment >= ticket.source_expires_at:
                self.invalidate(principal, scope, ticket.turn_id)
                continue
            if not self._consented(principal, scope, ticket.privacy):
                self.invalidate(principal, scope, ticket.turn_id)
                continue
            try:
                self._check_auth(principal,
                                 f"handoff_review_privacy:{ticket.privacy}", scope)
                live = self._live(principal, scope, ticket.turn_id)
            except PermissionError:
                # Fail-closed on revoked label authority or lookup failure.
                continue
            if live is None or _fingerprint(live, self._secret) != ticket.version_fingerprint:
                self.invalidate(principal, scope, ticket.turn_id)
                continue
            permitted.append(ticket)
        return tuple(sorted(permitted, key=lambda item: (
            item.eligible_at, item.turn_id,
        )))


__all__ = [
    "DEFAULT_REVIEW_AGE", "HandoffEligibility", "HandoffPolicy",
    "HandoffReviewTicket", "HandoffReviewQueue",
]
