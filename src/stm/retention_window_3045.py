"""Opt-in Vera day-30 review / day-45 local conversation expiry binding.

Patrick selected this lifecycle on 2026-10-28. It is a source-stage policy,
not an installed Vera scheduler, consent grant or DeepMemoryStorage writer.
The local deadline does not pause while a review or external send is pending.

The only persistence enabled by this module is through the existing
consent-gated ``RetainedConversationArchive``. The embedding host must run
its supervised expiry sweeps, protect local artifacts/backups, and separately
authenticate any long-term export target and destination-specific consent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from .archive import ArchiveScope, ArchiveTurn, ConversationArchive
from .core import STM
from .handoff_policy import HandoffEligibility, HandoffPolicy
from .retention import ConsentChecker, RetainedConversationArchive, RetentionPolicy
from .vera_bridge import VerifiedConversation, VeraConversationBridge


REVIEW_AFTER = timedelta(days=30)
LOCAL_EXPIRE_AFTER = timedelta(days=45)
REVIEW_PERIOD = LOCAL_EXPIRE_AFTER - REVIEW_AFTER
MAX_CLOCK_SKEW = timedelta(seconds=1)


def _wall_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ThirtyFortyFiveReviewPolicy(HandoffPolicy):
    """Handoff review with a strict day-45 upper bound on each source turn.

    Callers can use this policy in ``HandoffReviewQueue`` and
    ``DeepMemoryHandoff``. A record whose source deadline exceeds day 45 is
    denied even if a generic 30-day review policy would have accepted it.
    ``recorded_at`` is the source's actual archive admission timestamp, not
    a caller-controlled historical event time.
    """

    def __post_init__(self) -> None:
        HandoffPolicy.__post_init__(self)
        if self.review_age != REVIEW_AFTER:
            raise ValueError("this host-approved review window starts at day 30")

    def evaluate(
        self, turn: ArchiveTurn, *, now: datetime,
        current_consent: bool, current_authority: bool,
    ) -> HandoffEligibility:
        result = HandoffPolicy.evaluate(
            self, turn, now=now, current_consent=current_consent,
            current_authority=current_authority,
        )
        if result.eligible_at is not None and result.source_expires_at is not None:
            admitted_at = result.eligible_at - REVIEW_AFTER
            if result.source_expires_at > admitted_at + LOCAL_EXPIRE_AFTER:
                return HandoffEligibility(
                    False, "source_exceeds_day_45_limit", result.eligible_at,
                    result.source_expires_at,
                )
        return result


class _BoundedRetainedArchive(RetainedConversationArchive):
    """Marker for source-store wrappers made by this strict policy factory."""


class ThirtyFortyFiveRetentionGate:
    """Bridge gate: exact archive identity, 45-day grant, host enforcement.

    ``verify_enforcement`` MUST be an independently trusted host check of
    its scheduler, registry and privacy policy. No source-only callback can
    prove that a daemon is running or historical files are erased.
    """

    def __init__(
        self, window: "ThirtyFortyFiveWindow", *,
        archive: ConversationArchive, retained: RetainedConversationArchive,
        verify_enforcement: Callable[[VerifiedConversation, ConversationArchive], bool],
    ) -> None:
        if not callable(verify_enforcement):
            raise PermissionError("trusted enforcement verification required")
        if (not isinstance(retained, _BoundedRetainedArchive)
                or retained._archive is not archive
                or retained._policy != window.retention_policy):
            raise PermissionError("day-45 bridge must use the same bounded archive")
        self._window = window
        self._archive = archive
        self._retained = retained
        self._verify_enforcement = verify_enforcement

    def _verify_current(
        self, grant: VerifiedConversation, archive: ConversationArchive,
        operation: str, privacy_scopes: frozenset[str],
    ) -> bool:
        if archive is not self._archive:
            return False
        try:
            # Guard against a host reconfiguring the wrapper after bridge
            # construction; the raw bridge write must never outlive its
            # consent/expiry policy attachment.
            if (not isinstance(self._retained, _BoundedRetainedArchive)
                    or self._retained._archive is not archive
                    or self._retained._policy != self._window.retention_policy):
                return False
            self._window.validate_bridge_grant(grant)
            if not privacy_scopes or not privacy_scopes <= grant.privacy_scopes:
                return False
            # The bridge writes to the raw archive; without a fresh check here,
            # revoking consent in the retained wrapper would not prevent a
            # previously credentialed caller from persisting another turn.
            scope = ArchiveScope(
                grant.session.tenant_id, grant.session.owner_id,
                grant.session.agent_id,
            )
            for privacy in sorted(privacy_scopes):
                self._retained._consent(
                    grant.principal, scope, operation, privacy,
                )
            return self._verify_enforcement(grant, archive) is True
        except Exception:
            return False

    def verify(self, grant: VerifiedConversation, archive: ConversationArchive) -> bool:
        return self._verify_current(
            grant, archive, "archive_write", grant.privacy_scopes,
        )

    def verify_read(
        self, grant: VerifiedConversation, archive: ConversationArchive,
        privacy_scopes: frozenset[str],
    ) -> bool:
        """Require live retained consent for historical reads as well as writes."""
        return self._verify_current(grant, archive, "archive_read", privacy_scopes)


@dataclass(frozen=True, slots=True)
class ThirtyFortyFiveWindow:
    """Single explicit configuration source for two otherwise separate planes.

    Host uses ``retained_archive(...)`` for *new* records; it does not migrate
    old rows or override their deadlines. It uses ``review_policy`` for
    content-free review and, with additional independent export authority,
    the optional historical sink. No automatic transfer or deletion on review.
    """

    privacy_labels: frozenset[str] = frozenset({"private"})

    def __post_init__(self) -> None:
        RetentionPolicy(maximum_age=LOCAL_EXPIRE_AFTER,
                        privacy_labels=self.privacy_labels)
        ThirtyFortyFiveReviewPolicy(review_age=REVIEW_AFTER,
                                     privacy_labels=self.privacy_labels)

    @property
    def retention_policy(self) -> RetentionPolicy:
        return RetentionPolicy(maximum_age=LOCAL_EXPIRE_AFTER,
                               privacy_labels=self.privacy_labels)

    @property
    def review_policy(self) -> ThirtyFortyFiveReviewPolicy:
        return ThirtyFortyFiveReviewPolicy(
            review_age=REVIEW_AFTER, privacy_labels=self.privacy_labels,
        )

    def retained_archive(
        self, archive: ConversationArchive, *, consent_check: ConsentChecker,
        clock: Callable[[], datetime] | None = None,
    ) -> RetainedConversationArchive:
        """Attach the actual 45-day retention ceiling to a consented archive.

        Call the returned wrapper's ``sweep`` under separate scoped expiry
        authority at startup/periodically; this module does not launch a job.
        Shorter requested turn lifetimes remain permitted, and such turns may
        expire before day 30 without becoming review-eligible.
        """
        return _BoundedRetainedArchive(
            archive, policy=self.retention_policy,
            consent_check=consent_check, clock=self.bounded_clock(clock),
        )

    def bounded_clock(
        self, clock: Callable[[], datetime] | None = None,
    ) -> Callable[[], datetime]:
        """Use a wall-bounded clock for retention-admitting host operations."""
        # ConversationArchive records its own *actual* wall time, independently
        # of RetainedConversationArchive's clock. A host clock five days ahead
        # would otherwise produce a 50-day deadline for a 45-day policy. Only
        # permit injection close to observed wall time, clamp future drift,
        # and fail closed rather than storing an overlong source record.
        if clock is not None and not callable(clock):
            raise TypeError("trusted UTC clock must be callable")

        def bounded_clock() -> datetime:
            wall = _wall_utc()
            if clock is None:
                return wall
            candidate = clock()
            if (not isinstance(candidate, datetime)
                    or candidate.tzinfo is None
                    or candidate.utcoffset() is None):
                raise PermissionError("trusted clock must be timezone aware")
            candidate = candidate.astimezone(timezone.utc)
            if abs(candidate - wall) > MAX_CLOCK_SKEW:
                raise PermissionError("clock skew exceeds one-second admission bound")
            return min(candidate, wall)

        return bounded_clock

    def vera_bridge(
        self, stm: STM, *, archive: ConversationArchive,
        retained: RetainedConversationArchive,
        resolve: Callable[[object], VerifiedConversation],
        authorize: Callable[[VerifiedConversation, str, str], bool],
        verify_enforcement: Callable[[VerifiedConversation, ConversationArchive], bool],
        clock: Callable[[], datetime] | None = None,
    ) -> VeraConversationBridge:
        """Construct a grant/clock-gated bridge, not a local auth server.

        The caller still must actually authenticate request identity, operate
        a scheduler, and prevent direct raw-archive bypass. This factory does
        not connect to VeraOS's unauthenticated loopback HTTP endpoints.
        """
        gate = ThirtyFortyFiveRetentionGate(
            self, archive=archive, retained=retained,
            verify_enforcement=verify_enforcement,
        )
        return VeraConversationBridge(
            stm, resolve=resolve, authorize=authorize,
            archive=archive, retention_gate=gate,
            history_gate=gate.verify_read, clock=self.bounded_clock(clock),
        )

    def validate_bridge_grant(self, grant: VerifiedConversation) -> None:
        """Optional host preflight before enabling a VeraConversationBridge.

        This is a validation method, *not* a hooked enforcement point. The
        host must deny raw/archive writes bypassing the 45-day policy. No
        grant alone authenticates a caller or enables persistence.
        """
        if not isinstance(grant, VerifiedConversation):
            raise PermissionError("trusted verified conversation grant required")
        age = grant.archive_retention_seconds
        if (grant.archive_consent is not True or age is None
                or not 0 < age <= LOCAL_EXPIRE_AFTER.total_seconds()
                or not grant.privacy_scopes <= self.privacy_labels):
            raise PermissionError("bridge grant exceeds consented day-45 archive bound")


__all__ = [
    "REVIEW_AFTER", "LOCAL_EXPIRE_AFTER", "REVIEW_PERIOD", "MAX_CLOCK_SKEW",
    "ThirtyFortyFiveReviewPolicy", "ThirtyFortyFiveRetentionGate",
    "ThirtyFortyFiveWindow",
]
