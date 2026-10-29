"""Fail-closed policy boundary between an account export and local memory.

The account export is immutable historical source material.  This module only
decides whether a *metadata-only* candidate may enter a separate human/owner
review queue.  It neither reads chat bodies nor writes memories, weights,
identity, permissions, or model state.

An authenticating caller must establish ``OwnerContext`` externally; a caller
must never treat a string found in an exported conversation as authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


RECALL_SCOPE = "memory.historical.recall.review"
STM_REVIEW_AFTER = timedelta(days=30)
STM_EXPIRE_AFTER = timedelta(days=45)


class Privacy(str, Enum):
    UNKNOWN = "unknown"
    PRIVATE_ACCOUNT = "private_account"
    THIRD_PARTY = "third_party"
    PUBLIC_APPROVED = "public_approved"


class ThirdPartyScreen(str, Enum):
    UNKNOWN = "unknown"
    PRESENT = "present"
    SCREENED_ABSENT = "screened_absent"


class CandidateDisposition(str, Enum):
    DENIED = "denied"
    QUARANTINED = "quarantined"
    REVIEW_ELIGIBLE = "review_eligible"


class RetentionState(str, Enum):
    SOURCE_POLICY_SEPARATE = "source_policy_separate"
    ACTIVE = "active"
    REVIEW_ELIGIBLE = "review_eligible"
    EXPIRED = "expired"


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("an aware datetime is required")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, repr=False)
class HistoricalCandidate:
    """Only opaque references; no free-text or reconstructed message body."""

    owner_key: str
    export_ref: str
    conversation_ref: str
    message_ref: str
    author_role: str
    privacy: Privacy = Privacy.UNKNOWN
    third_party_screen: ThirdPartyScreen = ThirdPartyScreen.UNKNOWN
    event_time: datetime | None = None
    event_time_quality: str = "unknown"
    corrects_message_ref: str | None = None
    superseded_by_ref: str | None = None

    def __post_init__(self) -> None:
        if any(not isinstance(v, str) or not v or len(v) > 256 for v in (
            self.owner_key, self.export_ref, self.conversation_ref, self.message_ref
        )):
            raise ValueError("nonempty bounded opaque references required")
        if not isinstance(self.privacy, Privacy) or not isinstance(self.third_party_screen, ThirdPartyScreen):
            raise ValueError("recognized privacy and screening classifications required")
        if self.event_time is not None:
            _utc(self.event_time)
        if self.event_time_quality not in {"unknown", "unverified", "source_recorded", "independently_verified"}:
            raise ValueError("unrecognized time-quality label")
        for v in (self.corrects_message_ref, self.superseded_by_ref):
            if v is not None and (not isinstance(v, str) or not v or len(v) > 256):
                raise ValueError("invalid correction reference")


@dataclass(frozen=True, repr=False)
class OwnerContext:
    """Proof metadata supplied by an external authenticated owner boundary.

    ``principal_verified`` may be true only after an independent identity
    check; this module cannot authenticate callers or devices by itself.
    """

    owner_key: str | None = None
    principal_verified: bool = False
    opted_in: bool = False
    consent_scope: str | None = None
    consent_valid_at: datetime | None = None


@dataclass(frozen=True)
class CandidateDecision:
    disposition: CandidateDisposition
    reason: str
    # Deliberately immutable, never inferred from historical source material.
    may_promote_to_present_fact: bool = False
    may_change_identity: bool = False
    may_change_weights: bool = False
    may_grant_authority: bool = False
    may_send_to_model: bool = False


def classify_candidate(candidate: HistoricalCandidate, context: OwnerContext,
                       *, now: datetime) -> CandidateDecision:
    """Return review eligibility, never a direct memory or inference grant."""

    current = _utc(now)
    if not isinstance(candidate, HistoricalCandidate) or not isinstance(context, OwnerContext):
        raise TypeError("candidate and owner context required")
    # Do not let truthy non-booleans (for example client JSON strings such as
    # "false", or integer 1) masquerade as an authenticated owner or consent.
    # This remains a policy check, not a replacement for external authentication.
    if context.principal_verified is not True or not context.owner_key or context.owner_key != candidate.owner_key:
        return CandidateDecision(CandidateDisposition.DENIED, "owner_authentication_required")
    if context.opted_in is not True or context.consent_scope != RECALL_SCOPE:
        return CandidateDecision(CandidateDisposition.DENIED, "explicit_recall_review_consent_required")
    if context.consent_valid_at is None or _utc(context.consent_valid_at) > current:
        return CandidateDecision(CandidateDisposition.DENIED, "valid_consent_time_required")
    if candidate.privacy in {Privacy.UNKNOWN, Privacy.THIRD_PARTY}:
        return CandidateDecision(CandidateDisposition.QUARANTINED, "privacy_scope_unreviewed")
    if candidate.third_party_screen != ThirdPartyScreen.SCREENED_ABSENT:
        return CandidateDecision(CandidateDisposition.QUARANTINED, "third_party_review_required")
    if candidate.author_role != "user":
        return CandidateDecision(CandidateDisposition.QUARANTINED, "non_owner_author_review_required")
    if candidate.superseded_by_ref:
        return CandidateDecision(CandidateDisposition.QUARANTINED, "superseded_source")
    return CandidateDecision(CandidateDisposition.REVIEW_ELIGIBLE, "historical_source_for_owner_review_only")


def retention_state(*, source_class: str, now: datetime,
                    admitted_at: datetime | None = None) -> RetentionState:
    """Day-30/45 applies to new consented STM, never an imported source ZIP.

    ``source_class`` must be exact: unknown classes fail closed.  Archive
    retention requires a separate authorized source-preservation policy.
    """

    current = _utc(now)
    if source_class == "chatgpt_account_export":
        if admitted_at is not None:
            raise ValueError("source archive must not use STM admission time")
        return RetentionState.SOURCE_POLICY_SEPARATE
    if source_class != "new_consented_stm":
        raise ValueError("unknown retention class")
    if admitted_at is None:
        raise ValueError("new STM admission time required")
    admitted = _utc(admitted_at)
    if admitted > current:
        raise ValueError("future admission time")
    elapsed = current - admitted
    if elapsed >= STM_EXPIRE_AFTER:
        return RetentionState.EXPIRED
    if elapsed >= STM_REVIEW_AFTER:
        return RetentionState.REVIEW_ELIGIBLE
    return RetentionState.ACTIVE
