"""Opt-in, host-governed STM-to-historical-store handoff boundary.

This module DOES NOT implement a DeepMemoryStorage writer.  As inspected on
2026-10-28, that repository documents an append-only evidence ledger and a
read/query interface, not a revocable, retention-governed ingestion service.

Day-30 eligibility is a *review* milestone.  No private conversation content
leaves STM unless the embedding host supplies fresh source authentication,
specific export consent, verified target lifecycle guarantees, an explicitly
injected writer, and an independent receipt verifier.  Receipt verification is
the host's responsibility; this module never equates an arbitrary string with
evidence of external storage.  No successful handoff deletes local records.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Callable, Protocol

from .archive import ArchiveScope, ArchiveTurn


HISTORICAL_ONLY = "HISTORICAL_EVIDENCE_ONLY_NOT_CURRENT_MEMORY_OR_AUTHORITY"
_OPAQUE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,79}$", re.ASCII)
_SENSITIVE_REF = re.compile(r"(?:bearer|authorization|password|secret|api.?key|ghp_|sk-)", re.I)


def _utc_time(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("all historical handoff times must be timezone aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class TargetGovernance:
    """Host-verified target capabilities, never accepted as self-authentication.

    In particular an immutable append-only target that cannot honor deletion,
    correction and consent withdrawal MUST NOT be represented as compatible.
    The host must independently verify every assertion before any export.
    """

    destination_id: str
    retention_until: datetime
    supports_deletion: bool
    supports_correction: bool
    supports_consent_revocation: bool
    private_destination: bool
    supports_scope_isolation: bool


@dataclass(frozen=True, slots=True)
class HistoricalHandoffRecord:
    """Source-bound historical evidence candidate, not governed admission."""

    schema: str
    tenant_id: str
    owner_id: str
    agent_id: str
    turn_id: str
    conversation_id: str
    role: str
    content: str
    source_id: str
    privacy_scope: str
    event_time: str
    recorded_at: str
    supersedes_id: str | None
    expires_at: str | None
    source_version_digest: str
    result_semantics: str = HISTORICAL_ONLY


@dataclass(frozen=True, slots=True)
class HistoricalHandoffReceipt:
    destination_id: str
    source_version_digest: str
    idempotency_key: str
    external_record_id: str
    verification: str = "HOST_VERIFIED_EXTERNAL_RECEIPT"


class HistoricalSink(Protocol):
    """Host-owned idempotent writer; STM itself owns no DeepMemoryStorage credentials.

    ``submit`` MUST durably deduplicate identical idempotency keys across
    process restarts. The explicit verifier must separately establish the
    matching accepted record under the target's authorized scope.
    """

    def submit(self, record: HistoricalHandoffRecord, *,
               target: TargetGovernance, idempotency_key: str) -> object: ...


class HandoffUnverified(RuntimeError):
    """Target may have received data; no verified acceptance was established.

    The caller must not erase source data or claim external storage. Reconcile
    with the same idempotency key and the target's durable write ledger.
    """

    def __init__(self, message: str, *, idempotency_key: str) -> None:
        super().__init__(message)
        self.idempotency_key = idempotency_key


class DeepMemoryHandoff:
    """Fail-closed injection boundary for a separately approved historical sink.

    The host's ``resolve_live_turn`` must fetch an exact, currently active,
    privacy-authorized source row, not a cached/attacker-supplied snapshot.
    ``authorize`` grants both the ``long_term_export`` action and its specific
    privacy label. ``consent`` checks the *current* source-owner consent for
    this exact turn+target retention contract, not a historical statement of
    intent or permission for an arbitrarily longer target retention period.
    ``verify_target`` independently checks the target's deletion/correction,
    revocation and finite-retention behavior. ``verify_receipt`` independently
    checks actual target acceptance. These are trusted host integrations, not
    local credentials and not verified by the library alone.
    """

    def __init__(
        self,
        *,
        policy: object,
        resolve_live_turn: Callable[[object, ArchiveScope, str], ArchiveTurn | None],
        authorize: Callable[[object, str, ArchiveScope, str | None], bool],
        consent: Callable[[object, ArchiveScope, str, str, TargetGovernance], bool],
        verify_target: Callable[[TargetGovernance, ArchiveScope, str], bool],
        sink: HistoricalSink,
        verify_receipt: Callable[[object, HistoricalHandoffRecord, str], bool],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not callable(getattr(policy, "evaluate", None)):
            raise TypeError("a live 30-day review policy is required")
        for value in (resolve_live_turn, authorize, consent, verify_target,
                      verify_receipt, clock, getattr(sink, "submit", None)):
            if not callable(value):
                raise TypeError("explicit host callbacks and a sink are required")
        self._policy = policy
        self._resolve_live_turn = resolve_live_turn
        self._authorize = authorize
        self._consent = consent
        self._verify_target = verify_target
        self._sink = sink
        self._verify_receipt = verify_receipt
        self._clock = clock

    def _authorized(self, principal: object, scope: ArchiveScope,
                    privacy: str | None) -> None:
        try:
            permitted = self._authorize(principal, "long_term_export", scope, privacy)
        except Exception as error:
            raise PermissionError("host long-term export authorization unavailable") from error
        if permitted is not True:
            raise PermissionError("host long-term export authorization denied")

    def _live(self, principal: object, scope: ArchiveScope, turn_id: str) -> ArchiveTurn:
        try:
            turn = self._resolve_live_turn(principal, scope, turn_id)
        except Exception as error:
            raise PermissionError("cannot resolve an authorized active archive turn") from error
        if (not isinstance(turn, ArchiveTurn) or turn.turn_id != turn_id
                or not turn.content or not turn.source or not turn.privacy):
            raise PermissionError("missing or superseded archive source turn")
        return turn

    def _consented(self, principal: object, scope: ArchiveScope,
                   turn: ArchiveTurn, target: TargetGovernance) -> None:
        try:
            permitted = self._consent(principal, scope, turn.turn_id,
                                      turn.privacy, target)
        except Exception as error:
            raise PermissionError("fresh long-term export consent unavailable") from error
        if permitted is not True:
            raise PermissionError("current turn-specific export consent denied")

    @staticmethod
    def _record(scope: ArchiveScope, turn: ArchiveTurn) -> HistoricalHandoffRecord:
        source = {
            "scope": [scope.tenant_id, scope.owner_id, scope.agent_id],
            "turn": [turn.turn_id, turn.conversation_id, turn.role, turn.content,
                     turn.source, turn.privacy, turn.event_time, turn.recorded_at,
                     turn.supersedes_id, turn.expires_at],
        }
        digest = hashlib.sha256(json.dumps(source, ensure_ascii=False,
                             separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
        return HistoricalHandoffRecord(
            schema="STM_HISTORICAL_HANDOFF_CANDIDATE_V1",
            tenant_id=scope.tenant_id, owner_id=scope.owner_id,
            agent_id=scope.agent_id, turn_id=turn.turn_id,
            conversation_id=turn.conversation_id, role=turn.role,
            content=turn.content, source_id=turn.source,
            privacy_scope=turn.privacy, event_time=turn.event_time,
            recorded_at=turn.recorded_at, supersedes_id=turn.supersedes_id,
            expires_at=turn.expires_at, source_version_digest=digest,
        )

    def submit(self, principal: object, scope: ArchiveScope, turn_id: str,
               *, target: TargetGovernance) -> HistoricalHandoffReceipt:
        """Submit once, only after explicit export consent and lifecycle evidence.

        Source content is never transmitted to a sink when a preflight gate
        fails. A host should hold a source-level revocation/active-version
        lease through this call; the post-write check detects but cannot undo
        an externally published record after a concurrent revocation.
        """
        if principal is None or not isinstance(scope, ArchiveScope):
            raise PermissionError("authenticated archive scope is required")
        if not isinstance(turn_id, str) or not turn_id.strip():
            raise ValueError("explicit source turn ID required")
        if (not isinstance(target, TargetGovernance)
                or not isinstance(target.destination_id, str)
                or not target.destination_id.strip()):
            raise PermissionError("verified target governance contract required")
        now = max(_utc_time(self._clock()), datetime.now(timezone.utc))
        if (not all(value is True for value in (
                target.supports_deletion, target.supports_correction,
                target.supports_consent_revocation, target.private_destination,
                target.supports_scope_isolation))
                or _utc_time(target.retention_until) <= now):
            raise PermissionError("target lacks private, scoped, revocable, finite retention")

        self._authorized(principal, scope, None)
        turn = self._live(principal, scope, turn_id)
        self._authorized(principal, scope, turn.privacy)
        self._consented(principal, scope, turn, target)
        if turn.expires_at is None or _utc_time(turn.expires_at) <= now:
            raise PermissionError("source retention expired or policy is missing")
        try:
            eligibility = self._policy.evaluate(
                turn, now=now, current_consent=True, current_authority=True)
        except Exception as error:
            raise PermissionError("handoff review policy failed") from error
        if getattr(eligibility, "eligible", None) is not True:
            raise PermissionError("turn is not eligible for day-30 handoff review")
        try:
            target_verified = self._verify_target(target, scope, turn.privacy)
        except Exception as error:
            raise PermissionError("target retention verification unavailable") from error
        if target_verified is not True:
            raise PermissionError("target retention and revocation guarantees unverified")

        record = self._record(scope, turn)
        binding = json.dumps({
            "destination_id": target.destination_id,
            "retention_until": _utc_time(target.retention_until).isoformat(),
            "supports_deletion": target.supports_deletion,
            "supports_correction": target.supports_correction,
            "supports_consent_revocation": target.supports_consent_revocation,
            "private_destination": target.private_destination,
            "supports_scope_isolation": target.supports_scope_isolation,
            "source_version_digest": record.source_version_digest,
        }, sort_keys=True, separators=(",", ":"))
        key = hashlib.sha256(binding.encode("utf-8")).hexdigest()
        # Revalidate immediately before crossing the external privacy boundary.
        refreshed = self._live(principal, scope, turn_id)
        self._authorized(principal, scope, refreshed.privacy)
        self._consented(principal, scope, refreshed, target)
        if self._record(scope, refreshed).source_version_digest != record.source_version_digest:
            raise PermissionError("source version changed during export preflight")

        try:
            raw_receipt = self._sink.submit(record, target=target, idempotency_key=key)
        except Exception as error:
            raise HandoffUnverified("sink acceptance is unknown; source preserved",
                                    idempotency_key=key) from error
        try:
            accepted = self._verify_receipt(raw_receipt, record, key)
        except Exception as error:
            raise HandoffUnverified("external acceptance could not be verified",
                                    idempotency_key=key) from error
        if accepted is not True:
            raise HandoffUnverified("external acceptance was not independently verified",
                                    idempotency_key=key)
        external_id = raw_receipt.get("external_record_id") if isinstance(raw_receipt, dict) else None
        if (not isinstance(external_id, str) or _OPAQUE_REF.fullmatch(external_id) is None
                or _SENSITIVE_REF.search(external_id) is not None):
            raise HandoffUnverified("backend did not return a safe opaque external identifier",
                                    idempotency_key=key)
        # A concurrent revocation after transmission cannot be undone here.
        # Never describe it as a successful governed transfer.
        try:
            still_live = self._live(principal, scope, turn_id)
            self._authorized(principal, scope, still_live.privacy)
            self._consented(principal, scope, still_live, target)
            if self._verify_target(target, scope, still_live.privacy) is not True:
                raise PermissionError("destination governance withdrawn")
        except PermissionError as error:
            raise HandoffUnverified("source authorization changed during export",
                                    idempotency_key=key) from error
        except Exception as error:
            raise HandoffUnverified("target governance check failed after export",
                                    idempotency_key=key) from error
        if self._record(scope, still_live).source_version_digest != record.source_version_digest:
            raise HandoffUnverified("source changed during external export",
                                    idempotency_key=key)
        if _utc_time(still_live.expires_at) <= datetime.now(timezone.utc):
            raise HandoffUnverified("source expiry crossed during external export",
                                    idempotency_key=key)
        return HistoricalHandoffReceipt(
            destination_id=target.destination_id,
            source_version_digest=record.source_version_digest,
            idempotency_key=key, external_record_id=external_id,
        )


__all__ = ["HISTORICAL_ONLY", "TargetGovernance", "HistoricalHandoffRecord",
           "HistoricalHandoffReceipt", "HistoricalSink", "HandoffUnverified",
           "DeepMemoryHandoff"]
