"""Conservative, dependency-free memory access and admission policy for STM.

The host must authenticate callers before constructing :class:`Actor`.  A
matching string identifier is NOT authentication.  Stored text is data, never
an instruction or proof of authority.  This policy deliberately has no
long-term-memory promotion capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Protocol
import hashlib
import re
import secrets


PRIVACY_LABELS = frozenset({"private", "session", "shared"})
MEMORY_KINDS = frozenset({"observation", "interpretation", "hypothesis"})
ORIGINS = frozenset({"direct", "external", "historical"})


class AccessDenied(PermissionError):
    """A scope, consent, or provenance boundary disallows the operation."""


class AdmissionRejected(ValueError):
    """A record is invalid or requires explicit review before admission."""


class ScopeLike(Protocol):
    tenant_id: str
    owner_id: str
    agent_id: str
    session_id: str


class RecordLike(Protocol):
    id: str
    scope: ScopeLike
    content: str
    source: str
    kind: str
    privacy: str
    version: int


@dataclass(frozen=True, slots=True)
class Actor:
    """Identity claims supplied by the *authenticated* STM host."""

    tenant_id: str
    owner_id: str
    agent_id: str
    session_id: str
    roles: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.owner_id, self.agent_id, self.session_id)):
            raise ValueError("all actor identifiers are required")
        if not isinstance(self.roles, frozenset):
            object.__setattr__(self, "roles", frozenset(self.roles))


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    allowed: bool
    quarantine: bool
    reasons: tuple[str, ...]
    evidence_status: str
    authority: str = "none"


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """A narrow, revocable consent receipt stored by a policy instance.

    Possession of a copied receipt does not grant access unless its ID is
    present in the issuing policy's grant registry with every field matching.
    """

    grant_id: str
    issuer: Actor
    recipient: Actor
    record_id: str
    record_version: int
    record_digest: str
    purpose: str
    issued_at: datetime
    expires_at: datetime


_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"\b(ignore|disregard|override)\s+(all\s+)?(previous|prior|above|system|developer)\s+(?:(?:system|developer)\s+)?(instructions?|rules?|messages?)\b", re.I)),
    ("role_spoofing", re.compile(r"(?:<\|im_start\|>\s*(?:system|developer)|\[/?INST\]|\[system\]|(?m:^\s*(?:system|developer)\s*:\s*))", re.I)),
    ("authority_spoofing", re.compile(r"\b(?:you\s+are\s+now\s+(?:the\s+)?(?:system|developer)|this\s+(?:message|text)\s+(?:supersedes|overrides)\s+(?:your\s+)?(?:policy|instructions?))\b", re.I)),
    ("memory_promotion", re.compile(r"\b(?:save|promote|write)\s+(?:this|these|the\s+following)\s+(?:as|to|in)\s+(?:permanent|long.term|canonical|system)\s+memory\b", re.I)),
)


def flag_injection(content: str) -> tuple[str, ...]:
    """Conservative lexical flags; not a complete injection detector.

    False positives are possible (for example, quoted security examples).
    Callers should quarantine for review, never execute or obey such text.
    """

    if not isinstance(content, str):
        raise TypeError("content must be text")
    return tuple(code for code, pattern in _INJECTION_RULES if pattern.search(content))


def _same_scope(actor: Actor, scope: ScopeLike) -> bool:
    return (
        actor.tenant_id == scope.tenant_id
        and actor.owner_id == scope.owner_id
        and actor.agent_id == scope.agent_id
        and actor.session_id == scope.session_id
    )


def _same_trust_domain(a: Actor, b: Actor) -> bool:
    return (
        a.tenant_id == b.tenant_id
        and a.owner_id == b.owner_id
        and a.session_id == b.session_id
    )


def _actor_from_scope(scope: ScopeLike) -> Actor:
    return Actor(scope.tenant_id, scope.owner_id, scope.agent_id, scope.session_id)


def _record_digest(record: RecordLike) -> str:
    """Bind a grant to immutable record material, not just a reusable ID."""
    values = (
        record.id,
        str(record.version),
        record.content,
        record.source,
        record.kind,
        record.privacy,
        getattr(record, "origin", "direct"),
    )
    digest = hashlib.sha256()
    for value in values:
        raw = value.encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


class GovernancePolicy:
    """Fail-closed STM policy with optional explicit, record-scoped read grants.

    ``validate_admission`` and ``validate_read`` implement the lightweight
    STM ``MemoryPolicy`` protocol.  A policy instance keeps ephemeral grants;
    they are intentionally NOT persisted or inherited after restart.
    """

    def __init__(self, *, max_content_chars: int = 100_000, max_grants: int = 1024):
        if max_content_chars < 1 or max_grants < 1:
            raise ValueError("limits must be positive")
        self.max_content_chars = max_content_chars
        self.max_grants = max_grants
        self._grants: dict[str, AccessGrant] = {}
        self._lock = RLock()

    def admit(
        self,
        actor: Actor,
        content: str,
        *,
        source: str,
        kind: str = "observation",
        privacy: str = "private",
        origin: str = "direct",
        evidence_is_historical: bool | None = None,
    ) -> AdmissionDecision:
        """Classify an incoming data item; never assert its truth or authority."""

        if not isinstance(actor, Actor):
            raise TypeError("actor must be authenticated by the host")
        reasons: list[str] = []
        if not isinstance(content, str) or not content.strip():
            reasons.append("empty_content")
        elif len(content) > self.max_content_chars:
            reasons.append("content_too_large")
        else:
            reasons.extend(flag_injection(content))
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            reasons.append("invalid_source")
        if kind not in MEMORY_KINDS:
            reasons.append("invalid_kind")
        if privacy not in PRIVACY_LABELS:
            reasons.append("invalid_privacy")
        if origin not in ORIGINS:
            reasons.append("invalid_origin")
        historical_source = isinstance(source, str) and source.lower().startswith(
            ("historical:", "archive:", "deepmemorystorage:", "dms:")
        )
        if historical_source and origin != "historical":
            reasons.append("historical_source_requires_historical_origin")
        if evidence_is_historical is True and origin != "historical":
            reasons.append("historical_evidence_cannot_be_current")
        if evidence_is_historical is False and origin == "historical":
            reasons.append("contradictory_historical_origin")
        status = {
            "direct": "unverified_direct_observation",
            "external": "untrusted_external_evidence",
            "historical": "historical_evidence_only",
        }.get(origin, "unclassified")
        return AdmissionDecision(
            allowed=not reasons,
            quarantine=bool(reasons),
            reasons=tuple(dict.fromkeys(reasons)),
            evidence_status=status,
        )

    def authorize_write(self, actor: Actor, record: RecordLike) -> None:
        if not _same_scope(actor, record.scope):
            raise AccessDenied("write requires exact identity and session scope")
        decision = self.admit(
            actor,
            record.content,
            source=record.source,
            kind=record.kind,
            privacy=record.privacy,
            origin=getattr(record, "origin", "direct"),
        )
        if not decision.allowed:
            raise AdmissionRejected(",".join(decision.reasons))

    def authorize_read(
        self,
        actor: Actor,
        record: RecordLike,
        *,
        purpose: str = "context",
        grant_id: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        if not isinstance(actor, Actor) or not record.id or not purpose:
            return False
        now = now or datetime.now(timezone.utc)
        expires_at = getattr(record, "expires_at", None)
        if expires_at is not None and expires_at <= now:
            return False
        if _same_scope(actor, record.scope):
            return True
        if not grant_id:
            return False
        with self._lock:
            grant = self._grants.get(grant_id)
            if not grant:
                return False
            if grant.expires_at <= now:
                self._grants.pop(grant_id, None)
                return False
            return (
                grant.recipient == actor
                and grant.record_id == record.id
                and grant.record_version == record.version
                and grant.record_digest == _record_digest(record)
                and grant.purpose == purpose
                and _same_scope(grant.issuer, record.scope)
                and _same_trust_domain(grant.issuer, actor)
            )

    def issue_read_grant(
        self,
        issuer: Actor,
        record: RecordLike,
        recipient: Actor,
        *,
        purpose: str,
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> AccessGrant:
        if not _same_scope(issuer, record.scope):
            raise AccessDenied("grant issuer must control the exact record scope")
        if not _same_trust_domain(issuer, recipient):
            raise AccessDenied("cross-tenant, owner, or session sharing is forbidden")
        if not purpose or not isinstance(purpose, str) or len(purpose) > 100:
            raise ValueError("bounded purpose is required")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 86400:
            raise ValueError("grant TTL must be from 1 to 86400 seconds")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("grant time must be timezone-aware")
        grant = AccessGrant(
            grant_id=secrets.token_urlsafe(24),
            issuer=issuer,
            recipient=recipient,
            record_id=record.id,
            record_version=record.version,
            record_digest=_record_digest(record),
            purpose=purpose,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._prune_grants_locked(now)
            if len(self._grants) >= self.max_grants:
                raise AccessDenied("read grant capacity reached")
            self._grants[grant.grant_id] = grant
        return grant

    def revoke_read_grant(self, issuer: Actor, grant_id: str) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                return False
            if grant.issuer != issuer:
                raise AccessDenied("only the original issuer can revoke this grant")
            del self._grants[grant_id]
            return True

    def prune_grants(self, now: datetime | None = None) -> int:
        with self._lock:
            return self._prune_grants_locked(now or datetime.now(timezone.utc))

    def _prune_grants_locked(self, now: datetime) -> int:
        expired = [gid for gid, grant in self._grants.items() if grant.expires_at <= now]
        for gid in expired:
            del self._grants[gid]
        return len(expired)

    def authorize_correction(self, actor: Actor, original: RecordLike, replacement: RecordLike) -> None:
        if not _same_scope(actor, original.scope) or not _same_scope(actor, replacement.scope):
            raise AccessDenied("correction must remain in its original scope")
        for name in ("id", "scope", "role", "source", "kind", "privacy", "origin", "pinned", "expires_at"):
            if getattr(original, name, None) != getattr(replacement, name, None):
                raise AccessDenied(f"correction cannot change {name}")
        if replacement.version != original.version + 1:
            raise AccessDenied("correction must increment exactly one version")
        if getattr(original, "created_at", None) != getattr(replacement, "created_at", None):
            raise AccessDenied("correction cannot change creation time")
        if getattr(replacement, "updated_at", None) < getattr(original, "updated_at", None):
            raise AccessDenied("correction time cannot move backward")
        self.authorize_write(actor, replacement)

    @staticmethod
    def authorize_promotion(*_args: object, **_kwargs: object) -> bool:
        """No STM action grants historical/current or long-term authority."""
        return False

    # STM MemoryPolicy protocol: an exact session key is the caller identity.
    def validate_admission(self, scope: ScopeLike, record: RecordLike) -> None:
        self.authorize_write(_actor_from_scope(scope), record)

    def validate_read(self, scope: ScopeLike, record: RecordLike) -> None:
        if not self.authorize_read(_actor_from_scope(scope), record):
            raise AccessDenied("read requires exact identity/session or explicit grant")
