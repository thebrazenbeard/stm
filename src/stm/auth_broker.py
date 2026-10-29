"""Local, cryptographically verified conversation credentials for STM.

This module validates short-lived, scoped HMAC-SHA256 bearer credentials and
binds the verified claims to an opaque principal. It is NOT a VeraOS HTTP
server, credential issuer policy, OS peer authenticator, key manager, or
long-term revocation ledger. The embedding trusted host must authenticate an
account *before* issuing a credential, keep the 256-bit key secret, derive the
transport binding from authenticated connection evidence, and provide a
durable revocation check. Passing client JSON as a channel binding is unsafe.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
from threading import RLock
from typing import Callable

from .archive import ArchiveScope
from .models import SessionKey
from .retention import MAX_RETENTION
from .vera_bridge import ALLOWED_LABELS, ALLOWED_ROLES, VerifiedConversation


MAX_CREDENTIAL_SECONDS = 300
MAX_WORKING_SECONDS = 3600
MAX_TOKEN_BYTES = 8192
MAX_ACTIVE_GRANTS = 2048
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_OPERATIONS = frozenset({
    "working_context", "archive_read", "archive_delete", "archive_correct",
    "archive_store",
    *(f"working_write:{role}" for role in ALLOWED_ROLES),
    *(f"archive_write:{role}" for role in ALLOWED_ROLES),
})
_CLAIM_KEYS = frozenset({
    "v", "iss", "aud", "sub", "tenant", "owner", "agent", "session",
    "conversation", "privacy", "permissions", "iat", "exp", "jti",
    "binding", "working_ttl", "archive_consent", "archive_ttl",
})


def _nonblank(text: str, name: str, maximum: int = 256) -> str:
    if not isinstance(text, str) or not text.strip() or len(text) > maximum:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return text


def _now_utc(clock: Callable[[], datetime]) -> datetime:
    moment = clock()
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise RuntimeError("credential clock must return a timezone-aware datetime")
    return moment.astimezone(timezone.utc)


def _secret(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("HMAC key must be at least 256 bits from a trusted source")
    return key


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    if not value or not _BASE64URL.fullmatch(value):
        raise PermissionError("invalid credential encoding")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise PermissionError("invalid credential encoding") from error
    if _b64_encode(result) != value:
        raise PermissionError("noncanonical credential encoding")
    return result


@dataclass(frozen=True, slots=True)
class ConversationCredentialSpec:
    """Host-verified grant *inputs*; constructing one is not authentication."""

    subject: str
    session: SessionKey
    conversation_id: str
    privacy_scopes: frozenset[str]
    capabilities: frozenset[str]
    channel_binding: str
    max_working_ttl_seconds: float
    archive_consent: bool = False
    archive_retention_seconds: float | None = None

    def __post_init__(self) -> None:
        _nonblank(self.subject, "subject")
        if not isinstance(self.session, SessionKey):
            raise ValueError("server-owned SessionKey required")
        for part in (self.session.tenant_id, self.session.owner_id,
                     self.session.agent_id, self.session.session_id):
            _nonblank(part, "session scope")
        _nonblank(self.conversation_id, "conversation_id")
        _nonblank(self.channel_binding, "authenticated channel binding", 512)
        if not isinstance(self.privacy_scopes, frozenset) or not (
            self.privacy_scopes and self.privacy_scopes <= ALLOWED_LABELS
        ):
            raise ValueError("credential privacy scopes must be explicit supported labels")
        if not isinstance(self.capabilities, frozenset) or not (
            self.capabilities and self.capabilities <= _OPERATIONS
        ):
            raise ValueError("unknown or missing per-operation capabilities")
        if (isinstance(self.max_working_ttl_seconds, bool)
                or not isinstance(self.max_working_ttl_seconds, (int, float))
                or not math.isfinite(self.max_working_ttl_seconds)
                or not (0 < self.max_working_ttl_seconds <= MAX_WORKING_SECONDS)):
            raise ValueError("working TTL outside credential ceiling")
        if not isinstance(self.archive_consent, bool):
            raise ValueError("archive consent must be explicit bool")
        if self.archive_consent:
            if (isinstance(self.archive_retention_seconds, bool)
                    or not isinstance(self.archive_retention_seconds, (int, float))
                    or not math.isfinite(self.archive_retention_seconds)
                    or not (0 < self.archive_retention_seconds <= MAX_RETENTION.total_seconds())):
                raise ValueError("consented archive must have finite authorized retention")
        elif self.archive_retention_seconds is not None:
            raise ValueError("archival retention cannot be granted without consent")


class HmacCredentialIssuer:
    """Mint credentials ONLY after host independently authenticates the user.

    The instance and signing key are trusted authority; never expose `.issue`
    to a network client or make it derive `subject` from caller JSON.
    """

    def __init__(self, key: bytes, *, issuer: str, audience: str,
                 clock: Callable[[], datetime] | None = None) -> None:
        self._key = _secret(key)
        self.issuer = _nonblank(issuer, "issuer")
        self.audience = _nonblank(audience, "audience")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not callable(self._clock):
            raise TypeError("credential clock must be callable")

    def issue(self, spec: ConversationCredentialSpec, *, ttl_seconds: int = 60) -> str:
        if not isinstance(spec, ConversationCredentialSpec):
            raise TypeError("a verified credential specification is required")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_CREDENTIAL_SECONDS:
            raise ValueError("credential lifetime must be 1..300 whole seconds")
        issued = int(_now_utc(self._clock).timestamp())
        payload = {
            "v": 1, "iss": self.issuer, "aud": self.audience,
            "sub": spec.subject,
            "tenant": spec.session.tenant_id,
            "owner": spec.session.owner_id,
            "agent": spec.session.agent_id,
            "session": spec.session.session_id,
            "conversation": spec.conversation_id,
            "privacy": sorted(spec.privacy_scopes),
            "permissions": sorted(spec.capabilities),
            "iat": issued, "exp": issued + ttl_seconds,
            "jti": secrets.token_urlsafe(24),
            "binding": spec.channel_binding,
            "working_ttl": spec.max_working_ttl_seconds,
            "archive_consent": spec.archive_consent,
            "archive_ttl": spec.archive_retention_seconds,
        }
        encoded = _b64_encode(json.dumps(payload, sort_keys=True,
                                         separators=(",", ":"), allow_nan=False).encode("utf-8"))
        signature = _b64_encode(hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest())
        token = f"{encoded}.{signature}"
        if len(token.encode("ascii")) > MAX_TOKEN_BYTES:
            raise ValueError("credential exceeds maximum token size")
        return token


@dataclass(slots=True)
class _IssuedGrant:
    grant: VerifiedConversation
    principal: object
    subject: str
    token_id: str
    capabilities: frozenset[str]


class HmacConversationBroker:
    """Verify signed credentials and expose STM's host-broker callbacks.

    `token_from_request` extracts a bearer token. `channel_binding_from_request`
    MUST derive a connection-specific identity from trusted host transport,
    never request JSON, browser Origin/Host, or a self-claimed conversation ID.
    `is_revoked(issuer, subject, token_id)` MUST consult the host's durable
    revocation/credential-epoch authority, returning literal False only when
    active. A missing or failing checker is denied, not silently bypassed.

    `single_use=True` additionally REQUIRES a host-supplied durable, atomic
    `consume_jti(issuer, subject, token_id, expires_at_unix) -> bool` returning
    literal True only for the first consumption. In-process nonce tracking by
    itself cannot prevent replay across process restart or competing workers.

    Tokens can intentionally be reused for multiple operations until expiry,
    unless `single_use=True`. Bearer replay after theft can only be mitigated
    by real channel binding, short expiry, and host revocation; this module is
    not an end-to-end authenticated channel. The in-process grant registry is
    bounded and identity-based, so caller-created VerifiedConversation values
    and fabricated principal objects cannot authorize archive operations.
    """

    def __init__(
        self,
        key: bytes,
        *,
        issuer: str,
        audience: str,
        token_from_request: Callable[[object], str],
        channel_binding_from_request: Callable[[object], str],
        is_revoked: Callable[[str, str, str], bool],
        clock: Callable[[], datetime] | None = None,
        single_use: bool = False,
        consume_jti: Callable[[str, str, str, int], bool] | None = None,
        max_active_grants: int = MAX_ACTIVE_GRANTS,
    ) -> None:
        self._key = _secret(key)
        self.issuer = _nonblank(issuer, "issuer")
        self.audience = _nonblank(audience, "audience")
        for callback in (token_from_request, channel_binding_from_request, is_revoked):
            if not callable(callback):
                raise TypeError("trusted token, transport and durable revocation callbacks required")
        if not isinstance(single_use, bool):
            raise TypeError("single_use must be boolean")
        if single_use and not callable(consume_jti):
            raise ValueError("single-use credentials require durable atomic replay ledger")
        if type(max_active_grants) is not int or not 1 <= max_active_grants <= 16384:
            raise ValueError("max_active_grants must be between 1 and 16384")
        self._token_from_request = token_from_request
        self._channel_binding_from_request = channel_binding_from_request
        self._is_revoked = is_revoked
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not callable(self._clock):
            raise TypeError("credential clock must be callable")
        self._single_use = single_use
        self._consume_jti = consume_jti
        self._max_grants = max_active_grants
        self._lock = RLock()
        self._grants: OrderedDict[int, _IssuedGrant] = OrderedDict()
        self._principals: dict[int, _IssuedGrant] = {}
        self._seen_ids: dict[str, int] = {}

    def _active(self, issuer: str, subject: str, token_id: str) -> bool:
        try:
            revoked = self._is_revoked(issuer, subject, token_id)
        except Exception:
            return False
        return revoked is False

    def _decode(self, token: str) -> dict[str, object]:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or token.count(".") != 1:
            raise PermissionError("missing or malformed bearer credential")
        encoded, mac = token.split(".", 1)
        if not _BASE64URL.fullmatch(encoded):
            raise PermissionError("credential payload encoding invalid")
        signed = hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        supplied = _b64_decode(mac)
        if len(supplied) != len(signed) or not hmac.compare_digest(signed, supplied):
            raise PermissionError("credential signature invalid")
        raw = _b64_decode(encoded)
        if len(raw) > 4096:
            raise PermissionError("credential payload exceeds bounded length")
        try:
            payload = json.loads(raw.decode("utf-8"),
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
        except (ValueError, UnicodeDecodeError) as error:
            raise PermissionError("credential payload malformed") from error
        if not isinstance(payload, dict) or frozenset(payload) != _CLAIM_KEYS:
            raise PermissionError("credential claims not canonical")
        return payload

    def _claims(self, payload: dict[str, object], channel_binding: str) -> tuple[ConversationCredentialSpec, str, int, str]:
        if payload["v"] != 1 or type(payload["v"]) is not int:
            raise PermissionError("credential protocol version unsupported")
        if payload["iss"] != self.issuer or payload["aud"] != self.audience:
            raise PermissionError("wrong credential issuer or audience")
        if type(payload["iat"]) is not int or type(payload["exp"]) is not int:
            raise PermissionError("invalid credential validity window")
        issued, expiry = payload["iat"], payload["exp"]
        now = int(_now_utc(self._clock).timestamp())
        if expiry <= now or issued > now + 1 or not 1 <= expiry - issued <= MAX_CREDENTIAL_SECONDS:
            raise PermissionError("credential expired, not yet valid or excessive lifetime")
        if (not isinstance(channel_binding, str) or not channel_binding
                or len(channel_binding) > 512):
            raise PermissionError("authenticated channel binding missing")
        if not isinstance(payload["binding"], str) or not hmac.compare_digest(
            payload["binding"], channel_binding
        ):
            raise PermissionError("credential transport binding mismatch")
        if not isinstance(payload["privacy"], list) or not isinstance(payload["permissions"], list):
            raise PermissionError("invalid credential scopes")
        try:
            canonical_scopes = sorted(set(payload["privacy"]))
            canonical_permissions = sorted(set(payload["permissions"]))
        except (TypeError, ValueError) as error:
            raise PermissionError("invalid credential scope list") from error
        if payload["privacy"] != canonical_scopes or payload["permissions"] != canonical_permissions:
            raise PermissionError("noncanonical credential scope list")
        try:
            spec = ConversationCredentialSpec(
                subject=payload["sub"],
                session=SessionKey(payload["tenant"], payload["owner"],
                                   payload["agent"], payload["session"]),
                conversation_id=payload["conversation"],
                privacy_scopes=frozenset(payload["privacy"]),
                capabilities=frozenset(payload["permissions"]),
                channel_binding=payload["binding"],
                max_working_ttl_seconds=payload["working_ttl"],
                archive_consent=payload["archive_consent"],
                archive_retention_seconds=payload["archive_ttl"],
            )
            token_id = _nonblank(payload["jti"], "credential id", 128)
        except (TypeError, ValueError) as error:
            raise PermissionError("invalid credential scope claims") from error
        return spec, token_id, expiry, self.issuer

    def resolve(self, request: object) -> VerifiedConversation:
        if request is None:
            raise PermissionError("authenticated request required")
        try:
            token = self._token_from_request(request)
            binding = self._channel_binding_from_request(request)
        except Exception as error:
            raise PermissionError("authenticated transport extraction failed") from error
        payload = self._decode(token)
        spec, token_id, expiry, issuer = self._claims(payload, binding)
        with self._lock:
            self._prune()
            if not self._active(issuer, spec.subject, token_id):
                raise PermissionError("credential revoked or revocation status unknown")
            if self._single_use and token_id in self._seen_ids:
                raise PermissionError("credential replay denied")
            if self._single_use:
                if len(self._seen_ids) >= self._max_grants * 8:
                    raise PermissionError("replay protection registry full")
                try:
                    consumed = self._consume_jti(issuer, spec.subject, token_id, expiry)
                except Exception as error:
                    raise PermissionError("durable replay ledger unavailable") from error
                if consumed is not True:
                    raise PermissionError("credential replay denied")
                self._seen_ids[token_id] = expiry
            principal = object()
            grant = VerifiedConversation(
                principal=principal,
                session=spec.session,
                conversation_id=spec.conversation_id,
                privacy_scopes=spec.privacy_scopes,
                expires_at=datetime.fromtimestamp(expiry, tz=timezone.utc),
                max_working_ttl_seconds=spec.max_working_ttl_seconds,
                archive_consent=spec.archive_consent,
                archive_retention_seconds=spec.archive_retention_seconds,
            )
            state = _IssuedGrant(grant, principal, spec.subject, token_id, spec.capabilities)
            self._grants[id(grant)] = state
            self._principals[id(principal)] = state
            self._prune()
            return grant

    def _prune(self) -> None:
        now = _now_utc(self._clock)
        for key, state in tuple(self._grants.items()):
            if state.grant.expires_at <= now:
                self._grants.pop(key, None)
                self._principals.pop(id(state.principal), None)
        while len(self._grants) > self._max_grants:
            _, state = self._grants.popitem(last=False)
            self._principals.pop(id(state.principal), None)
        # Never clear unexpired replay IDs to relieve capacity: that would
        # silently allow replay. Reject new credentials instead when full.
        for token_id, expiry in tuple(self._seen_ids.items()):
            if expiry <= now.timestamp():
                self._seen_ids.pop(token_id, None)

    def _state(self, grant: VerifiedConversation) -> _IssuedGrant | None:
        state = self._grants.get(id(grant))
        if state is None or state.grant is not grant:
            return None
        if grant.expires_at <= _now_utc(self._clock):
            return None
        if not self._active(self.issuer, state.subject, state.token_id):
            return None
        return state

    def authorize(self, grant: VerifiedConversation, action: str, privacy: str) -> bool:
        with self._lock:
            if not isinstance(grant, VerifiedConversation):
                return False
            state = self._state(grant)
            return (state is not None and privacy in grant.privacy_scopes
                    and action in state.capabilities)

    def authorize_archive(self, principal: object, action: str,
                          scope: ArchiveScope) -> bool:
        with self._lock:
            state = self._principals.get(id(principal))
            if state is None or state.principal is not principal or not isinstance(scope, ArchiveScope):
                return False
            if self._state(state.grant) is None:
                return False
            session = state.grant.session
            if scope != ArchiveScope(session.tenant_id, session.owner_id, session.agent_id):
                return False
            capabilities = state.capabilities
            if action == "search":
                return "archive_read" in capabilities and state.grant.archive_consent
            if action == "append":
                return "archive_store" in capabilities and state.grant.archive_consent
            if action == "correct":
                return "archive_correct" in capabilities and state.grant.archive_consent
            if action == "delete":
                return "archive_delete" in capabilities
            if action.startswith("read_privacy:"):
                label = action.removeprefix("read_privacy:")
                return (label in state.grant.privacy_scopes and state.grant.archive_consent
                        and "archive_read" in capabilities)
            if action.startswith("write_privacy:"):
                label = action.removeprefix("write_privacy:")
                consent = state.grant.archive_consent
                return label in state.grant.privacy_scopes and (
                    "archive_delete" in capabilities
                    or (consent and bool(capabilities & frozenset({
                        "archive_store", "archive_correct",
                    })))
                )
            return False


class ScopedCleanupAuthority:
    """Independently authenticated, exact-scope expiry-service capability.

    This is intentionally separate from user conversation credentials: a
    scheduler must still be able to expire old rows after users log out or
    all user tokens expire. The trusted host provisions an independent random
    >=256-bit secret in secure service-only storage. `acquire(secret)` may be
    invoked ONLY from its authenticated scheduler/OS-service lane; do not
    expose that method as a generic HTTP endpoint. An acquired opaque principal
    authorizes only `expire`, read-only `audit_legacy`, and matching
    `write_privacy:<label>` operations on one exact archive scope, never
    arbitrary `delete`, append, search, correct, or broader scopes.

    It is an in-process authorization building block, not proof of actual OS
    service identity, cron scheduling, ACLs, key storage or backup erasure.
    """

    def __init__(self, secret: bytes, *, scope: ArchiveScope,
                 privacy_scopes: frozenset[str],
                 clock: Callable[[], datetime] | None = None,
                 lease_seconds: int = 60,
                 max_live_leases: int = 32) -> None:
        self._secret = _secret(secret)
        if not isinstance(scope, ArchiveScope):
            raise ValueError("exact cleanup ArchiveScope required")
        if (not isinstance(privacy_scopes, frozenset) or not privacy_scopes
                or not privacy_scopes <= ALLOWED_LABELS):
            raise ValueError("exact cleanup privacy labels required")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= MAX_CREDENTIAL_SECONDS:
            raise ValueError("cleanup lease must be between 1 and 300 seconds")
        if type(max_live_leases) is not int or not 1 <= max_live_leases <= 1024:
            raise ValueError("cleanup lease limit invalid")
        self._scope = scope
        self._labels = privacy_scopes
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not callable(self._clock):
            raise TypeError("cleanup clock must be callable")
        self._lease_seconds = lease_seconds
        self._max_live_leases = max_live_leases
        self._lock = RLock()
        self._leases: OrderedDict[int, tuple[object, datetime]] = OrderedDict()

    def acquire(self, presented_secret: bytes) -> object:
        if (not isinstance(presented_secret, bytes)
                or not hmac.compare_digest(presented_secret, self._secret)):
            raise PermissionError("cleanup service credential denied")
        now = _now_utc(self._clock)
        with self._lock:
            for key, (_, deadline) in tuple(self._leases.items()):
                if deadline <= now:
                    self._leases.pop(key, None)
            if len(self._leases) >= self._max_live_leases:
                raise PermissionError("cleanup principal capacity exceeded")
            principal = object()
            self._leases[id(principal)] = (principal,
                                           now + timedelta(seconds=self._lease_seconds))
            return principal

    def authorize_archive(self, principal: object, action: str,
                          scope: ArchiveScope) -> bool:
        with self._lock:
            state = self._leases.get(id(principal))
            if state is None or state[0] is not principal:
                return False
            if state[1] <= _now_utc(self._clock) or scope != self._scope:
                return False
            if action in ("expire", "audit_legacy"):
                return True
            if isinstance(action, str) and action.startswith("write_privacy:"):
                return action.removeprefix("write_privacy:") in self._labels
            return False


__all__ = [
    "MAX_CREDENTIAL_SECONDS", "ConversationCredentialSpec",
    "HmacCredentialIssuer", "HmacConversationBroker", "ScopedCleanupAuthority",
]
