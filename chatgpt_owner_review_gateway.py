"""Host-injected, ephemeral owner-review boundary for a private account export.

This is a *source-level interface*, not a device authenticator, server, model
tool, credential issuer, or deployed Vera endpoint. A trusted host must supply
callbacks backed by its actual OS peer identity, owner/consent database,
private encrypted archive, and independent candidate screening. In particular,
neither a request field nor a historical message may construct identity proof.

Only local human-owner previews are returned. A model-facing memory endpoint
requires a separate design, approval and live qualification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable, Mapping

from chatgpt_memory_policy import HistoricalCandidate, OwnerContext, RECALL_SCOPE
from chatgpt_recall import (
    MAX_HITS, MAX_QUERY_CHARS, ReviewHit, search_for_owner_review,
)


_SHA = re.compile(r"[0-9a-f]{64}\Z")


class HistoricalReviewDenied(PermissionError):
    """A generic denial, deliberately containing no private source details."""


@dataclass(frozen=True, repr=False)
class HostOwnerProof:
    """Issued only by a trusted, independently authenticating host callback.

    This dataclass is *not* an unforgeable credential. Its provenance is the
    injected callback, which must not echo client-supplied identity claims.
    """

    owner_key: str
    authenticated_principal: str
    trusted_channel_binding: str
    principal_verified: bool


@dataclass(frozen=True, repr=False)
class HostReviewConsent:
    """Current, owner-bound, versioned host-consent snapshot."""

    owner_key: str
    scope: str
    opted_in: bool
    valid_at: datetime
    expires_at: datetime
    revision: str


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise HistoricalReviewDenied("historical owner review unavailable")
    return value.astimezone(timezone.utc)


def _valid_proof(value: object) -> bool:
    return (
        isinstance(value, HostOwnerProof)
        and value.principal_verified is True
        and all(isinstance(item, str) and item.strip() and len(item) <= 256 for item in (
            value.owner_key, value.authenticated_principal, value.trusted_channel_binding,
        ))
    )


def _valid_consent(value: object, owner_key: str, now: datetime) -> bool:
    if not isinstance(value, HostReviewConsent):
        return False
    try:
        start, end = _utc(value.valid_at), _utc(value.expires_at)
    except HistoricalReviewDenied:
        return False
    return (
        value.owner_key == owner_key
        and value.scope == RECALL_SCOPE
        and value.opted_in is True
        and isinstance(value.revision, str) and bool(value.revision.strip()) and len(value.revision) <= 256
        and start <= now < end
    )


class HistoricalOwnerReviewGateway:
    """Single-request host-gated preview, with a second consent readback.

    `authenticate` must derive identity and channel binding from the trusted
    transport; `current_consent` must consult a durable, revocable host store
    on each call; `load_conversation` must retrieve/decrypt within the owner-
    restricted vault; and `screen_candidates` must independently validate
    privacy, author and third-party status. No callback is called on the
    source until the preceding gate succeeds.

    This interface does not make those callbacks trustworthy by itself.
    A restart-safe or distributed service must enforce revocation atomically
    with source access and UI delivery. Checking twice limits, but cannot
    eliminate, an interleaving revocation race in this in-process prototype.
    """

    def __init__(
        self,
        *,
        authenticate: Callable[[object], HostOwnerProof],
        current_consent: Callable[[HostOwnerProof, str], HostReviewConsent],
        load_conversation: Callable[[HostOwnerProof, str, str], dict],
        screen_candidates: Callable[[HostOwnerProof, str, str], Mapping[str, HistoricalCandidate]],
        clock: Callable[[], datetime],
    ) -> None:
        if not all(callable(callback) for callback in (
            authenticate, current_consent, load_conversation, screen_candidates, clock,
        )):
            raise TypeError("all trusted-host callbacks are required")
        self._authenticate = authenticate
        self._current_consent = current_consent
        self._load_conversation = load_conversation
        self._screen_candidates = screen_candidates
        self._clock = clock

    def preview(
        self,
        request: object,
        *,
        export_sha256: str,
        conversation_id: str,
        query: str,
        active_branch_only: bool = True,
        max_hits: int = 10,
    ) -> tuple[ReviewHit, ...]:
        """Produce attributed local UI snippets; never a model input grant."""
        denied = HistoricalReviewDenied("historical owner review unavailable")
        if (request is None or not isinstance(export_sha256, str)
                or not _SHA.fullmatch(export_sha256)
                or not isinstance(conversation_id, str)
                or not 0 < len(conversation_id) <= 256
                or not isinstance(query, str) or not query.strip()
                or not 0 < len(query) <= MAX_QUERY_CHARS
                or type(active_branch_only) is not bool
                or type(max_hits) is not int or not 1 <= max_hits <= MAX_HITS):
            raise denied
        try:
            now = _utc(self._clock())
            proof = self._authenticate(request)
            if not _valid_proof(proof):
                raise denied
            first = self._current_consent(proof, export_sha256)
            if not _valid_consent(first, proof.owner_key, now):
                raise denied

            conversation = self._load_conversation(proof, export_sha256, conversation_id)
            if (not isinstance(conversation, dict)
                    or conversation.get("id", conversation.get("conversation_id")) != conversation_id):
                raise denied
            candidates = self._screen_candidates(proof, export_sha256, conversation_id)
            if not isinstance(candidates, Mapping):
                raise denied
            context = OwnerContext(
                owner_key=proof.owner_key,
                principal_verified=True,
                opted_in=True,
                consent_scope=RECALL_SCOPE,
                consent_valid_at=first.valid_at,
            )
            hits = search_for_owner_review(
                conversation, export_sha256, query, candidates, context,
                now=now, active_branch_only=active_branch_only, max_hits=max_hits,
            )
            # Fail closed when permission changes during search or the durable
            # consent store is unavailable. Do not cache grants between calls.
            second = self._current_consent(proof, export_sha256)
            if second != first or not _valid_consent(second, proof.owner_key, _utc(self._clock())):
                raise denied
            return hits
        except Exception:
            # Deliberately suppress callback exceptions, paths and source IDs.
            raise HistoricalReviewDenied("historical owner review unavailable") from None
