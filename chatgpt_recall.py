"""Ephemeral, owner-review-only search over one authenticated conversation.

The caller MUST independently authenticate the owner, decrypt the conversation
inside the private vault boundary, and supply externally screened candidates.
This module does none of those things.  It does not write a plaintext index,
expose a network endpoint, or authorize sending any result to a model.

Historical text is untrusted evidence, including when it impersonates a system
instruction.  Returned snippets are suitable only for a bounded, local owner
review UI that preserves the provenance and no-authority labels.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping

from chatgpt_graph import derive_graph
from chatgpt_memory_policy import (
    CandidateDisposition,
    HistoricalCandidate,
    OwnerContext,
    classify_candidate,
)


MAX_QUERY_CHARS = 128
MAX_HITS = 20
MAX_SNIPPET_CHARS = 280
MAX_SCAN_NODES = 10_000
MAX_SCAN_CHARS = 1_000_000


class RecallFailure(ValueError):
    """A request cannot be safely evaluated in this local review boundary."""


@dataclass(frozen=True, repr=False)
class ReviewHit:
    """Untrusted local owner preview, deliberately hidden from repr/logs."""

    export_sha256: str
    conversation_id: str
    node_id: str
    message_id: str | None
    author_role: str
    is_active_branch: bool
    excerpt: str = field(repr=False, compare=False)
    evidence_class: str = "HISTORICAL_UNTRUSTED"
    requested_effect: str = "NONE"
    authority_granted: bool = False
    may_send_to_model: bool = False


def _plain_text(message: object, remaining_chars: int) -> str:
    """Read only text parts without first joining an unbounded message body."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if not isinstance(parts, list):
        return ""
    chunks: list[str] = []
    used = 0
    for part in parts:
        if not isinstance(part, str):
            continue
        additional = len(part) + (1 if chunks else 0)
        if used + additional > remaining_chars:
            raise RecallFailure("review search exceeds text scan budget")
        chunks.append(part)
        used += additional
    return "\n".join(chunks)


def search_for_owner_review(
    conversation: dict,
    export_sha256: str,
    query: str,
    candidates: Mapping[str, HistoricalCandidate],
    context: OwnerContext,
    *,
    now: datetime,
    active_branch_only: bool = True,
    max_hits: int = 10,
) -> tuple[ReviewHit, ...]:
    """Return bounded, attributed historical excerpts for local owner review.

    One screening decision is required for each candidate node to be shown.
    Unknown, unsigned, foreign-owner, assistant-authored, third-party,
    superseded and otherwise unscreened records are never returned.  This
    method is not an authentication endpoint or a tool/LLM retrieval method.
    """
    if not isinstance(context, OwnerContext) or not context.principal_verified:
        raise RecallFailure("verified principal required")
    if not isinstance(query, str) or not 0 < len(query) <= MAX_QUERY_CHARS or not query.strip():
        raise RecallFailure("nonempty bounded query required")
    if not isinstance(candidates, Mapping):
        raise RecallFailure("external candidate screening required")
    if type(active_branch_only) is not bool or type(max_hits) is not int or not 1 <= max_hits <= MAX_HITS:
        raise RecallFailure("invalid bounded search options")

    # Graph validation occurs before any matching. Invalid graphs require
    # quarantine/review; never synthesize a plausible chronology from a subset.
    graph = derive_graph(conversation, export_sha256)
    if len(graph.nodes) > MAX_SCAN_NODES:
        raise RecallFailure("review search exceeds node scan budget")
    mapping = conversation["mapping"]
    active = set(graph.active_path)
    needle = query.casefold()
    hits: list[ReviewHit] = []
    scanned = 0

    for node in graph.nodes:
        if active_branch_only and node.node_id not in active:
            continue
        if not node.has_message:
            continue
        candidate = candidates.get(node.node_id)
        if not isinstance(candidate, HistoricalCandidate):
            continue
        # Exact source/node attribution is not negotiable.
        if (candidate.export_ref != graph.export_sha256
                or candidate.conversation_ref != graph.conversation_id
                or candidate.message_ref != node.node_id
                or candidate.author_role != node.role):
            continue
        decision = classify_candidate(candidate, context, now=now)
        if decision.disposition != CandidateDisposition.REVIEW_ELIGIBLE:
            continue
        raw_node = mapping[node.node_id]
        content = _plain_text(raw_node.get("message"), MAX_SCAN_CHARS - scanned)
        scanned += len(content)
        if scanned > MAX_SCAN_CHARS:
            raise RecallFailure("review search exceeds text scan budget")
        position = content.casefold().find(needle)
        if position < 0:
            continue
        start = max(0, position - 60)
        excerpt = content[start:start + MAX_SNIPPET_CHARS]
        hits.append(ReviewHit(
            export_sha256=graph.export_sha256,
            conversation_id=graph.conversation_id,
            node_id=node.node_id,
            message_id=node.message_id,
            author_role=node.role or "unknown",
            is_active_branch=node.node_id in active,
            excerpt=excerpt,
        ))
        if len(hits) >= max_hits:
            break
    return tuple(hits)
