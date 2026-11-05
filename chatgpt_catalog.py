"""Bounded, content-free catalog facts derived from one authenticated export record.

This is an *ephemeral structural view*, not an index of private messages or
attachments, a semantic classifier, a memory admission, or an owner-auth API.
The caller is responsible for authenticating the owner and decrypting exactly
one conversation inside the private vault boundary. All source identifiers
remain private. In particular, an opaque multimodal part is **not** evidence
that the original ZIP includes a retrievable matching asset.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from chatgpt_graph import GraphFailure, derive_graph


MAX_CATALOG_PARTS = 100_000
MAX_CATALOG_NODES = 200_000
MAX_ACCOUNT_CATALOG_RECORDS = 50_000
_KNOWN_ROLES = frozenset({"user", "assistant", "system", "developer", "tool"})
_KNOWN_CONTENT_TYPES = frozenset({
    "text", "multimodal_text", "code", "execution_output", "audio",
    "image", "video", "real_time_user_audio_video",
})


class CatalogFailure(ValueError):
    """A source conversation cannot be safely represented as catalog facts."""


@dataclass(frozen=True, repr=False)
class HistoricalCatalog:
    """One source-version's counts, with no private title or message content."""

    export_sha256: str = field(repr=False)
    conversation_id: str = field(repr=False)
    total_nodes: int
    message_nodes: int
    root_nodes: int
    active_path_nodes: int
    inactive_nodes: int
    branch_points: int
    text_parts: int
    opaque_parts: int
    role_counts: tuple[tuple[str, int], ...]
    content_type_counts: tuple[tuple[str, int], ...]
    structural_tags: tuple[str, ...]
    evidence_class: str = "HISTORICAL_UNTRUSTED"
    admission: str = "NOT_ADMITTED"
    requested_effect: str = "NONE"
    authority_granted: bool = False


@dataclass(frozen=True, repr=False)
class AccountCatalogSummary:
    """Ephemeral aggregate: never evidence of independent source coverage."""

    export_sha256: str = field(repr=False)
    conversation_count: int
    total_nodes: int
    message_nodes: int
    inactive_nodes: int
    branching_conversations: int
    opaque_part_conversations: int
    coverage_verified: bool = False
    source_recount_performed: bool = False
    evidence_class: str = "HISTORICAL_UNTRUSTED"
    requested_effect: str = "NONE"
    authority_granted: bool = False


def _bucket(value: str | None, allowed: frozenset[str]) -> str:
    # Export-controlled strings must never become public tag/category keys.
    return value if value in allowed else "other"


def catalog_conversation(conversation: dict, export_sha256: str) -> HistoricalCatalog:
    """Validate the full branch graph and count structure, including inactive edits.

    The graph's current branch is identified by its source ``current_node``;
    timestamps are never used to infer chronology. No source text, title,
    project marker value, part object, asset pointer or metadata is copied.
    The caller must keep even the source IDs within the private boundary.
    """
    try:
        graph = derive_graph(conversation, export_sha256)
    except GraphFailure as exc:
        raise CatalogFailure("invalid source graph") from exc

    message_nodes = 0
    text_parts = 0
    opaque_parts = 0
    observed_parts = 0
    roles: Counter[str] = Counter()
    types: Counter[str] = Counter()
    for node in graph.nodes:
        if not node.has_message:
            continue
        message_nodes += 1
        roles[_bucket(node.role, _KNOWN_ROLES)] += 1
        types[_bucket(node.content_type, _KNOWN_CONTENT_TYPES)] += 1
        message = conversation["mapping"][node.node_id]["message"]
        content = message.get("content")
        if not isinstance(content, dict):
            continue
        parts = content.get("parts")
        if parts is None:
            continue
        if not isinstance(parts, list):
            raise CatalogFailure("unsupported content parts")
        observed_parts += len(parts)
        if observed_parts > MAX_CATALOG_PARTS:
            raise CatalogFailure("structural part budget exceeded")
        for part in parts:
            if isinstance(part, str):
                text_parts += 1
            else:
                # An opaque part is not a verified attachment/asset.
                opaque_parts += 1

    inactive = len(graph.nodes) - len(graph.active_path)
    tags = ["historical-source", "graph-validated", "not-admitted"]
    if any(len(node.children) > 1 for node in graph.nodes):
        tags.append("branching-history")
    if opaque_parts:
        tags.append("opaque-multimodal-parts")
    if graph.current_node is None:
        tags.append("active-path-unknown")

    return HistoricalCatalog(
        export_sha256=graph.export_sha256,
        conversation_id=graph.conversation_id,
        total_nodes=len(graph.nodes),
        message_nodes=message_nodes,
        root_nodes=len(graph.root_ids),
        active_path_nodes=len(graph.active_path),
        inactive_nodes=inactive,
        branch_points=sum(len(node.children) > 1 for node in graph.nodes),
        text_parts=text_parts,
        opaque_parts=opaque_parts,
        role_counts=tuple(sorted(roles.items())),
        content_type_counts=tuple(sorted(types.items())),
        structural_tags=tuple(tags),
    )


def _validate_aggregate_input(entry: HistoricalCatalog, export_sha256: str) -> None:
    """Reject forged or internally inconsistent source-derived catalog records.

    Catalog records are not cryptographic source proof, but an aggregate must
    not silently accept caller-constructed negative counts, injected categories,
    or a modified authority/admission label as if they were derived facts.
    """
    if not isinstance(entry, HistoricalCatalog) or entry.export_sha256 != export_sha256:
        raise CatalogFailure("mixed or invalid source version")
    if not isinstance(entry.conversation_id, str) or not 1 <= len(entry.conversation_id) <= 256:
        raise CatalogFailure("invalid conversation identity")

    counters = (
        entry.total_nodes, entry.message_nodes, entry.root_nodes,
        entry.active_path_nodes, entry.inactive_nodes, entry.branch_points,
        entry.text_parts, entry.opaque_parts,
    )
    if any(type(value) is not int or value < 0 for value in counters):
        raise CatalogFailure("invalid catalog counters")
    if (not 1 <= entry.root_nodes <= entry.total_nodes <= MAX_CATALOG_NODES
            or entry.message_nodes > entry.total_nodes
            or entry.active_path_nodes > entry.total_nodes
            or entry.inactive_nodes != entry.total_nodes - entry.active_path_nodes
            or entry.branch_points > entry.total_nodes
            or entry.text_parts + entry.opaque_parts > MAX_CATALOG_PARTS):
        raise CatalogFailure("inconsistent catalog counters")

    def check_buckets(items: tuple[tuple[str, int], ...], allowed: frozenset[str]) -> bool:
        if not isinstance(items, tuple):
            return False
        accepted = allowed | {"other"}
        if len(items) > len(accepted):
            return False
        if any(not isinstance(pair, tuple) or len(pair) != 2 for pair in items):
            return False
        if any(type(name) is not str or name not in accepted
               or type(number) is not int or number <= 0 for name, number in items):
            return False
        return items == tuple(sorted(items)) and len({name for name, _ in items}) == len(items) \
            and sum(number for _, number in items) == entry.message_nodes

    if not check_buckets(entry.role_counts, _KNOWN_ROLES) or not check_buckets(
        entry.content_type_counts, _KNOWN_CONTENT_TYPES
    ):
        raise CatalogFailure("invalid catalog buckets")

    expected_tags = ["historical-source", "graph-validated", "not-admitted"]
    if entry.branch_points > 0:
        expected_tags.append("branching-history")
    if entry.opaque_parts > 0:
        expected_tags.append("opaque-multimodal-parts")
    if entry.active_path_nodes == 0:
        expected_tags.append("active-path-unknown")
    if (entry.structural_tags != tuple(expected_tags)
            or entry.evidence_class != "HISTORICAL_UNTRUSTED"
            or entry.admission != "NOT_ADMITTED"
            or entry.requested_effect != "NONE"
            or entry.authority_granted is not False):
        raise CatalogFailure("catalog authority or provenance mismatch")


def summarize_catalogs(
    catalogs: Iterable[HistoricalCatalog], export_sha256: str,
) -> AccountCatalogSummary:
    """Aggregate an externally selected set without asserting full archive coverage.

    The caller must separately run an original-ZIP/source-to-index recount to
    qualify completeness. Counting derived records alone cannot prove that a
    conversation was not omitted; matching a caller's expected count is not a
    substitute for independent source reconciliation.
    """
    if not isinstance(export_sha256, str) or len(export_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in export_sha256
    ):
        raise CatalogFailure("invalid source digest")
    count = total = messages = inactive = branching = opaque = 0
    seen_ids: set[str] = set()
    for entry in catalogs:
        count += 1
        if count > MAX_ACCOUNT_CATALOG_RECORDS:
            raise CatalogFailure("account catalog budget exceeded")
        _validate_aggregate_input(entry, export_sha256)
        if entry.conversation_id in seen_ids:
            raise CatalogFailure("duplicate conversation identity")
        seen_ids.add(entry.conversation_id)
        total += entry.total_nodes
        messages += entry.message_nodes
        inactive += entry.inactive_nodes
        branching += int(entry.branch_points > 0)
        opaque += int(entry.opaque_parts > 0)

    return AccountCatalogSummary(
        export_sha256=export_sha256,
        conversation_count=count,
        total_nodes=total,
        message_nodes=messages,
        inactive_nodes=inactive,
        branching_conversations=branching,
        opaque_part_conversations=opaque,
    )
