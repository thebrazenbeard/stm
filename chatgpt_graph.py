"""In-memory, non-authoritative graph view of an encrypted ChatGPT export.

This module accepts a conversation already authenticated and decrypted by the
private archive owner.  It never opens a file, creates an index, calls a model,
or persists plaintext.  All nodes, including inactive edit/regeneration
branches and null-message roots, are represented.  Original content remains
in the authenticated encrypted source rather than being duplicated here.

IMPORTANT: Role, timestamps and metadata originate in historical, untrusted
export data; they are provenance, not live instructions or permissions.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import re
from typing import Any


_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_MAX_NODES = 200_000


class GraphFailure(ValueError):
    """Graph derivation cannot establish complete, coherent lineage."""


@dataclass(frozen=True, repr=False)
class HistoricalNode:
    """Source pointer, graph links, and untrusted metadata; no message body."""

    export_sha256: str
    conversation_id: str
    node_id: str
    parent_id: str | None
    children: tuple[str, ...]
    has_message: bool
    message_id: str | None
    role: str | None
    recipient: str | None
    content_type: str | None
    event_time_raw: Any = field(repr=False, compare=False)
    update_time_raw: Any = field(repr=False, compare=False)
    message_metadata: dict[str, Any] = field(repr=False, compare=False)
    node_metadata: dict[str, Any] = field(repr=False, compare=False)
    evidence_class: str = "HISTORICAL_UNTRUSTED"
    requested_effect: str = "NONE"
    authority_granted: bool = False


@dataclass(frozen=True, repr=False)
class HistoricalGraph:
    """One version of a conversation graph, not a memory admission."""

    export_sha256: str
    conversation_id: str
    nodes: tuple[HistoricalNode, ...]
    root_ids: tuple[str, ...]
    current_node: str | None
    active_path: tuple[str, ...]
    evidence_class: str = "HISTORICAL_UNTRUSTED"
    requested_effect: str = "NONE"
    authority_granted: bool = False


def _string_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 0 < len(value) <= 512:
        raise GraphFailure(f"invalid {label}")
    return value


def _metadata(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise GraphFailure(f"invalid {label}")
    return deepcopy(value)


def derive_graph(conversation: dict[str, Any], export_sha256: str) -> HistoricalGraph:
    """Project every graph node without treating old text as current truth.

    Consumers must authorize use of the decrypted input and keep the returned
    metadata private.  No content parts are copied into the result; to retrieve
    an exact message, resolve its source IDs through the authenticated archive.
    A corrupt graph fails closed and should be quarantined, not repaired by
    guessing chronology or choosing a different current node.
    """
    if not isinstance(conversation, dict):
        raise GraphFailure("invalid conversation object")
    if not isinstance(export_sha256, str) or not _SHA256.fullmatch(export_sha256):
        raise GraphFailure("invalid export digest")
    conversation_id = conversation.get("id", conversation.get("conversation_id"))
    if not isinstance(conversation_id, str) or not 0 < len(conversation_id) <= 256:
        raise GraphFailure("invalid conversation identity")
    mapping = conversation.get("mapping")
    if not isinstance(mapping, dict) or not mapping:
        raise GraphFailure("missing or unsupported message graph")
    if len(mapping) > _MAX_NODES:
        raise GraphFailure("graph exceeds bounded node budget")

    records: dict[str, HistoricalNode] = {}
    for node_id, raw_node in mapping.items():
        if not isinstance(node_id, str) or not 0 < len(node_id) <= 512:
            raise GraphFailure("invalid node key")
        if not isinstance(raw_node, dict):
            raise GraphFailure("invalid node")
        declared_id = raw_node.get("id")
        if declared_id is not None and declared_id != node_id:
            raise GraphFailure("node identity mismatch")
        parent_id = _string_or_none(raw_node.get("parent"), "parent")
        raw_children = raw_node.get("children", [])
        if not isinstance(raw_children, list):
            raise GraphFailure("invalid children list")
        children = tuple(_string_or_none(child, "child") for child in raw_children)
        if any(child is None for child in children) or len(set(children)) != len(children):
            raise GraphFailure("invalid or duplicate child")

        message = raw_node.get("message")
        if message is not None and not isinstance(message, dict):
            raise GraphFailure("invalid message")
        author = message.get("author") if message is not None else None
        if author is not None and not isinstance(author, dict):
            raise GraphFailure("invalid author")
        content = message.get("content") if message is not None else None
        if content is not None and not isinstance(content, dict):
            raise GraphFailure("invalid message content type")
        records[node_id] = HistoricalNode(
            export_sha256=export_sha256,
            conversation_id=conversation_id,
            node_id=node_id,
            parent_id=parent_id,
            children=children,
            has_message=message is not None,
            message_id=_string_or_none(message.get("id") if message else None, "message id"),
            role=_string_or_none(author.get("role") if author else None, "author role"),
            recipient=_string_or_none(message.get("recipient") if message else None, "recipient"),
            content_type=_string_or_none(content.get("content_type") if content else None, "content type"),
            event_time_raw=deepcopy(message.get("create_time") if message else None),
            update_time_raw=deepcopy(message.get("update_time") if message else None),
            message_metadata=_metadata(message.get("metadata") if message else None, "message metadata"),
            node_metadata=_metadata(raw_node.get("metadata"), "node metadata"),
        )

    for node in records.values():
        if node.parent_id is not None:
            if node.parent_id not in records:
                raise GraphFailure("missing parent node")
            if node.node_id not in records[node.parent_id].children:
                raise GraphFailure("parent/child mismatch")
        for child_id in node.children:
            if child_id not in records:
                raise GraphFailure("missing child node")
            if records[child_id].parent_id != node.node_id:
                raise GraphFailure("child/parent mismatch")

    # Walk each parent chain at most once. This detects cycles even in an
    # inactive branch, without recursion or quadratic traversal.
    validated: set[str] = set()
    for start in records:
        if start in validated:
            continue
        visiting: set[str] = set()
        chain: list[str] = []
        node_id: str | None = start
        while node_id is not None and node_id not in validated:
            if node_id in visiting:
                raise GraphFailure("cyclic message graph")
            visiting.add(node_id)
            chain.append(node_id)
            node_id = records[node_id].parent_id
        validated.update(chain)

    current_node = _string_or_none(conversation.get("current_node"), "current node")
    active: list[str] = []
    if current_node is not None:
        if current_node not in records:
            raise GraphFailure("current node not present")
        cursor: str | None = current_node
        while cursor is not None:
            active.append(cursor)
            cursor = records[cursor].parent_id
        active.reverse()

    roots = tuple(node_id for node_id, node in records.items() if node.parent_id is None)
    return HistoricalGraph(
        export_sha256=export_sha256,
        conversation_id=conversation_id,
        nodes=tuple(records.values()),
        root_ids=roots,
        current_node=current_node,
        active_path=tuple(active),
    )
