"""Independent, streaming source-to-index coverage audit for ChatGPT exports.

This is deliberately distinct from ChatGPTArchive.verify(), which authenticates
the encrypted source copy and the indexed ciphertext but cannot establish that
every source conversation still exists in the index if its counters were altered.

Run only on a user-selected original ZIP on the private host.  No message text,
conversation identifiers, or fingerprints are logged or returned.  This helper
does not write to the vault, repair an import, or confer memory authority.
"""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import hmac
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure, _SHA


def verify_source_index(
    archive: ChatGPTArchive, original_zip_path: str | Path, export_sha: str
) -> dict[str, int | bool]:
    """Reconcile every original conversation with the private SQLite index.

    Uses bounded one-object-at-a-time JSON parsing and indexed lookups.  The
    archive's authenticated ``verify()`` is an *additional* requirement for a
    complete cryptographic qualification: this audit does not itself decrypt
    the encrypted ZIP copy or all sealed conversation objects.

    Two full source hashes (before and after the ZIP scan) make mid-scan source
    changes detectable.  This is an intentionally expensive, opt-in evidence
    check, not something to run for every local recall.
    """
    if not isinstance(archive, ChatGPTArchive):
        raise TypeError("authenticated archive object required")
    if not isinstance(export_sha, str) or not _SHA.fullmatch(export_sha):
        raise ImportFailure("invalid source fingerprint")

    candidate = Path(original_zip_path)
    if candidate.is_symlink():
        raise ImportFailure("source ZIP symlink refused")
    try:
        source = candidate.resolve(strict=True)
    except OSError as exc:
        raise ImportFailure("original ZIP is unavailable") from exc
    if not source.is_file() or not zipfile.is_zipfile(source):
        raise ImportFailure("original source must be a valid ZIP")

    first_sha, first_size = archive._source_digest(source)
    if not hmac.compare_digest(first_sha, export_sha):
        raise ImportFailure("original source fingerprint mismatched")

    # The digest map only holds HMAC tokens and digests, never message bodies.
    seen: dict[str, bytes] = {}
    row_count = 0
    duplicate_count = 0
    node_count = 0
    part_count = 0
    try:
        with zipfile.ZipFile(source) as source_zip, closing(archive._db()) as db:
            members = archive._safe_zip_members(source_zip)
            parts = archive._parts(source_zip, members)
            part_count = len(parts)
            db.execute("BEGIN")  # One read-only snapshot for the whole recount.
            recorded = db.execute(
                "SELECT input_bytes,part_files,source_rows,unique_conversations,"
                "duplicate_rows,message_nodes FROM imports WHERE export_sha=?",
                (export_sha,),
            ).fetchone()
            if recorded is None:
                raise ImportFailure("source export is absent from index")
            if recorded[0] != first_size:
                raise ImportFailure("recorded source size mismatched")

            for part in parts:
                for conversation in archive._records(source_zip, part):
                    row_count += 1
                    cid = conversation.get("id", conversation.get("conversation_id"))
                    if not isinstance(cid, str) or not 1 <= len(cid) <= 256:
                        raise ImportFailure("original source contains invalid conversation ID")
                    raw = archive._serialize(conversation)
                    token = archive._id_token(cid)
                    digest = archive._digest(raw)
                    previously_seen = seen.get(token)
                    if previously_seen is not None:
                        if not hmac.compare_digest(previously_seen, digest):
                            raise ImportFailure("original source has conflicting conversation ID")
                        duplicate_count += 1
                        continue
                    seen[token] = digest
                    indexed = db.execute(
                        "SELECT digest FROM conversations WHERE export_sha=? "
                        "AND conversation_token=?", (export_sha, token)
                    ).fetchone()
                    if indexed is None or not isinstance(indexed[0], bytes) or not hmac.compare_digest(indexed[0], digest):
                        raise ImportFailure("source conversation absent or changed in index")
                    mapping = conversation.get("mapping")
                    if isinstance(mapping, dict):
                        node_count += sum(
                            1 for node in mapping.values()
                            if isinstance(node, dict) and node.get("message") is not None
                        )
                    elif isinstance(conversation.get("messages"), list):
                        node_count += len(conversation["messages"])

            unique = len(seen)
            if row_count == 0 or row_count != unique + duplicate_count:
                raise ImportFailure("original source row reconciliation failed")
            index_count = db.execute(
                "SELECT COUNT(*) FROM conversations WHERE export_sha=?",
                (export_sha,),
            ).fetchone()[0]
            if index_count != unique:
                raise ImportFailure("index contains missing or extra conversations")
            if (recorded[1:] != (part_count, row_count, unique, duplicate_count, node_count)):
                raise ImportFailure("recorded source coverage counters mismatched")
    except ImportFailure:
        raise
    except Exception as exc:
        # Do not echo a private member path, message, or parser error detail.
        raise ImportFailure("original conversation source could not be recounted") from exc

    second_sha, second_size = archive._source_digest(source)
    if second_size != first_size or not hmac.compare_digest(second_sha, export_sha):
        raise ImportFailure("original source changed during recount")
    return {
        "source_reconciled": True,
        "part_files": part_count,
        "source_rows": row_count,
        "unique_conversations": len(seen),
        "duplicate_rows": duplicate_count,
        "message_nodes": node_count,
    }
