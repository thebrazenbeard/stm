"""Bounded, session-isolated short-term storage with optional JSON checkpoints.

This is working memory, not an autobiographical/historical-memory authority.
No network, vector database, model runtime, or external service is involved.

The same :class:`SessionKey` must be supplied for every read and mutation;
there is no cross-session scan API. Pinned items resist capacity eviction but
are subject to explicit deletion and their declared expiration time.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import mkstemp
from threading import RLock
from typing import Callable

from .models import CapacityExceeded, MemoryRecord, SessionKey, VersionConflict, utc_now
from datetime import datetime


_SCHEMA = "stm-session-checkpoint-v1"
_RECORD_FIELDS = frozenset(
    {"id", "scope", "content", "role", "source", "kind", "privacy", "pinned",
     "created_at", "updated_at", "expires_at", "version", "origin"}
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _scope_dict(scope: SessionKey) -> dict[str, str]:
    return {"tenant_id": scope.tenant_id, "owner_id": scope.owner_id,
            "agent_id": scope.agent_id, "session_id": scope.session_id}


def _record_dict(record: MemoryRecord) -> dict[str, object]:
    return {
        "id": record.id, "scope": _scope_dict(record.scope),
        "content": record.content, "role": record.role, "source": record.source,
        "kind": record.kind, "privacy": record.privacy, "pinned": record.pinned,
        "origin": record.origin,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "version": record.version,
    }


def _decode_record(row: object, expected_scope: SessionKey) -> MemoryRecord:
    if not isinstance(row, dict) or set(row) != _RECORD_FIELDS:
        raise ValueError("checkpoint has malformed memory fields")
    if row["scope"] != _scope_dict(expected_scope):
        raise PermissionError("checkpoint record belongs to a different scope")
    if not isinstance(row["pinned"], bool) or not isinstance(row["version"], int):
        raise ValueError("checkpoint has malformed memory types")
    try:
        record = MemoryRecord(
            id=row["id"], scope=expected_scope, content=row["content"],
            role=row["role"], source=row["source"], kind=row["kind"],
            privacy=row["privacy"], pinned=row["pinned"], origin=row["origin"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            expires_at=(datetime.fromisoformat(row["expires_at"])
                        if row["expires_at"] is not None else None),
            version=row["version"],
        )
    except (TypeError, KeyError, ValueError) as error:
        raise ValueError("checkpoint has invalid memory values") from error
    if record.updated_at < record.created_at:
        raise ValueError("checkpoint record update predates its creation")
    return record


class InMemoryStore:
    """Thread-safe storage with deterministic oldest-created unpinned eviction.

    ``max_items_per_session`` and ``max_sessions`` bound record allocations.
    Session quotas are exact across tenant, owner, agent, and session IDs.
    Admission fails closed when every candidate is pinned. Deletion and
    correction are explicit, version-checked operations.

    Each API call is atomic within this process; this is not a multi-process
    shared store. Checkpoints are opt-in and save sensitive content to disk.
    Only use private, access-controlled paths. In-memory deletion does not
    erase previously created checkpoint files.
    """

    def __init__(
        self,
        *,
        max_items_per_session: int = 256,
        max_sessions: int = 128,
        clock: Callable[[], datetime] = utc_now,
        max_checkpoint_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_items_per_session < 1 or max_sessions < 1 or max_checkpoint_bytes < 1:
            raise ValueError("capacity bounds must be positive")
        self.max_items_per_session = max_items_per_session
        self.max_sessions = max_sessions
        self.max_checkpoint_bytes = max_checkpoint_bytes
        self._clock = clock
        self._records: dict[SessionKey, dict[str, MemoryRecord]] = {}
        self._lock = RLock()
        self._evictions: dict[SessionKey, int] = {}
        self._expirations: dict[SessionKey, int] = {}

    def _purge_locked(self, scope: SessionKey, now: datetime) -> int:
        bucket = self._records.get(scope)
        if not bucket:
            return 0
        expired = [key for key, value in bucket.items() if value.is_expired(now)]
        for key in expired:
            del bucket[key]
        if expired:
            self._expirations[scope] = self._expirations.get(scope, 0) + len(expired)
        if not bucket:
            del self._records[scope]
        return len(expired)

    def _make_room_locked(self, scope: SessionKey) -> None:
        bucket = self._records.get(scope)
        if bucket is None:
            if len(self._records) >= self.max_sessions:
                # Release sessions whose entire contents have expired.
                for other in list(self._records):
                    self._purge_locked(other, self._clock())
            if len(self._records) >= self.max_sessions:
                raise CapacityExceeded("maximum concurrent sessions reached")
            self._records[scope] = {}
            return
        if len(bucket) < self.max_items_per_session:
            return
        candidates = [record for record in bucket.values() if not record.pinned]
        if not candidates:
            raise CapacityExceeded("session capacity reached; all entries are pinned")
        victim = min(candidates, key=lambda record: (record.created_at, record.id))
        del bucket[victim.id]
        self._evictions[scope] = self._evictions.get(scope, 0) + 1

    def add(self, record: MemoryRecord) -> None:
        with self._lock:
            now = self._clock()
            if record.is_expired(now):
                raise ValueError("cannot admit already expired memory")
            self._purge_locked(record.scope, now)
            if record.id in self._records.get(record.scope, {}):
                raise ValueError("duplicate memory id in session")
            self._make_room_locked(record.scope)
            self._records[record.scope][record.id] = record

    def get(
        self, scope: SessionKey, record_id: str, now: datetime | None = None
    ) -> MemoryRecord | None:
        with self._lock:
            self._purge_locked(scope, now or self._clock())
            return self._records.get(scope, {}).get(record_id)

    def list(self, scope: SessionKey, now: datetime | None = None) -> list[MemoryRecord]:
        with self._lock:
            self._purge_locked(scope, now or self._clock())
            return sorted(self._records.get(scope, {}).values(),
                          key=lambda record: (record.created_at, record.id))

    def replace(
        self, scope: SessionKey, record: MemoryRecord, expected_version: int
    ) -> None:
        if scope != record.scope:
            raise PermissionError("cross-session correction denied")
        with self._lock:
            self._purge_locked(scope, self._clock())
            previous = self._records.get(scope, {}).get(record.id)
            if previous is None:
                raise KeyError(record.id)
            if previous.version != expected_version:
                raise VersionConflict("memory version changed before correction")
            if record.version != expected_version + 1:
                raise VersionConflict("correction version must increment exactly once")
            if record.created_at != previous.created_at or record.updated_at < previous.updated_at:
                raise ValueError("correction must preserve creation and monotonic update time")
            if any(getattr(record, field) != getattr(previous, field) for field in (
                "role", "source", "kind", "privacy", "pinned", "expires_at", "origin"
            )):
                raise ValueError("correction cannot silently change provenance or policy")
            if record.is_expired(self._clock()):
                raise ValueError("cannot replace with already expired memory")
            self._records[scope][record.id] = record

    def delete(self, scope: SessionKey, record_id: str) -> bool:
        with self._lock:
            self._purge_locked(scope, self._clock())
            bucket = self._records.get(scope)
            if bucket is None or record_id not in bucket:
                return False
            del bucket[record_id]
            if not bucket:
                del self._records[scope]
            return True

    def prune(self, scope: SessionKey, now: datetime | None = None) -> int:
        with self._lock:
            return self._purge_locked(scope, now or self._clock())

    def clear(self, scope: SessionKey) -> int:
        """Explicitly delete a whole session, without touching other sessions."""
        with self._lock:
            bucket = self._records.pop(scope, {})
            return len(bucket)

    def stats(self, scope: SessionKey) -> dict[str, int]:
        with self._lock:
            self._purge_locked(scope, self._clock())
            bucket = self._records.get(scope, {})
            return {
                "items": len(bucket),
                "pinned": sum(record.pinned for record in bucket.values()),
                "evictions": self._evictions.get(scope, 0),
                "expirations": self._expirations.get(scope, 0),
                "max_items": self.max_items_per_session,
                "active_sessions": len(self._records),
            }

    def checkpoint(
        self, scope: SessionKey, path: str | os.PathLike[str], *, overwrite: bool = False
    ) -> str:
        """Atomically write a private, checksummed JSON snapshot for one scope.

        The target parent directory must already exist. A target file is not
        overwritten without explicit ``overwrite=True``. ``fsync`` and atomic
        rename protect against partial file replacement on common local filesystems.
        There is no confidentiality guarantee on an unencrypted disk.
        """
        destination = Path(path)
        if destination.is_symlink():
            raise ValueError("checkpoint target may not be a symlink")
        if destination.exists() and not overwrite:
            raise FileExistsError(destination)
        if not destination.parent.is_dir():
            raise FileNotFoundError(destination.parent)
        with self._lock:
            self._purge_locked(scope, self._clock())
            rows = [_record_dict(record) for record in self.list(scope)]
        body = {"schema": _SCHEMA, "scope": _scope_dict(scope), "records": rows}
        digest = hashlib.sha256(_json_bytes(body)).hexdigest()
        content = _json_bytes({"body": body, "sha256": digest})
        if len(content) > self.max_checkpoint_bytes:
            raise CapacityExceeded("checkpoint exceeds configured byte limit")

        temp_path: str | None = None
        try:
            fd, temp_path = mkstemp(prefix=f".{destination.name}.", suffix=".tmp",
                                    dir=destination.parent)
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            # Recheck to avoid silently crossing an ordinary path replacement.
            if destination.exists() and not overwrite:
                raise FileExistsError(destination)
            os.replace(temp_path, destination)
            temp_path = None
            try:
                dir_fd = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass  # Some filesystems do not support directory fsync.
        finally:
            if temp_path is not None:
                os.unlink(temp_path)
        return digest

    def restore(
        self,
        scope: SessionKey,
        path: str | os.PathLike[str],
        *,
        overwrite: bool = False,
        now: datetime | None = None,
    ) -> int:
        """Validate the whole snapshot, then atomically restore one session.

        Scope mismatch, malformed checksum/schema, duplicate IDs, capacity
        overflow, or invalid timestamps reject *before* any mutation. Expired
        rows are discarded on recovery, including pinned rows.
        """
        source = Path(path)
        if source.is_symlink():
            raise ValueError("restore source may not be a symlink")
        with source.open("rb") as stream:
            raw = stream.read(self.max_checkpoint_bytes + 1)
        if len(raw) > self.max_checkpoint_bytes:
            raise CapacityExceeded("checkpoint exceeds configured byte limit")
        try:
            envelope = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("invalid checkpoint JSON") from error
        if not isinstance(envelope, dict) or set(envelope) != {"body", "sha256"}:
            raise ValueError("malformed checkpoint envelope")
        body = envelope["body"]
        if not isinstance(body, dict) or set(body) != {"schema", "scope", "records"}:
            raise ValueError("malformed checkpoint body")
        if body["schema"] != _SCHEMA:
            raise ValueError("unsupported checkpoint schema")
        if body["scope"] != _scope_dict(scope):
            raise PermissionError("checkpoint belongs to a different session")
        if not isinstance(envelope["sha256"], str) or (
            hashlib.sha256(_json_bytes(body)).hexdigest() != envelope["sha256"]
        ):
            raise ValueError("checkpoint checksum mismatch")
        if not isinstance(body["records"], list):
            raise ValueError("checkpoint records must be a list")
        if len(body["records"]) > self.max_items_per_session:
            raise CapacityExceeded("checkpoint exceeds per-session item capacity")
        timestamp = now or self._clock()
        recovered: dict[str, MemoryRecord] = {}
        for row in body["records"]:
            record = _decode_record(row, scope)
            if record.id in recovered:
                raise ValueError("duplicate checkpoint memory id")
            recovered[record.id] = record
        recovered = {key: record for key, record in recovered.items()
                     if not record.is_expired(timestamp)}

        with self._lock:
            self._purge_locked(scope, timestamp)
            if self._records.get(scope) and not overwrite:
                raise FileExistsError("session already has records; pass overwrite=True")
            if recovered and scope not in self._records and len(self._records) >= self.max_sessions:
                raise CapacityExceeded("maximum concurrent sessions reached")
            if recovered:
                self._records[scope] = recovered
            else:
                self._records.pop(scope, None)
        return len(recovered)
