"""Narrow, opt-in management of *known* local SQLite archive derivatives.

This is a whole-database operator-owned backup vault, not a tenant-filtered
export, filesystem-wide erasure, encryption, or a service. A trusted host must
authenticate the principal and separately authorize ARCHIVE-WIDE backup
creation. Every SQLite snapshot includes ALL tenants and privacy labels in the
database. Only POSIX 0700 vaults are qualified here; Windows ACLs need a
separate implementation. Removing a file does NOT guarantee forensic erase.

See https://www.sqlite.org/backup.html and https://www.sqlite.org/pragma.html
for SQLite online backup and WAL checkpoint behavior.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from tempfile import NamedTemporaryFile
from typing import Callable, Iterator
from urllib.parse import quote
from uuid import uuid4

from .archive import ArchiveScope
from .retention import RetentionPolicy


_BACKUP = re.compile(r"stm-backup-[0-9a-f]{32}\.sqlite3\Z")
_CATALOG = "stm-backup-index.json"
_LOCK = "stm-backup-index.lock"


def _now(moment: datetime | None) -> datetime:
    chosen = moment or datetime.now(timezone.utc)
    if not isinstance(chosen, datetime) or chosen.tzinfo is None or chosen.utcoffset() is None:
        raise ValueError("time must be timezone-aware")
    return chosen.astimezone(timezone.utc)


def _posix() -> None:
    if os.name != "posix":
        raise NotImplementedError("local backup privacy is not qualified for this OS ACL model")


def _private_dir(path: Path) -> None:
    _posix()
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError("backup vault must be an owned private directory (0700)")


def _private_file(path: Path) -> None:
    _posix()
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError("backup artifact must be an owned private regular file (0600)")


def _digest(path: Path) -> str:
    _private_file(path)
    hashed = sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) & 0o077):
            raise PermissionError("backup artifact changed during opening")
        with os.fdopen(fd, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(131072), b""):
                hashed.update(chunk)
    finally:
        os.close(fd)
    return hashed.hexdigest()


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    name: str
    created_at: str
    expires_at: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BackupInventory:
    managed: tuple[BackupReceipt, ...]
    unmanaged_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackupRetirement:
    due: int
    removed: int
    dry_run: bool
    remaining: int
    complete: bool


@dataclass(frozen=True, slots=True)
class WalCheckpoint:
    busy: int
    log_pages: int
    checkpointed_pages: int


class ManagedArchiveBackupVault:
    """Create, inventory and retire *only* explicitly registered snapshots.

    Important: the source SQLite file may contain multiple owners and agents.
    The standard SQLite online backup API copies the ENTIRE database, without
    tenant filtering. Every operation on a whole-database snapshot therefore
    requires a distinct ``..._all_scopes`` administrator permission that
    ordinary per-scope archive authority MUST NOT grant. The vault must be
    host-admin owned and never exposed to a signed-in conversation user.

    A new vault path is never created implicitly, nor is any unknown file
    removed. A temporary exclusive index lock refuses a simultaneous process;
    a stale lock after a crash requires deliberate host recovery. A caller
    cannot supply deletion paths or bypass source-scoped authorization.
    """

    def __init__(self, directory: str | os.PathLike[str], *,
                 archive_path: str | os.PathLike[str],
                 scope: ArchiveScope, policy: RetentionPolicy,
                 authorize: Callable[[object, str, ArchiveScope], bool]) -> None:
        if not isinstance(scope, ArchiveScope) or not isinstance(policy, RetentionPolicy):
            raise TypeError("authenticated host scope and explicit retention policy required")
        if not callable(authorize):
            raise TypeError("trusted backup authorizer required")
        folder = Path(directory)
        source = Path(archive_path)
        if not folder.is_absolute() or not source.is_absolute():
            raise ValueError("backup vault and source paths must be absolute")
        self._directory = folder
        self._source = source
        self._scope = scope
        self._policy = policy
        self._authorize = authorize
        _private_dir(folder)
        _private_file(source)
        if folder == source.parent:
            raise ValueError("backup vault must be separate from the active SQLite directory")

    def _permission(self, principal: object, verb: str) -> None:
        if principal is None:
            raise PermissionError("authenticated backup principal required")
        try:
            allowed = self._authorize(principal, verb, self._scope)
        except Exception as exc:
            raise PermissionError("backup authorization failed") from exc
        if allowed is not True:
            raise PermissionError("backup authorization denied")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        _private_dir(self._directory)
        lock_path = self._directory / _LOCK
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("backup vault is busy or has an unresolved stale lock") from exc
        try:
            yield
        finally:
            os.close(fd)
            # Only this call created the lock; it is a single known vault path.
            os.unlink(lock_path)

    def _read(self) -> list[BackupReceipt]:
        path = self._directory / _CATALOG
        if not path.exists():
            if any(self._directory.iterdir()):
                # A lock file is expected inside an active _locked context.
                unexpected = [item.name for item in self._directory.iterdir()
                              if item.name != _LOCK]
                if unexpected:
                    raise RuntimeError("uninitialized nonempty backup vault requires operator review")
            return []
        _private_file(path)
        with path.open("r", encoding="utf-8") as source:
            doc = json.load(source)
        if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("entries"), list):
            raise ValueError("unsupported or corrupt backup manifest")
        entries: list[BackupReceipt] = []
        names: set[str] = set()
        for entry in doc["entries"]:
            if not isinstance(entry, dict) or set(entry) != set(BackupReceipt.__dataclass_fields__):
                raise ValueError("malformed backup manifest entry")
            record = BackupReceipt(**entry)
            if (not _BACKUP.fullmatch(record.name) or record.name in names
                    or not isinstance(record.bytes, int) or record.bytes < 0
                    or not isinstance(record.sha256, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", record.sha256)):
                raise ValueError("invalid backup manifest entry")
            _now(datetime.fromisoformat(record.created_at))
            _now(datetime.fromisoformat(record.expires_at))
            names.add(record.name)
            entries.append(record)
        return entries

    def _write(self, records: list[BackupReceipt]) -> None:
        payload = json.dumps({"version": 1, "entries": [
            {field: getattr(record, field) for field in BackupReceipt.__dataclass_fields__}
            for record in records
        ]}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with NamedTemporaryFile(mode="wb", dir=self._directory, prefix="stm-index-",
                                delete=False) as output:
            temp_path = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.replace(temp_path, self._directory / _CATALOG)
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def create(self, principal: object, *, retention: timedelta,
               now: datetime | None = None) -> BackupReceipt:
        self._permission(principal, "backup_create")
        # A scope-local grant is insufficient: SQLite backup() includes every
        # tenant/owner/agent row sharing this database. Require a distinct
        # archive-wide administrator capability *before any file is created*.
        self._permission(principal, "backup_create_all_scopes")
        if not isinstance(retention, timedelta) or not (
            timedelta(0) < retention <= self._policy.maximum_age
        ):
            raise ValueError("backup retention must be positive within host policy")
        instant = max(_now(now), datetime.now(timezone.utc))
        name = f"stm-backup-{uuid4().hex}.sqlite3"
        destination = self._directory / name
        with self._locked():
            records = self._read()
            _private_file(self._source)
            source_uri = f"file:{quote(str(self._source), safe='/')}?mode=ro"
            # Reject KNOWN ineligible source data before creating any new
            # plaintext copy. The post-copy check below remains mandatory
            # because a concurrent writer may change the source in between.
            with closing(sqlite3.connect(source_uri, uri=True)) as preflight:
                self._bounded_snapshot_deadline(preflight, instant, retention)
            fd = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
            try:
                with closing(sqlite3.connect(source_uri, uri=True)) as source:
                    with closing(sqlite3.connect(destination)) as target:
                        source.backup(target)
                        # The backup API copies the ENTIRE multi-tenant store.
                        # A newly minted backup cannot silently extend any
                        # contained record's existing retention deadline.
                        # Legacy NULL retention must be handled by an explicit
                        # source migration/erasure decision before archiving.
                        earliest = self._bounded_snapshot_deadline(target, instant, retention)
                _private_file(destination)
                receipt = BackupReceipt(name, instant.isoformat(),
                                        earliest.isoformat(),
                                        destination.stat().st_size, _digest(destination))
                self._write([*records, receipt])
            except BaseException:
                # A failed backup created by this exact operation may be
                # incomplete; remove it before dropping the vault lock.
                if destination.exists():
                    _private_file(destination)
                    destination.unlink()
                raise
            return receipt

    @staticmethod
    def _bounded_snapshot_deadline(connection: sqlite3.Connection,
                                   instant: datetime,
                                   retention: timedelta) -> datetime:
        """Reject policyless/expired content, bound backup by earliest turn."""
        earliest = instant + retention
        for (raw_expiry,) in connection.execute("SELECT expires_at FROM turns"):
            if raw_expiry is None:
                raise PermissionError("source contains policyless records; refuse backup")
            try:
                record_expiry = _now(datetime.fromisoformat(raw_expiry))
            except (ValueError, TypeError) as exc:
                raise PermissionError("invalid source record expiry") from exc
            if record_expiry <= instant:
                raise PermissionError("source contains expired unswept records; refuse backup")
            earliest = min(earliest, record_expiry)
        return earliest

    def inventory(self, principal: object) -> BackupInventory:
        self._permission(principal, "backup_list")
        self._permission(principal, "backup_list_all_scopes")
        with self._locked():
            records = self._read()
            registered = {record.name for record in records}
            unmanaged = sorted(item.name for item in self._directory.iterdir()
                               if item.name not in registered | {_CATALOG, _LOCK})
            return BackupInventory(tuple(records), tuple(unmanaged))

    def retire_due(self, principal: object, *, now: datetime | None = None,
                   dry_run: bool = True, limit: int = 100) -> BackupRetirement:
        self._permission(principal, "backup_retire")
        self._permission(principal, "backup_retire_all_scopes")
        if not isinstance(dry_run, bool) or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("dry_run must be bool and limit must be 1..100")
        # Never permit clock rollback to indefinitely defer expiry or
        # cause inconsistent counting across independently hosted operations.
        instant = max(_now(now), datetime.now(timezone.utc))
        with self._locked():
            records = self._read()
            eligible = [record for record in records
                        if datetime.fromisoformat(record.expires_at) <= instant]
            return self._retire_selected(records, eligible[:limit],
                                         eligible_count=len(eligible), dry_run=dry_run)

    def retire_all(self, principal: object, *, reason: str,
                   dry_run: bool = True, limit: int = 100) -> BackupRetirement:
        """Purge known snapshots on a source deletion/consent policy event.

        An SQLite snapshot cannot safely remove one private turn in place.
        To honor a deletion request, the host must explicitly invalidate all
        snapshots containing that turn and any unrelated external copies.
        This operation is NOT automatically hooked to archive.delete().
        """
        self._permission(principal, "backup_retire")
        self._permission(principal, "backup_retire_all_scopes")
        if reason not in {"source_turn_deleted", "consent_revoked", "policy_changed"}:
            raise ValueError("recognized source deletion or policy reason required")
        if not isinstance(dry_run, bool) or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("dry_run must be bool and limit must be 1..100")
        with self._locked():
            records = self._read()
            return self._retire_selected(records, records[:limit],
                                         eligible_count=len(records), dry_run=dry_run)

    def _retire_selected(self, records: list[BackupReceipt],
                         selected: list[BackupReceipt], *,
                         eligible_count: int, dry_run: bool) -> BackupRetirement:
        # "complete" refers ONLY to *registered managed* snapshots, never
        # unknown external copies. A partial batch must never certify that a
        # deletion/consent-revocation cleanup has finished.
        if dry_run:
            return BackupRetirement(len(selected), 0, True,
                                    eligible_count, eligible_count == 0)
        # Preflight every target before unlinking *any* of them. A swapped or
        # modified file blocks the operation without a partial cleanup.
        for record in selected:
            path = self._directory / record.name
            if path.exists() or path.is_symlink():
                _private_file(path)
                if _digest(path) != record.sha256:
                    raise PermissionError("registered backup differs from original receipt")
        for record in selected:
            path = self._directory / record.name
            if path.exists() or path.is_symlink():
                path.unlink()
        selected_names = {record.name for record in selected}
        self._write([record for record in records if record.name not in selected_names])
        remaining = eligible_count - len(selected)
        return BackupRetirement(len(selected), len(selected), False,
                                remaining, remaining == 0)

    def checkpoint_wal(self, principal: object) -> WalCheckpoint:
        """Attempt TRUNCATE checkpoint; busy is failure, not evidence of erasure.

        Checkpointing merges committed frames into main DB, so it is **not**
        secure deletion. A running writer may recreate WAL immediately.
        """
        self._permission(principal, "wal_checkpoint")
        self._permission(principal, "wal_checkpoint_all_scopes")
        with self._locked():
            _private_file(self._source)
            # Explicit mode=rw refuses to create a fresh empty DB if another
            # process removes the source between validation and opening.
            source_uri = f"file:{quote(str(self._source), safe='/')}?mode=rw"
            with closing(sqlite3.connect(source_uri, uri=True, timeout=2.0)) as connection:
                row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if row is None or len(row) != 3:
                raise RuntimeError("SQLite returned no WAL checkpoint receipt")
            receipt = WalCheckpoint(int(row[0]), int(row[1]), int(row[2]))
            if receipt.busy:
                raise RuntimeError("SQLite WAL checkpoint was blocked by active readers or writers")
            _private_file(self._source)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self._source) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    _private_file(sidecar)
            return receipt


__all__ = [
    "BackupReceipt", "BackupInventory", "BackupRetirement", "WalCheckpoint",
    "ManagedArchiveBackupVault",
]
