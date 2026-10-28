"""Opt-in, source-preserving SQLite conversation archive.

This is historical *evidence*, not a replacement for STM's session-local working
memory, an authorization engine, or a trusted instruction channel. The embedding
host must authenticate the principal and provide a fail-closed authorizer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import sqlite3
import stat
from threading import RLock
from typing import Callable
from uuid import uuid4


SCHEMA_VERSION = 1
MAX_CONTENT_BYTES = 262_144
MAX_QUERY_CHARS = 4_096
MAX_QUERY_TERMS = 32
MAX_RESULTS = 100
_TERMS = re.compile(r"\w+", re.UNICODE)


@dataclass(frozen=True, slots=True)
class ArchiveScope:
    tenant_id: str
    owner_id: str
    agent_id: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip()
               for value in (self.tenant_id, self.owner_id, self.agent_id)):
            raise ValueError("all archive scope IDs must be non-empty strings")


@dataclass(frozen=True, slots=True)
class ArchiveTurn:
    turn_id: str
    conversation_id: str
    role: str
    content: str
    source: str
    privacy: str
    event_time: str
    recorded_at: str
    supersedes_id: str | None


@dataclass(frozen=True, slots=True)
class ArchiveHit:
    turn: ArchiveTurn
    score: float


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("archive event times must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _nonblank(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_content(value: str) -> str:
    _nonblank(value, "content")
    if len(value.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError("archive turn exceeds maximum content bytes")
    return value


def _safe_match(query: str) -> str:
    """Map arbitrary user text to quoted FTS5 tokens, never raw MATCH syntax."""
    _nonblank(query, "query")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError("archive query too long")
    terms = _TERMS.findall(query)
    if not terms:
        raise ValueError("query must contain searchable words")
    if len(terms) > MAX_QUERY_TERMS:
        raise ValueError("archive query exceeds maximum search terms")
    # Each token contains only Unicode word characters; quotes make FTS5
    # operators such as OR/NEAR literal words. Deterministic bounded OR recall.
    return " OR ".join('"' + term.replace('"', '""') + '"'
                       for term in terms)


def _check_private_file(path: str) -> bool:
    """Reject symlinks, links, and files accessible to other POSIX users.

    Existing files are never silently chmod'ed: the host must make the
    deliberate recovery/privacy choice before this archive can open them.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"archive file is not a regular file: {path}")
    if info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise PermissionError(f"archive file ownership/link count unsafe: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(f"archive file permissions expose private data: {path}")
    return True


def _prepare_private_sqlite_path(path: str) -> None:
    """Create the main database with 0600 *before* SQLite creates WAL files."""
    if os.name != "posix" or path == ":memory:":
        return
    parent = os.path.dirname(os.path.abspath(path))
    parent_info = os.lstat(parent)
    if (not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022):
        raise PermissionError("archive parent directory must be owned and private to writes")
    for suffix in ("", "-wal", "-shm"):
        _check_private_file(path + suffix)
    if not os.path.lexists(path):
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            # Another opener may have won the race. Validate, never chmod.
            pass
        else:
            os.close(fd)
    if not _check_private_file(path):
        raise PermissionError("archive database must exist as a private regular file")


class ConversationArchive:
    """Transactional conversation ledger with separately authorized cross-chat reads.

    ``authorize(principal, action, scope)`` is supplied by a trusted host. The
    library checks both operation verbs and label-specific ``read_privacy:...`` /
    ``write_privacy:...`` verbs. No default allow policy exists. Scope values
    alone do not authenticate anyone.

    A single archive instance serializes connection operations with a lock;
    SQLite WAL allows concurrent readers in other processes and one writer.
    Call ``close`` before process shutdown. SQLite/WAL/backup artifacts are not
    encrypted or guaranteed forensically erased by this module.
    """

    def __init__(
        self,
        path: str,
        *,
        authorize: Callable[[object, str, ArchiveScope], bool],
    ) -> None:
        if not callable(authorize):
            raise TypeError("a trusted archive authorization callback is required")
        if not isinstance(path, (str, os.PathLike)) or not os.fspath(path):
            raise ValueError("archive path must be non-empty")
        self._authorize_callback = authorize
        self._path = os.fspath(path)
        self._lock = RLock()
        self._closed = False
        self.fts_secure_delete_enabled = False
        _prepare_private_sqlite_path(self._path)
        self._db = sqlite3.connect(self._path, timeout=5.0, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.execute("PRAGMA secure_delete=ON")
            # Avoid spilling private query/FTS material to unencrypted SQLite
            # temporary files. SQLite may still make OS-level swap copies.
            self._db.execute("PRAGMA temp_store=MEMORY")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._init_schema()
            # FTS5 index terms require their *own* secure-delete setting;
            # SQLite's PRAGMA secure_delete alone is insufficient. The FTS5
            # command is not supported by all Python-bundled SQLite versions.
            # This reduces some local remnants but cannot erase prior WAL,
            # backups, snapshots, or storage-device copies.
            try:
                with self._db:
                    self._db.execute(
                        "INSERT INTO turns_fts(turns_fts, rank) "
                        "VALUES ('secure-delete', 1)"
                    )
            except sqlite3.OperationalError:
                self.fts_secure_delete_enabled = False
            else:
                self.fts_secure_delete_enabled = True
            self._check_private_files()
        except BaseException:
            self._db.close()
            raise

    def _init_schema(self) -> None:
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, SCHEMA_VERSION):
            raise RuntimeError(f"unsupported conversation archive schema version {version}")
        with self._db:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS turns (
                    id INTEGER PRIMARY KEY,
                    turn_id TEXT UNIQUE NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    privacy TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    supersedes_id TEXT,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1))
                );
                CREATE INDEX IF NOT EXISTS idx_turns_scope
                ON turns(tenant_id, owner_id, agent_id, active, privacy, event_time);
                CREATE INDEX IF NOT EXISTS idx_turns_supersedes ON turns(supersedes_id);
                CREATE VIRTUAL TABLE IF NOT EXISTS turns_fts
                USING fts5(content, content='turns', content_rowid='id');
                CREATE TRIGGER IF NOT EXISTS turns_ai AFTER INSERT ON turns
                BEGIN
                    INSERT INTO turns_fts(rowid, content) VALUES(new.id, new.content);
                END;
                CREATE TRIGGER IF NOT EXISTS turns_ad AFTER DELETE ON turns
                BEGIN
                    INSERT INTO turns_fts(turns_fts, rowid, content)
                    VALUES('delete', old.id, old.content);
                END;
                CREATE TRIGGER IF NOT EXISTS turns_au AFTER UPDATE OF content ON turns
                BEGIN
                    INSERT INTO turns_fts(turns_fts, rowid, content)
                    VALUES('delete', old.id, old.content);
                    INSERT INTO turns_fts(rowid, content)
                    VALUES(new.id, new.content);
                END;
            """)
            if version == 0:
                self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("conversation archive is closed")
        self._check_private_files()

    def _check_private_files(self) -> None:
        if os.name == "posix" and self._path != ":memory:":
            if not _check_private_file(self._path):
                raise PermissionError("archive database path disappeared")
            for suffix in ("-wal", "-shm"):
                _check_private_file(self._path + suffix)

    def _permission(self, principal: object, scope: ArchiveScope,
                    action: str, privacy: str | None = None) -> None:
        if not isinstance(scope, ArchiveScope) or principal is None:
            raise PermissionError("authenticated archive principal and scope required")
        actions = [action]
        if privacy is not None:
            actions.append(("read_privacy:" if action == "search" else "write_privacy:")
                           + privacy)
        for verb in actions:
            try:
                decision = self._authorize_callback(principal, verb, scope)
            except Exception as error:
                raise PermissionError("archive authorization failed") from error
            if decision is not True:
                raise PermissionError(f"archive authorization denied for {verb}")

    @staticmethod
    def _turn(row: sqlite3.Row) -> ArchiveTurn:
        return ArchiveTurn(
            turn_id=row["turn_id"], conversation_id=row["conversation_id"],
            role=row["role"], content=row["content"], source=row["source"],
            privacy=row["privacy"], event_time=row["event_time"],
            recorded_at=row["recorded_at"], supersedes_id=row["supersedes_id"],
        )

    def _insert(self, scope: ArchiveScope, *, conversation_id: str, role: str,
                content: str, source: str, privacy: str, event_time: str,
                supersedes_id: str | None = None) -> ArchiveTurn:
        uid = uuid4().hex
        recorded = _utc_iso(datetime.now(timezone.utc))
        self._db.execute("""
            INSERT INTO turns (
                turn_id, tenant_id, owner_id, agent_id, conversation_id,
                role, content, source, privacy, event_time, recorded_at,
                supersedes_id, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (uid, scope.tenant_id, scope.owner_id, scope.agent_id,
              conversation_id, role, content, source, privacy,
              event_time, recorded, supersedes_id))
        return ArchiveTurn(uid, conversation_id, role, content, source,
                           privacy, event_time, recorded, supersedes_id)

    def append_turn(
        self,
        principal: object,
        scope: ArchiveScope,
        *,
        conversation_id: str,
        role: str,
        content: str,
        source: str = "conversation",
        privacy: str = "private",
        event_time: datetime | None = None,
    ) -> ArchiveTurn:
        _nonblank(conversation_id, "conversation_id")
        _nonblank(role, "role")
        _nonblank(source, "source")
        _nonblank(privacy, "privacy")
        _validate_content(content)
        when = _utc_iso(event_time or datetime.now(timezone.utc))
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "append", privacy)
            self._db.execute("BEGIN IMMEDIATE")
            with self._db:
                turn = self._insert(scope, conversation_id=conversation_id,
                                    role=role, content=content, source=source,
                                    privacy=privacy, event_time=when)
            self._check_private_files()
            return turn

    def search(
        self,
        principal: object,
        scope: ArchiveScope,
        query: str,
        *,
        privacy_scopes: frozenset[str],
        limit: int = 8,
    ) -> tuple[ArchiveHit, ...]:
        match = _safe_match(query)
        if not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
            raise ValueError("limit must be between 1 and 100")
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes or any(
            not isinstance(item, str) or not item.strip() for item in privacy_scopes
        ):
            raise PermissionError("authorized privacy labels required")
        labels = tuple(sorted(privacy_scopes))
        terms = tuple(dict.fromkeys(term.casefold() for term in _TERMS.findall(query)))
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "search")
            for label in labels:
                self._permission(principal, scope, "search", label)
            placeholders = ",".join("?" for _ in labels)
            # Global bm25() uses corpus-wide document frequencies and can
            # reveal other owners' term prevalence through returned scores.
            # Instead scan authorized matches and rank by exact lexical token
            # overlap, retaining only the top K in Python. No global FTS rank,
            # recency candidate cutoff, or substring match that treats "cat"
            # as a hit for "caterpillar". Query work still grows with the
            # permitted matching corpus; results and Python memory stay bound.
            sql = f"""
                SELECT t.*
                FROM turns_fts JOIN turns AS t ON t.id = turns_fts.rowid
                WHERE turns_fts MATCH ? AND t.active = 1
                  AND t.tenant_id = ? AND t.owner_id = ? AND t.agent_id = ?
                  AND t.privacy IN ({placeholders})
            """
            query_terms = set(terms)
            selected: list[ArchiveHit] = []

            def order(hit: ArchiveHit) -> tuple[float, float, str]:
                # Event times are already normalized to UTC at admission.
                return (-hit.score,
                        -datetime.fromisoformat(hit.turn.event_time).timestamp(),
                        hit.turn.turn_id)

            for row in self._db.execute(sql, (match, scope.tenant_id,
                                              scope.owner_id, scope.agent_id, *labels)):
                turn = self._turn(row)
                content_terms = set(_TERMS.findall(turn.content.casefold()))
                item = ArchiveHit(turn, float(len(query_terms & content_terms)))
                selected.append(item)
                selected.sort(key=order)
                if len(selected) > limit:
                    selected.pop()
            return tuple(selected)

    def _get_row(self, scope: ArchiveScope, turn_id: str) -> sqlite3.Row | None:
        return self._db.execute("""
            SELECT * FROM turns WHERE turn_id = ?
            AND tenant_id = ? AND owner_id = ? AND agent_id = ?
        """, (turn_id, scope.tenant_id, scope.owner_id, scope.agent_id)).fetchone()

    def correct(self, principal: object, scope: ArchiveScope,
                turn_id: str, content: str) -> ArchiveTurn:
        _nonblank(turn_id, "turn_id")
        _validate_content(content)
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "correct")
            # Serialize the active-version check and successor insertion across
            # *different* SQLite connections, not only this instance's lock.
            self._db.execute("BEGIN IMMEDIATE")
            with self._db:
                previous = self._get_row(scope, turn_id)
                if previous is None or previous["active"] != 1:
                    raise KeyError(turn_id)
                self._permission(principal, scope, "correct", previous["privacy"])
                result = self._db.execute(
                    "UPDATE turns SET active=0 WHERE id=? AND active=1",
                    (previous["id"],),
                )
                if result.rowcount != 1:
                    raise RuntimeError("archive correction lost its active-version race")
                turn = self._insert(
                    scope, conversation_id=previous["conversation_id"],
                    role=previous["role"], content=content,
                    source=previous["source"], privacy=previous["privacy"],
                    event_time=_utc_iso(datetime.now(timezone.utc)),
                    supersedes_id=turn_id,
                )
            self._check_private_files()
            return turn

    def delete(self, principal: object, scope: ArchiveScope, turn_id: str) -> bool:
        _nonblank(turn_id, "turn_id")
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "delete")
            self._db.execute("BEGIN IMMEDIATE")
            with self._db:
                row = self._get_row(scope, turn_id)
                if row is None:
                    return False
                # A correction is derived from an older version. Erasing any
                # ancestor therefore removes its complete descendant chain.
                descendants = self._db.execute("""
                    WITH RECURSIVE chain(turn_id) AS (
                        SELECT turn_id FROM turns WHERE turn_id=?
                          AND tenant_id=? AND owner_id=? AND agent_id=?
                        UNION
                        SELECT child.turn_id FROM turns AS child
                        JOIN chain AS parent ON child.supersedes_id=parent.turn_id
                        WHERE child.tenant_id=? AND child.owner_id=? AND child.agent_id=?
                    )
                    SELECT t.id, t.privacy FROM turns t
                    JOIN chain ON t.turn_id=chain.turn_id
                """, (turn_id, scope.tenant_id, scope.owner_id, scope.agent_id,
                      scope.tenant_id, scope.owner_id, scope.agent_id)).fetchall()
                for candidate in descendants:
                    self._permission(principal, scope, "delete", candidate["privacy"])
                for candidate in descendants:
                    self._db.execute("DELETE FROM turns WHERE id=?", (candidate["id"],))
            self._check_private_files()
            return True

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> "ConversationArchive":
        self._check_open()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


__all__ = ["ArchiveScope", "ArchiveTurn", "ArchiveHit", "ConversationArchive"]
