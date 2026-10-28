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


SCHEMA_VERSION = 2
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
    expires_at: str | None = None


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
        require_fts_secure_delete: bool = False,
    ) -> None:
        if not callable(authorize):
            raise TypeError("a trusted archive authorization callback is required")
        if not isinstance(require_fts_secure_delete, bool):
            raise TypeError("require_fts_secure_delete must be a bool")
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
            # FTS5 secure-delete is NOT safe merely because a SQLite version
            # accepts its configuration command. SQLite 3.45.1 accepts it but
            # our external-content deletion/integrity regression corrupts its
            # inverted index; 3.53.1 passed the same regression. Until more
            # builds are qualified, enable only on the verified 3.53.1+ range.
            # The strict flag prevents a host from unknowingly weakening its
            # retention policy when running an older SQLite build.
            if sqlite3.sqlite_version_info >= (3, 53, 1):
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
            if require_fts_secure_delete and not self.fts_secure_delete_enabled:
                raise RuntimeError(
                    "FTS5 secure-delete is not qualified on this SQLite build; "
                    "use a verified newer SQLite or refuse archival retention"
                )
            self._check_private_files()
        except BaseException:
            self._db.close()
            raise

    def _init_schema(self) -> None:
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, 1, SCHEMA_VERSION):
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
                    expires_at TEXT,
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
                -- FTS5 external-content delete must see the old content row.
                -- Remove the earlier AFTER triggers when reopening a v0.2
                -- prototype database so the new trigger order is unambiguous.
                DROP TRIGGER IF EXISTS turns_ad;
                DROP TRIGGER IF EXISTS turns_au;
                CREATE TRIGGER IF NOT EXISTS turns_bd BEFORE DELETE ON turns
                BEGIN
                    INSERT INTO turns_fts(turns_fts, rowid, content)
                    VALUES('delete', old.id, old.content);
                END;
                CREATE TRIGGER IF NOT EXISTS turns_bu BEFORE UPDATE OF content ON turns
                BEGIN
                    INSERT INTO turns_fts(turns_fts, rowid, content)
                    VALUES('delete', old.id, old.content);
                END;
                CREATE TRIGGER IF NOT EXISTS turns_au AFTER UPDATE OF content ON turns
                BEGIN
                    INSERT INTO turns_fts(rowid, content)
                    VALUES(new.id, new.content);
                END;
            """)
            # executescript commits implicitly. Start a new explicit SQLite
            # transaction so ALTER + index + user_version cannot tear across
            # an interruption. Also tolerate a field present from an older
            # interrupted prototype with an unbumped user_version.
            self._db.execute("BEGIN IMMEDIATE")
            if version == 1:
                # Old rows intentionally have no invented expiry timestamp.
                columns = {row["name"] for row in self._db.execute("PRAGMA table_info(turns)")}
                if "expires_at" not in columns:
                    self._db.execute("ALTER TABLE turns ADD COLUMN expires_at TEXT")
            self._db.execute("""
                CREATE INDEX IF NOT EXISTS idx_turns_expiration
                ON turns(tenant_id, owner_id, agent_id, expires_at)
            """)
            if version != SCHEMA_VERSION:
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
            expires_at=row["expires_at"],
        )

    def _insert(self, scope: ArchiveScope, *, conversation_id: str, role: str,
                content: str, source: str, privacy: str, event_time: str,
                supersedes_id: str | None = None,
                expires_at: str | None = None) -> ArchiveTurn:
        uid = uuid4().hex
        recorded = _utc_iso(datetime.now(timezone.utc))
        self._db.execute("""
            INSERT INTO turns (
                turn_id, tenant_id, owner_id, agent_id, conversation_id,
                role, content, source, privacy, event_time, recorded_at,
                supersedes_id, expires_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (uid, scope.tenant_id, scope.owner_id, scope.agent_id,
              conversation_id, role, content, source, privacy,
              event_time, recorded, supersedes_id, expires_at))
        return ArchiveTurn(uid, conversation_id, role, content, source,
                           privacy, event_time, recorded, supersedes_id,
                           expires_at)

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
        expires_at: datetime | None = None,
    ) -> ArchiveTurn:
        _nonblank(conversation_id, "conversation_id")
        _nonblank(role, "role")
        _nonblank(source, "source")
        _nonblank(privacy, "privacy")
        _validate_content(content)
        when = _utc_iso(event_time or datetime.now(timezone.utc))
        expiry = _utc_iso(expires_at) if expires_at is not None else None
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "append", privacy)
            self._db.execute("BEGIN IMMEDIATE")
            with self._db:
                turn = self._insert(scope, conversation_id=conversation_id,
                                    role=role, content=content, source=source,
                                    privacy=privacy, event_time=when,
                                    expires_at=expiry)
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
        require_expiration: bool = False,
        now: datetime | None = None,
    ) -> tuple[ArchiveHit, ...]:
        match = _safe_match(query)
        if not isinstance(require_expiration, bool):
            raise TypeError("require_expiration must be a bool")
        # A supplied test/host clock may run ahead, but must never roll
        # retrieval backward and resurrect logically expired rows. Enforce
        # at least the local wall clock as a lower bound.
        system_now = datetime.now(timezone.utc)
        requested_now = now or system_now
        if requested_now.tzinfo is None or requested_now.utcoffset() is None:
            raise ValueError("search time must be timezone-aware")
        cutoff = _utc_iso(max(requested_now.astimezone(timezone.utc), system_now))
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
                  AND (t.expires_at IS NULL OR t.expires_at > ?)
                  AND (? = 0 OR t.expires_at IS NOT NULL)
            """
            query_terms = set(terms)
            selected: list[ArchiveHit] = []

            def order(hit: ArchiveHit) -> tuple[float, float, str]:
                # Event times are already normalized to UTC at admission.
                return (-hit.score,
                        -datetime.fromisoformat(hit.turn.event_time).timestamp(),
                        hit.turn.turn_id)

            for row in self._db.execute(sql, (match, scope.tenant_id,
                                              scope.owner_id, scope.agent_id, *labels,
                                              cutoff,
                                              int(require_expiration))):
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
                    # A correction is not new retention consent and cannot
                    # reset the ancestor's expiration clock.
                    expires_at=previous["expires_at"],
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

    def expire_due(
        self,
        principal: object,
        scope: ArchiveScope,
        *,
        now: datetime | None = None,
        privacy_scopes: frozenset[str],
        limit: int = 100,
        dry_run: bool = False,
    ) -> int:
        """Remove up to ``limit`` expired turns in one authorized transaction.

        Only explicitly expiring, authorized rows inside ``scope`` qualify.
        Inherited expiry on corrections prevents retention-window extension.
        This is logical deletion from SQLite/FTS, NOT a forensic guarantee:
        WAL, old backups, filesystem snapshots and other copies need separate
        host-side retention controls. Dry-run returns a bounded count only.
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("expiry batch limit must be between 1 and 1000")
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be bool")
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes or any(
            not isinstance(label, str) or not label.strip()
            for label in privacy_scopes
        ):
            raise PermissionError("explicit expiry privacy labels required")
        # Maintenance must not postpone required erasure when a host clock
        # rolls backward. Keep the same monotone-to-wall floor as reads.
        system_now = datetime.now(timezone.utc)
        requested_now = now or system_now
        if requested_now.tzinfo is None or requested_now.utcoffset() is None:
            raise ValueError("expiry sweep time must be timezone-aware")
        cutoff = _utc_iso(max(requested_now.astimezone(timezone.utc), system_now))
        labels = tuple(sorted(privacy_scopes))
        with self._lock:
            self._check_open()
            # Maintenance expiry is deliberately a *narrower* authority than
            # delete(turn_id). A scheduled cleanup service must not acquire
            # unrestricted hard-deletion rights over unexpired conversations.
            self._permission(principal, scope, "expire")
            for label in labels:
                self._permission(principal, scope, "expire", label)
            placeholders = ",".join("?" for _ in labels)
            sql = f"""
                SELECT id, privacy FROM turns
                WHERE tenant_id=? AND owner_id=? AND agent_id=?
                  AND expires_at IS NOT NULL AND expires_at <= ?
                  AND privacy IN ({placeholders})
                ORDER BY expires_at, id LIMIT ?
            """
            if not dry_run:
                self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute(sql, (
                    scope.tenant_id, scope.owner_id, scope.agent_id,
                    cutoff, *labels, limit,
                )).fetchall()
                if not dry_run:
                    with self._db:
                        for row in rows:
                            self._db.execute("DELETE FROM turns WHERE id=?", (row["id"],))
            except BaseException:
                if not dry_run and self._db.in_transaction:
                    self._db.rollback()
                raise
            self._check_private_files()
            return len(rows)

    def has_legacy_unretained(
        self,
        principal: object,
        scope: ArchiveScope,
        *,
        privacy_scopes: frozenset[str],
    ) -> bool:
        """Audit only whether policyless rows remain in a scoped archive.

        A maintenance runner MUST NOT certify full managed retention while
        legacy NULL-expiry records remain. The host grants a distinct
        ``audit_legacy`` verb; this returns no content or record identifiers.
        Neither consent revocation nor expiry service authority authorizes
        automatically deleting these historical rows.
        """
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes or any(
            not isinstance(label, str) or not label.strip()
            for label in privacy_scopes
        ):
            raise PermissionError("explicit legacy audit privacy labels required")
        labels = tuple(sorted(privacy_scopes))
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "audit_legacy")
            for label in labels:
                self._permission(principal, scope, "audit_legacy", label)
            placeholders = ",".join("?" for _ in labels)
            row = self._db.execute(f"""
                SELECT 1 FROM turns
                WHERE tenant_id=? AND owner_id=? AND agent_id=?
                  AND expires_at IS NULL AND privacy IN ({placeholders})
                LIMIT 1
            """, (scope.tenant_id, scope.owner_id, scope.agent_id,
                  *labels)).fetchone()
            return row is not None

    def purge_legacy_unretained(
        self,
        principal: object,
        scope: ArchiveScope,
        *,
        privacy_scopes: frozenset[str],
        limit: int = 100,
        dry_run: bool = True,
    ) -> int:
        """Explicitly dispose of **policyless** pre-v0.3 rows in one scope.

        Migration never invents consent or a TTL for rows with null expiry.
        This separate opt-in operation requires an additional host
        ``delete_legacy`` authority. It is intentionally a dry run by default,
        and does not remove old copies in WAL, backups or source journals.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("legacy purge batch must be between 1 and 1000")
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be bool")
        if not isinstance(privacy_scopes, frozenset) or not privacy_scopes or any(
            not isinstance(label, str) or not label.strip()
            for label in privacy_scopes
        ):
            raise PermissionError("explicit legacy purge privacy labels required")
        labels = tuple(sorted(privacy_scopes))
        with self._lock:
            self._check_open()
            self._permission(principal, scope, "delete")
            self._permission(principal, scope, "delete_legacy")
            for label in labels:
                self._permission(principal, scope, "delete", label)
                self._permission(principal, scope, "delete_legacy", label)
            placeholders = ",".join("?" for _ in labels)
            sql = f"""
                SELECT id FROM turns
                WHERE tenant_id=? AND owner_id=? AND agent_id=?
                  AND expires_at IS NULL AND privacy IN ({placeholders})
                ORDER BY id LIMIT ?
            """
            if not dry_run:
                self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute(sql, (
                    scope.tenant_id, scope.owner_id, scope.agent_id,
                    *labels, limit,
                )).fetchall()
                if not dry_run:
                    with self._db:
                        for row in rows:
                            self._db.execute("DELETE FROM turns WHERE id=?", (row["id"],))
            except BaseException:
                if not dry_run and self._db.in_transaction:
                    self._db.rollback()
                raise
            self._check_private_files()
            return len(rows)

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
