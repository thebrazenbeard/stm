"""Opt-in durable single-use STM replay ledger, backed by a host anchor.

This is a source adapter for HmacConversationBroker(consume_jti=...). It is NOT
an OS-authenticated host service. The supplied anchor must be provisioned and
protected independently from this SQLite file; a cloneable in-process fake is
only suitable for tests. Do not activate private-memory use merely because
these source tests pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Protocol
import hashlib
import hmac
import json
import re
import sqlite3
import time


GENESIS = "0" * 64
_IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_JTI = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ROOT = re.compile(r"^[0-9a-f]{64}$")
_MAX_SCOPE_CONSUMPTIONS = 10_000


class HostMonotonicAnchor(Protocol):
    """Host-provided CAS; injection alone cannot authenticate its ownership."""

    def current(self, scope: str) -> tuple[int, str] | None: ...

    def claim_provisioning(self, scope: str) -> bool: ...

    def compare_advance(self, scope: str, epoch: int,
                        prior_root: str, next_root: str) -> bool: ...


class HostAnchoredJtiConsumer:
    """Cross-reader atomic JTI consumption with explicit external anchoring.

    A trusted host must construct this with a private HMAC key, authenticated
    principal/host identity and a genuinely nonrollbackable anchor. Never
    accept these parameters from the user or a model-generated tool call.

    SQLite restoration with an intact independent anchor is rejected; rollback
    of both stores is *not* prevented by this source module.
    """

    def __init__(self, ledger_path: str | Path, *, anchor: HostMonotonicAnchor,
                 host_id: str, issuer: str, principal_id: str, digest_key: bytes,
                 clock: Callable[[], int] | None = None) -> None:
        for identity in (host_id, issuer, principal_id):
            if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
                raise ValueError("invalid host replay identity")
        if not isinstance(digest_key, bytes) or len(digest_key) < 32:
            raise ValueError("host-held JTI digest key must be at least 256 bits")
        if not callable(getattr(anchor, "current", None)) or not callable(
            getattr(anchor, "claim_provisioning", None)
        ) or not callable(getattr(anchor, "compare_advance", None)):
            raise TypeError("host monotonic anchor protocol required")
        self.path = Path(ledger_path)
        self.anchor = anchor
        self.host_id = host_id
        self.issuer = issuer
        self.principal_id = principal_id
        self.scope = f"stm:{host_id}:{issuer}:{principal_id}"
        self._digest_key = digest_key
        self._key_id = hmac.new(
            digest_key, b"stm-replay-key-id-v1\0" + self.scope.encode("utf-8"),
            hashlib.sha256).hexdigest()
        self._clock = clock or (lambda: int(time.time()))
        if not callable(self._clock):
            raise TypeError("host replay clock must be callable")

    def provision_new(self) -> None:
        """Provision ONCE. Reopening a deleted ledger must never recreate it."""
        if self.path.exists() or self.path.is_symlink():
            raise PermissionError("replay ledger already exists")
        available, current = self._anchor_call("current", self.scope)
        if not available or current != (0, GENESIS):
            raise PermissionError("host replay anchor not independently provisioned")
        available, claimed = self._anchor_call("claim_provisioning", self.scope)
        if not available or claimed is not True:
            raise PermissionError("replay ledger provision already consumed")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), "
                       "epoch INTEGER NOT NULL, root TEXT NOT NULL, key_id TEXT NOT NULL)")
            db.execute("CREATE TABLE consumed (jti_mac TEXT PRIMARY KEY, epoch INTEGER NOT NULL)")
            db.execute("INSERT INTO checkpoint (id,epoch,root,key_id) VALUES (1,0,?,?)",
                       (GENESIS, self._key_id))
            db.commit()
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()

    def _anchor_call(self, operation: str, *args: object) -> tuple[bool, object]:
        """Bound denials without retaining provider exception details in callers."""
        try:
            return True, getattr(self.anchor, operation)(*args)
        except Exception:
            return False, None

    def _membership_root(self, db: sqlite3.Connection, epoch: int) -> str:
        """Commit the entire spent-JTI set to the externally anchored root.

        Recomputing it is deliberately bounded and conservative: deleting or
        editing a spent row must invalidate the existing external checkpoint.
        """
        rows = db.execute("SELECT jti_mac,epoch FROM consumed ORDER BY jti_mac").fetchall()
        if (len(rows) != epoch or len(rows) > _MAX_SCOPE_CONSUMPTIONS
                or any(not isinstance(jti, str) or _ROOT.fullmatch(jti) is None
                       or type(spent_epoch) is not int or not 1 <= spent_epoch <= epoch
                       for jti, spent_epoch in rows)):
            raise PermissionError("replay membership checkpoint is inconsistent")
        if epoch == 0:
            return GENESIS
        payload = json.dumps({"version": 1, "key_id": self._key_id, "rows": rows},
                             ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def __call__(self, issuer: str, subject: str,
                 token_id: str, expires_at_unix: int) -> bool:
        """Return True exactly once; unsafe/unavailable state denies or raises.

        This callback is invoked only *after* the broker verifies the HMAC,
        channel binding, expiry and durable revocation. The host must still
        re-check revocation at final release of protected data.
        """
        try:
            now = self._clock()
        except Exception:
            now = None
        if now is None:
            raise PermissionError("trusted replay clock unavailable")
        if (issuer != self.issuer or not isinstance(subject, str)
                or not 0 < len(subject) <= 256
                or not isinstance(token_id, str) or not _JTI.fullmatch(token_id)
                or type(expires_at_unix) is not int or type(now) is not int
                or not now < expires_at_unix <= now + 300):
            return False
        try:
            fingerprint = hmac.new(self._digest_key,
                                   (issuer + "\0" + subject + "\0" + token_id).encode("utf-8"),
                                   hashlib.sha256).hexdigest()
        except (UnicodeError, ValueError):
            return False
        if not self.path.is_file() or self.path.is_symlink():
            raise PermissionError("provisioned replay ledger missing")
        db = sqlite3.connect(str(self.path), timeout=2, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT epoch,root,key_id FROM checkpoint WHERE id=1").fetchone()
            available, remote_state = self._anchor_call("current", self.scope)
            if (row is None or type(row[0]) is not int or row[0] < 0
                    or not isinstance(row[1], str) or _ROOT.fullmatch(row[1]) is None
                    or not isinstance(row[2], str)
                    or not hmac.compare_digest(row[2], self._key_id)
                    or self._membership_root(db, row[0]) != row[1]
                    or not available or remote_state != (row[0], row[1])):
                raise PermissionError("external replay anchor mismatch")
            if db.execute("SELECT 1 FROM consumed WHERE jti_mac=?", (fingerprint,)).fetchone():
                return False
            db.execute("INSERT INTO consumed (jti_mac,epoch) VALUES (?,?)",
                       (fingerprint, row[0] + 1))
            next_root = self._membership_root(db, row[0] + 1)
            available, advanced = self._anchor_call(
                "compare_advance", self.scope, row[0], row[1], next_root)
            if not available or advanced is not True:
                raise PermissionError("external monotonic CAS rejected")
            db.execute("UPDATE checkpoint SET epoch=?,root=? WHERE id=1", (row[0] + 1, next_root))
            db.commit()
            return True
        except sqlite3.DatabaseError as error:
            raise PermissionError("durable replay ledger unavailable") from error
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()


__all__ = ["GENESIS", "HostMonotonicAnchor", "HostAnchoredJtiConsumer"]
