"""Encrypted, append-only Vera phone chat history on the local operator's machine.

This stores transcript evidence, not model memories or instructions. No network,
agent effects, semantic promotion, or automatic collection from ChatGPT.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SESSION = re.compile(r"[a-zA-Z0-9_-]{16,128}\Z")
_REQUEST = re.compile(r"[a-zA-Z0-9_-]{16,128}\Z")
_AAD = b"stm.vera_phone_journal.v1\x00"
_MAX_MESSAGE = 4096
_MAX_MODEL = 128


class JournalError(ValueError):
    pass


class EncryptedJournal:
    """Encrypted-at-rest authenticated turn log, with idempotent request IDs.

    Caller MUST supply existing 32-byte key file, stored privately outside repo.
    This class never creates keys, and never writes plaintext prompts into SQLite.
    """

    def __init__(self, database_path: str | Path, key_file: str | Path):
        self.database_path = Path(database_path)
        self.key_file = Path(key_file)
        if not self.key_file.is_file() or self.key_file.is_symlink():
            raise JournalError("encryption key file missing or unsafe")
        key = self.key_file.read_bytes()
        if len(key) != 32:
            raise JournalError("journal key must have 32 raw bytes")
        if not self.database_path.parent.is_dir() or self.database_path.is_symlink():
            raise JournalError("database parent missing or unsafe")
        if self.database_path.exists() and not self.database_path.is_file():
            raise JournalError("database path not a regular file")
        self._key = key
        self._cipher = AESGCM(key)
        self._lock = threading.RLock()
        with closing(self._connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS turns (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    sealed BLOB NOT NULL,
                    binding BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS turns_session_seq ON turns(session_id, sequence);
            """)

    def _connect(self):
        if self.database_path.is_symlink():
            raise JournalError("database symlink refused")
        db = sqlite3.connect(str(self.database_path), timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    @staticmethod
    def _validate_id(value: str, pattern: re.Pattern, name: str) -> None:
        if type(value) is not str or not pattern.fullmatch(value):
            raise JournalError("invalid " + name)

    @staticmethod
    def _validate_text(value: str, max_chars: int, name: str) -> None:
        if type(value) is not str or not 1 <= len(value) <= max_chars:
            raise JournalError("invalid " + name)

    def _data(self, session_id, request_id, model, user, assistant):
        self._validate_id(session_id, _SESSION, "session")
        self._validate_id(request_id, _REQUEST, "request")
        for value, bound, name in (
            (model, _MAX_MODEL, "model"), (user, _MAX_MESSAGE, "user"),
            (assistant, 16000, "assistant"),
        ):
            self._validate_text(value, bound, name)
        return json.dumps({"model": model, "user": user, "assistant": assistant},
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _aad(self, session_id, request_id):
        return _AAD + session_id.encode("ascii") + b"\x00" + request_id.encode("ascii")

    def _binding(self, session_id, request_id, data):
        return hmac.digest(self._key, self._aad(session_id, request_id) + b"\x00" + data, "sha256")

    def append_turn(self, session_id: str, request_id: str, model: str,
                    user: str, assistant: str) -> int:
        raw = self._data(session_id, request_id, model, user, assistant)
        fingerprint = self._binding(session_id, request_id, raw)
        nonce = os.urandom(12)
        wrapped = nonce + self._cipher.encrypt(nonce, raw, self._aad(session_id, request_id))
        with self._lock, closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                old = db.execute("SELECT sequence,session_id,binding FROM turns WHERE request_id=?",
                                 (request_id,)).fetchone()
                if old is not None:
                    if old[1] == session_id and hmac.compare_digest(old[2], fingerprint):
                        db.commit()
                        return old[0]
                    raise JournalError("request ID replay conflict")
                stamp = datetime.now(timezone.utc).isoformat()
                cursor = db.execute("INSERT INTO turns (session_id,request_id,sealed,binding,created_at) "
                                    "VALUES (?,?,?,?,?)",
                                    (session_id, request_id, wrapped, fingerprint, stamp))
                db.commit()
                return int(cursor.lastrowid)
            except Exception:
                db.rollback()
                raise

    def get_request(self, session_id: str, request_id: str):
        """Authenticated replay lookup by original request ID, never a history search."""
        self._validate_id(session_id, _SESSION, "session")
        self._validate_id(request_id, _REQUEST, "request")
        with self._lock, closing(self._connect()) as db:
            row = db.execute("SELECT session_id,sealed,binding,created_at FROM turns "
                             "WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        stored_session, sealed, fingerprint, stamp = row
        if stored_session != session_id:
            raise JournalError("request ID belongs to another session")
        try:
            if not isinstance(sealed, bytes) or len(sealed) < 29:
                raise JournalError("invalid encrypted turn")
            raw = self._cipher.decrypt(sealed[:12], sealed[12:],
                                       self._aad(session_id, request_id))
            if not hmac.compare_digest(
                    self._binding(session_id, request_id, raw), fingerprint):
                raise JournalError("request integrity invalid")
            payload = json.loads(raw)
            self._data(session_id, request_id, payload["model"],
                       payload["user"], payload["assistant"])
        except Exception as exc:
            raise JournalError("request authentication failed") from exc
        return {"request_id": request_id, "model": payload["model"],
                "user": payload["user"], "assistant": payload["assistant"],
                "created_at": stamp}

    def recent(self, session_id: str, limit: int = 10, max_bytes: int = 16000):
        self._validate_id(session_id, _SESSION, "session")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise JournalError("invalid recent limit")
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 65536:
            raise JournalError("invalid byte budget")
        with self._lock, closing(self._connect()) as db:
            rows = db.execute("SELECT request_id,sealed,binding,created_at FROM turns "
                              "WHERE session_id=? ORDER BY sequence DESC LIMIT ?",
                              (session_id, limit)).fetchall()
        chosen, remaining = [], max_bytes
        for request_id, sealed, fingerprint, stamp in rows:
            try:
                if type(sealed) is not bytes or len(sealed) < 29:
                    raise JournalError("invalid sealed transcript")
                data = self._cipher.decrypt(sealed[:12], sealed[12:],
                                            self._aad(session_id, request_id))
                if not hmac.compare_digest(
                        self._binding(session_id, request_id, data), fingerprint):
                    raise JournalError("journal integrity error")
                payload = json.loads(data)
                self._data(session_id, request_id, payload["model"],
                           payload["user"], payload["assistant"])
            except Exception as exc:
                raise JournalError("journal authentication failed") from exc
            if len(data) > remaining:
                break
            remaining -= len(data)
            chosen.append({"request_id": request_id, "model": payload["model"],
                           "user": payload["user"], "assistant": payload["assistant"],
                           "created_at": stamp})
        return list(reversed(chosen))

    def count(self, session_id: str):
        self._validate_id(session_id, _SESSION, "session")
        with self._lock, closing(self._connect()) as db:
            return db.execute("SELECT COUNT(*) FROM turns WHERE session_id=?",
                              (session_id,)).fetchone()[0]

    def delete_session(self, session_id: str):
        """Explicit local owner action only. Does not erase external backups."""
        self._validate_id(session_id, _SESSION, "session")
        with self._lock, closing(self._connect()) as db, db:
            return db.execute("DELETE FROM turns WHERE session_id=?", (session_id,)).rowcount
