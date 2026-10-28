"""Real SQLite regressions for scoped, durable conversation-archive expiry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from stm.archive import ArchiveScope, ConversationArchive


WHEN = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
ALICE = ArchiveScope("local", "alice", "vera")
BOB = ArchiveScope("local", "bob", "vera")
PRIVATE = frozenset({"private"})


class ArchiveRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "archive.sqlite")
        self.db = ConversationArchive(self.path, authorize=lambda *_: True)

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def append(self, scope: ArchiveScope, content: str, expiry: datetime | None):
        return self.db.append_turn(
            "verified-host", scope, conversation_id="chat", role="user",
            content=content, privacy="private", expires_at=expiry,
        )

    def test_expired_turn_never_retrieved_even_without_a_sweep(self) -> None:
        expired = self.append(ALICE, "expired sapphire detail", WHEN)
        live = self.append(ALICE, "live sapphire detail", WHEN + timedelta(days=100))
        hits = self.db.search("verified-host", ALICE, "sapphire",
                              privacy_scopes=PRIVATE)
        self.assertEqual([h.turn.turn_id for h in hits], [live.turn_id])
        self.assertEqual(expired.expires_at, WHEN.isoformat())

    def test_dry_run_scoped_sweep_restart_and_fts_integrity(self) -> None:
        first = self.append(ALICE, "expired lavender one", WHEN)
        self.append(ALICE, "expired lavender two", WHEN)
        self.append(ALICE, "fresh lavender three", WHEN + timedelta(days=100))
        self.append(BOB, "expired lavender bob", WHEN)
        self.append(ALICE, "legacy lavender no expiry", None)
        cutoff = WHEN + timedelta(days=1)
        self.assertEqual(self.db.expire_due("host", ALICE, now=cutoff,
                                           privacy_scopes=PRIVATE, dry_run=True), 2)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM turns").fetchone()[0], 5)
        self.assertEqual(self.db.expire_due("host", ALICE, now=cutoff,
                                           privacy_scopes=PRIVATE, limit=1), 1)
        self.assertEqual(self.db.expire_due("host", ALICE, now=cutoff,
                                           privacy_scopes=PRIVATE), 1)
        self.assertEqual(self.db.expire_due("host", ALICE, now=cutoff,
                                           privacy_scopes=PRIVATE), 0)
        self.db.close()
        self.db = ConversationArchive(self.path, authorize=lambda *_: True)
        self.assertFalse(self.db.delete("host", ALICE, first.turn_id))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM turns").fetchone()[0], 3)
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_corrections_inherit_original_expiration(self) -> None:
        initial = self.append(ALICE, "original violet mark", WHEN + timedelta(days=5))
        corrected = self.db.correct("host", ALICE, initial.turn_id, "corrected violet mark")
        self.assertEqual(corrected.expires_at, initial.expires_at)
        self.assertEqual(self.db.expire_due("host", ALICE, now=WHEN + timedelta(days=6),
                                           privacy_scopes=PRIVATE), 2)
        self.assertEqual(self.db.search("host", ALICE, "violet", privacy_scopes=PRIVATE), ())

    def test_denied_label_and_scope_do_not_delete_other_data(self) -> None:
        record = self.append(BOB, "secret indigo point", WHEN)
        with ConversationArchive(self.path, authorize=lambda p, a, s: s.owner_id == "alice") as gated:
            self.assertEqual(gated.expire_due("host", ALICE, now=WHEN + timedelta(days=1),
                                              privacy_scopes=PRIVATE), 0)
            with self.assertRaises(PermissionError):
                gated.expire_due("host", BOB, now=WHEN + timedelta(days=1),
                                 privacy_scopes=PRIVATE)
            with self.assertRaises(PermissionError):
                gated.expire_due("host", ALICE, now=WHEN + timedelta(days=1),
                                 privacy_scopes=frozenset())
        self.assertTrue(self.db.delete("host", BOB, record.turn_id))

    def test_reject_naive_expiry_and_unbounded_batch(self) -> None:
        with self.assertRaises(ValueError):
            self.append(ALICE, "time vague", datetime(2026, 10, 28))
        with self.assertRaises(ValueError):
            self.db.expire_due("host", ALICE, privacy_scopes=PRIVATE, limit=1001)

    def test_existing_v1_schema_migrates_without_fabricated_ttl(self) -> None:
        legacy = str(Path(self.tmp.name) / "legacy.sqlite")
        with sqlite3.connect(legacy) as connection:
            connection.execute("""CREATE TABLE turns (
                id INTEGER PRIMARY KEY, turn_id TEXT UNIQUE NOT NULL,
                tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL,
                source TEXT NOT NULL, privacy TEXT NOT NULL, event_time TEXT NOT NULL,
                recorded_at TEXT NOT NULL, supersedes_id TEXT,
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1))
            )""")
            connection.execute("PRAGMA user_version=1")
        if os.name == "posix":
            os.chmod(legacy, 0o600)
        with ConversationArchive(legacy, authorize=lambda *_: True) as migrated:
            self.assertEqual(migrated._db.execute("PRAGMA user_version").fetchone()[0], 2)
            item = migrated.append_turn("host", ALICE, conversation_id="c",
                                        role="user", content="legacy compatible")
            self.assertIsNone(item.expires_at)
            self.assertEqual(migrated.expire_due("host", ALICE, now=WHEN,
                                                 privacy_scopes=PRIVATE), 0)


if __name__ == "__main__":
    unittest.main()
