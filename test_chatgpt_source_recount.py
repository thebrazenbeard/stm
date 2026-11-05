"""Source-to-index independent coverage audits; synthetic private-data only."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest

from chatgpt_archive import ChatGPTArchive, ImportFailure
from chatgpt_source_recount import verify_source_index
from test_chatgpt_archive import conv, makezip


class SourceRecountTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.vault = self.root / "vault"
        self.vault.mkdir()
        self.key = self.root / "key.bin"
        self.key.write_bytes(os.urandom(32))
        self.archive = ChatGPTArchive(self.vault, self.key)

    def _import(self, parts=None):
        source = self.root / "original.zip"
        if parts is None:
            parts = {
                "conversations.json": [conv("one", "first"), conv("two", "second")],
                "conversations_1.json": [conv("three", "third")],
                "assets/a.bin": b"opaque asset bytes",
            }
        makezip(source, parts)
        imported = self.archive.import_zip(source)
        return source, imported["export_sha256"]

    def test_recounts_all_shards_and_sealed_index(self):
        source, fingerprint = self._import()
        result = verify_source_index(self.archive, source, fingerprint)
        self.assertEqual(
            result,
            {"source_reconciled": True, "part_files": 2,
             "source_rows": 3, "unique_conversations": 3,
             "duplicate_rows": 0, "message_nodes": 6},
        )
        # Counts prove a source audit; they do not transfer private names/text.
        self.assertNotIn("first", str(result))
        self.assertNotIn("one", str(result))

    def test_reconciles_identical_duplicates(self):
        row = conv("repeat", "same")
        source, fingerprint = self._import({
            "conversations.json": [row],
            "conversations-1.json": [row],
        })
        result = verify_source_index(self.archive, source, fingerprint)
        self.assertEqual((result["source_rows"], result["unique_conversations"],
                          result["duplicate_rows"], result["message_nodes"]),
                         (2, 1, 1, 2))

    def test_deleted_index_row_and_adjusted_counters_detected(self):
        source, fingerprint = self._import()
        with closing(sqlite3.connect(self.archive.db_path)) as db, db:
            token = self.archive._id_token("two")
            db.execute("DELETE FROM conversations WHERE export_sha=? AND conversation_token=?",
                       (fingerprint, token))
            # Counter manipulation could fool the original index-only verify.
            db.execute("UPDATE imports SET unique_conversations=2,source_rows=2,"
                       "message_nodes=4 WHERE export_sha=?", (fingerprint,))
        with self.assertRaisesRegex(ImportFailure, "absent or changed"):
            verify_source_index(self.archive, source, fingerprint)

    def test_changed_stored_digest_detected(self):
        source, fingerprint = self._import()
        with closing(sqlite3.connect(self.archive.db_path)) as db, db:
            db.execute("UPDATE conversations SET digest=? WHERE export_sha=? "
                       "AND conversation_token=?",
                       (bytes(32), fingerprint, self.archive._id_token("two")))
        with self.assertRaisesRegex(ImportFailure, "absent or changed"):
            verify_source_index(self.archive, source, fingerprint)

    def test_substituted_source_is_rejected_without_index_modification(self):
        source, fingerprint = self._import()
        makezip(source, {"conversations.json": [conv("substitute", "different")]})
        with self.assertRaisesRegex(ImportFailure, "fingerprint mismatched"):
            verify_source_index(self.archive, source, fingerprint)
        self.assertEqual(self.archive.status()["exports"], 1)

    def test_source_symlink_is_refused(self):
        source, fingerprint = self._import()
        alias = self.root / "linked.zip"
        try:
            alias.symlink_to(source)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks unavailable on this OS")
        with self.assertRaisesRegex(ImportFailure, "symlink refused"):
            verify_source_index(self.archive, alias, fingerprint)


if __name__ == "__main__":
    unittest.main()
