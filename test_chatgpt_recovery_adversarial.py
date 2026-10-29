"""Crash/replay contract checks using synthetic ChatGPT exports only."""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure


def _conversation(identifier="conversation-1"):
    return {
        "id": identifier,
        "title": "synthetic recovery fixture",
        "mapping": {
            "n0": {
                "id": "n0",
                "message": {
                    "id": "m0",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["fixture only"]},
                },
            }
        },
    }


def _zip(path, *, invalid_second=False):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("conversations.json", json.dumps([_conversation()]))
        if invalid_second:
            out.writestr("conversations_1.json", b'[{"id":"broken"}, INVALID]')


class RecoveryAdversarialTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.vault = self.root / "vault"
        self.vault.mkdir()
        self.key = self.root / "key.bin"
        self.key.write_bytes(os.urandom(32))
        self.arc = ChatGPTArchive(self.vault, self.key)

    def test_bad_later_shard_rolls_back_records_and_removes_new_ciphertext(self):
        source = self.root / "partially-valid.zip"
        _zip(source, invalid_second=True)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(source)
        self.assertEqual(self.arc.status()["exports"], 0)
        self.assertEqual(self.arc.status()["incomplete_exports"], 0)
        self.assertFalse(self.arc.source_path(digest).exists())

    def test_source_changed_between_digest_and_copy_is_rejected(self):
        source = self.root / "valid.zip"
        _zip(source)
        false_digest = "0" * 64
        with patch.object(self.arc, "_source_digest", return_value=(false_digest, source.stat().st_size)):
            with self.assertRaises(ImportFailure):
                self.arc.import_zip(source)
        self.assertFalse(self.arc.source_path(false_digest).exists())
        self.assertEqual(self.arc.status()["exports"], 0)

    def test_postcommit_verify_failure_is_not_reported_as_complete(self):
        source = self.root / "valid.zip"
        _zip(source)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with patch.object(self.arc, "verify", side_effect=ImportFailure("fault injected")):
            with self.assertRaises(ImportFailure):
                self.arc.import_zip(source)
        self.assertTrue(self.arc.source_path(digest).is_file())
        self.assertEqual(self.arc.status()["exports"], 0)
        self.assertEqual(self.arc.status()["incomplete_exports"], 1)
        # Authentication can succeed separately after the injected fault ends.
        self.assertEqual(self.arc.verify(digest)["verified"], 1)

    def test_retry_after_postcommit_fault_requires_full_reconciliation(self):
        """A complete source recount and AES readback permit safe recovery."""
        source = self.root / "valid.zip"
        _zip(source)
        with patch.object(self.arc, "verify", side_effect=ImportFailure("fault injected")):
            with self.assertRaises(ImportFailure):
                self.arc.import_zip(source)
        resumed = self.arc.import_zip(source)
        self.assertEqual(resumed["status"], "recovered_after_full_source_reconciliation")
        self.assertEqual(self.arc.status()["incomplete_exports"], 0)

    def test_verified_index_row_deleted_is_detected_by_full_verify(self):
        source = self.root / "valid.zip"
        _zip(source)
        result = self.arc.import_zip(source)
        with closing(sqlite3.connect(self.arc.db_path)) as db, db:
            db.execute("DELETE FROM conversations WHERE export_sha=?", (result["export_sha256"],))
        with self.assertRaises(ImportFailure):
            self.arc.verify(result["export_sha256"])


if __name__ == "__main__":
    unittest.main()
