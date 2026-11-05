"""Synthetic-only proof that operator recount never opens SQLite writable."""

from contextlib import closing, redirect_stdout
from io import StringIO
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from chatgpt_archive import ChatGPTArchive, ImportFailure
from chatgpt_readonly_recount import ReadOnlyArchiveView, main, recount_existing_vault
from test_chatgpt_archive import conv, makezip


class ReadOnlyRecountTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.vault = self.base / "private-vault"
        self.vault.mkdir()
        self.key = self.base / "key.bin"
        self.key.write_bytes(os.urandom(32))
        self.source = self.base / "account.zip"
        makezip(self.source, {
            "conversations.json": [conv("private-id-1", "PRIVATE_TEST_MARKER"),
                                   conv("private-id-2", "another text")],
            "assets/opaque.bin": b"synthetic asset",
        })
        self.importer = ChatGPTArchive(self.vault, self.key)
        self.importer.import_zip(self.source)

    def test_recount_is_readonly_and_does_not_leak_source_identifiers(self):
        before = hashlib.sha256((self.vault / "index.sqlite3").read_bytes()).digest()
        result = recount_existing_vault(
            vault_dir=self.vault, key_file=self.key, original_zip=self.source)
        after = hashlib.sha256((self.vault / "index.sqlite3").read_bytes()).digest()
        self.assertEqual(before, after)
        self.assertTrue(result["source_reconciled"])
        self.assertTrue(result["read_only_index"])
        self.assertFalse(result["ciphertext_authenticated_in_this_run"])
        self.assertFalse(result["memory_admitted"])
        self.assertFalse(result["model_learning_performed"])
        for secret in ("private-id-1", "PRIVATE_TEST_MARKER"):
            self.assertNotIn(secret, str(result))

        reader = ReadOnlyArchiveView(self.vault, self.key)
        with closing(reader._db()) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE imports SET verified=0")
        with self.assertRaisesRegex(ImportFailure, "read-only"):
            reader.import_zip(self.source)
        with self.assertRaisesRegex(ImportFailure, "read-only"):
            reader._encrypted_zip_copy(self.source, "0" * 64)

    def test_optional_ciphertext_readback_is_separate_and_readonly(self):
        result = recount_existing_vault(
            vault_dir=self.vault, key_file=self.key, original_zip=self.source,
            verify_ciphertext=True)
        self.assertTrue(result["ciphertext_authenticated_in_this_run"])
        self.assertEqual(result["unique_conversations"], 2)

    def test_wrong_key_and_absent_index_fail_without_initializing_schema(self):
        bad = self.base / "wrong-key.bin"
        bad.write_bytes(os.urandom(32))
        with self.assertRaises(ImportFailure):
            ReadOnlyArchiveView(self.vault, bad)
        empty = self.base / "absent-vault"
        empty.mkdir()
        with self.assertRaisesRegex(ImportFailure, "preexisting private archive index"):
            ReadOnlyArchiveView(empty, self.key)
        self.assertEqual(tuple(empty.iterdir()), ())

    def test_multiple_verified_exports_refused_instead_of_guessing(self):
        other = self.base / "another-account.zip"
        makezip(other, {"conversations.json": [conv("other-id", "OTHER_PRIVATE_TEST")]})
        self.importer.import_zip(other)
        with self.assertRaisesRegex(ImportFailure, "exactly one"):
            recount_existing_vault(
                vault_dir=self.vault, key_file=self.key, original_zip=self.source)

    def test_original_source_mismatch_fails(self):
        different = self.base / "wrong-account.zip"
        makezip(different, {"conversations.json": [conv("other-id", "something")]})
        with self.assertRaisesRegex(ImportFailure, "fingerprint mismatched"):
            recount_existing_vault(
                vault_dir=self.vault, key_file=self.key, original_zip=different)

    def test_cli_failure_is_sanitized(self):
        output = StringIO()
        with patch("sys.argv", ["verify", "--vault-dir", str(self.vault),
                                "--key-file", str(self.base / "SECRET_MISSING_KEY"),
                                "--zip", str(self.source)]), redirect_stdout(output):
            self.assertEqual(main(), 2)
        self.assertIn('"status": "FAILED"', output.getvalue())
        self.assertNotIn("SECRET_MISSING_KEY", output.getvalue())


if __name__ == "__main__":
    unittest.main()
