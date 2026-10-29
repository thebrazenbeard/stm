"""Synthetic portability checks for a copied sealed ChatGPT export vault.

These checks are not evidence of an OS-protected backup, key escrow,
cross-disk recovery or real Lappy restoration.
"""

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure


class SealedCopyRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.source = self.base / "synthetic.zip"
        conversation = [{"id": "synthetic-id", "mapping": {"n0": {
            "message": {"author": {"role": "user"},
                        "content": {"parts": ["fixture-only"]}}}}}]
        with zipfile.ZipFile(self.source, "w") as package:
            package.writestr("conversations.json", json.dumps(conversation))
        self.original_vault = self.base / "original"
        self.original_vault.mkdir()
        self.original_key = self.base / "key.bin"
        self.original_key.write_bytes(os.urandom(32))
        self.archive = ChatGPTArchive(self.original_vault, self.original_key)
        self.imported = self.archive.import_zip(self.source)

    def copied(self):
        destination = self.base / "restored"
        destination.mkdir()
        shutil.copy2(self.archive.db_path, destination / "index.sqlite3")
        shutil.copy2(self.archive.source_path(self.imported["export_sha256"]),
                     destination / self.archive.source_path(self.imported["export_sha256"]).name)
        copy_key = self.base / "restored-key.bin"
        shutil.copy2(self.original_key, copy_key)
        return destination, copy_key

    def test_sealed_copy_and_same_key_authenticate_after_reopen(self):
        vault, key = self.copied()
        reopened = ChatGPTArchive(vault, key)
        self.assertTrue(reopened.verify(self.imported["export_sha256"])["archive_verified"])
        self.assertEqual(reopened.status()["exports"], 1)
        self.assertEqual(reopened.conversation(self.imported["export_sha256"],
                                               "synthetic-id")["id"], "synthetic-id")

    def test_copied_vault_wrong_key_fails_closed(self):
        vault, key = self.copied()
        key.write_bytes(os.urandom(32))
        with self.assertRaises(ImportFailure):
            ChatGPTArchive(vault, key)

    def test_missing_ciphertext_in_copied_vault_fails_closed(self):
        vault, key = self.copied()
        ciphertext = vault / self.archive.source_path(self.imported["export_sha256"]).name
        ciphertext.unlink()
        reopened = ChatGPTArchive(vault, key)
        with self.assertRaises(ImportFailure):
            reopened.verify(self.imported["export_sha256"])


if __name__ == "__main__":
    unittest.main()
