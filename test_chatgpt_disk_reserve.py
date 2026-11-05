"""Synthetic disk-budget controls; no private export or host filesystem changes."""

from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure, _MAGIC
from test_chatgpt_archive import conv, makezip


class DiskReserveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = root / "synthetic.zip"
        makezip(self.source, {"conversations.json": [conv("synthetic", "not private")]})
        self.vault = root / "vault"
        self.vault.mkdir()
        key_file = root / "key.bin"
        key_file.write_bytes(os.urandom(32))
        self.archive = ChatGPTArchive(self.vault, key_file)
        with zipfile.ZipFile(self.source) as z:
            self.conversation_bytes = z.getinfo("conversations.json").file_size

    def test_low_free_space_refuses_copy_before_any_export_is_written(self):
        # Under the old source-only preflight this appeared sufficient to copy
        # the whole ZIP but left no realistic room for the SQLite index.
        zip_only_space = self.source.stat().st_size + 2 * 1024 * 1024
        with patch("chatgpt_archive.shutil.disk_usage", return_value=SimpleNamespace(free=zip_only_space)):
            with self.assertRaisesRegex(ImportFailure, "conversation index"):
                self.archive.import_zip(self.source)
        self.assertEqual(self.archive.status()["exports"], 0)
        self.assertFalse(list(self.vault.glob("source_*.zip.aesgcm")))

    def test_source_and_index_reserves_allow_ordinary_synthetic_import(self):
        estimated = (self.source.stat().st_size + len(_MAGIC) + 12 + 16
                     + 2 * self.conversation_bytes + 16 * 1024 * 1024)
        with patch("chatgpt_archive.shutil.disk_usage", return_value=SimpleNamespace(free=estimated)):
            result = self.archive.import_zip(self.source)
        self.assertEqual(result["unique_conversations"], 1)
        self.assertEqual(self.archive.verify(result["export_sha256"])["verified"], 1)

    def test_existing_encrypted_source_only_needs_index_reserve(self):
        digest, _ = self.archive._source_digest(self.source)
        self.assertTrue(self.archive._encrypted_zip_copy(self.source, digest))
        remaining = 2 * self.conversation_bytes + 16 * 1024 * 1024
        with patch("chatgpt_archive.shutil.disk_usage", return_value=SimpleNamespace(free=remaining)):
            result = self.archive.import_zip(self.source)
        self.assertEqual(result["unique_conversations"], 1)


if __name__ == "__main__":
    unittest.main()
