"""Synthetic source-mutation race adversary; no account data."""

import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure


class ChatGPTSourceRaceTests(unittest.TestCase):
    def test_source_replaced_between_encrypted_copy_and_indexing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            key_file = root / "key.bin"
            key_file.write_bytes(os.urandom(32))
            source = root / "export.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("conversations.json", '[{"id":"original","mapping":{}}]')

            archive = ChatGPTArchive(vault, key_file)
            encrypted_copy = archive._encrypted_zip_copy

            def replace_source_after_copy(source_path, export_sha):
                copied = encrypted_copy(source_path, export_sha)
                # Simulate an external actor replacing a syntactically valid ZIP
                # after the vault's authenticated copy but before index parsing.
                with zipfile.ZipFile(source_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                    z.writestr("conversations.json", '[{"id":"replacement","mapping":{}}]')
                return copied

            archive._encrypted_zip_copy = replace_source_after_copy
            with self.assertRaisesRegex(ImportFailure, "source changed"):
                archive.import_zip(source)
            self.assertEqual(archive.status()["exports"], 0)
            self.assertEqual(archive.status()["incomplete_exports"], 0)


if __name__ == "__main__":
    unittest.main()
