"""Adversarial ZIP metadata checks; fixtures contain no account information."""

import os
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from chatgpt_archive import ChatGPTArchive, ImportFailure


class ZipSecurityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.private = self.root / "vault"
        self.private.mkdir()
        self.key = self.root / "vault-key.bin"
        self.key.write_bytes(os.urandom(32))
        self.archive = ChatGPTArchive(self.private, self.key)

    def _write(self, members):
        path = self.root / "input.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, data in members:
                output.writestr(name, data)
        return path

    def _reject(self, members):
        target = self._write(members)
        with self.assertRaises(ImportFailure):
            self.archive.import_zip(target)
        self.assertEqual(self.archive.status()["exports"], 0)
        self.assertEqual(list(self.private.glob("source_*.aesgcm")), [])

    def test_parent_traversal_is_rejected_before_source_copy(self):
        self._reject([("conversations.json", b'[{"id":"safe"}]'),
                      ("../../outside.txt", b"no extraction permitted")])
        self.assertFalse((self.root / "outside.txt").exists())

    def test_windows_and_absolute_path_variants_rejected(self):
        for name in (r"C:\\somewhere\\credential.txt", "/etc/secrets", r"folder\\..\\secret.txt",
                     "a//b.txt", "folder/./file.txt"):
            with self.subTest(name=name):
                self._reject([("conversations.json", b'[{"id":"safe"}]'),
                              (name, b"untrusted")])

    def test_duplicate_member_names_are_rejected_case_insensitively(self):
        for variant in ("a/asset.txt", "A/ASSET.TXT"):
            with self.subTest(variant=variant):
                self._reject([("conversations.json", b'[{"id":"safe"}]'),
                              ("A/asset.txt", b"first"), (variant, b"second")])

    def test_symlink_member_is_rejected_without_dereference(self):
        link = zipfile.ZipInfo("assets/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self._reject([("conversations.json", b'[{"id":"safe"}]'),
                      (link, b"../../etc/passwd")])

    def test_numbered_shard_gaps_and_duplicate_indices_rejected(self):
        self._reject([("conversations_0.json", b'[{"id":"one"}]'),
                      ("conversations_2.json", b'[{"id":"two"}]')])
        self._reject([("conversations.json", b'[{"id":"one"}]'),
                      ("conversations_0000.json", b'[{"id":"two"}]')])
        self._reject([("conversations_19.json", b'[{"id":"orphan"}]')])

    def test_large_metadata_size_and_expansion_bomb_rejected(self):
        class FakeZip:
            def __init__(self, members):
                self.members = members

            def infolist(self):
                return self.members

        member = zipfile.ZipInfo("conversations.json")
        member.file_size = 64 * 1024**2
        member.compress_size = 1
        with self.assertRaisesRegex(ImportFailure, "expansion ratio"):
            ChatGPTArchive._safe_zip_members(FakeZip([member]))

        member.file_size = 33 * 1024**3
        member.compress_size = member.file_size
        with self.assertRaisesRegex(ImportFailure, "per-file"):
            ChatGPTArchive._safe_zip_members(FakeZip([member]))

    def test_normal_assets_and_contiguous_shards_admitted(self):
        target = self._write([("exports/conversations.json", b'[{"id":"one"}]'),
                              ("exports/conversations-001.json", b'[{"id":"two"}]'),
                              ("exports/assets/img.bin", b"not conversation text")])
        result = self.archive.import_zip(target)
        self.assertEqual((result["part_files"], result["unique_conversations"]), (2, 2))


if __name__ == "__main__":
    unittest.main()
