"""Bounded synthetic resource tests; never open the real account export.

The memory test deliberately uses incompressible-enough synthetic JSON bodies
of fixed size so a regression to SQLite ``fetchall`` is observable. Its ceiling
is generous enough for one-at-a-time cryptographic record verification.
"""

import json
import os
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch
import zipfile

import chatgpt_archive
import chatgpt_graph
import chatgpt_recall
from chatgpt_archive import ChatGPTArchive, ImportFailure
from chatgpt_graph import GraphFailure
from chatgpt_recall import RecallFailure, search_for_owner_review
from test_chatgpt_recall import SHA, NOW, candidate, context, conversation


class FakeZip:
    def __init__(self, members):
        self.members = members

    def infolist(self):
        return self.members


def member(name, unpacked, packed):
    info = zipfile.ZipInfo(name)
    info.file_size = unpacked
    info.compress_size = packed
    return info


class ResourceBoundsTests(unittest.TestCase):
    def test_zip_member_count_limit_avoids_large_manifest_allocation(self):
        with patch.object(chatgpt_archive, "_MAX_ZIP_MEMBERS", 2):
            with self.assertRaisesRegex(ImportFailure, "member count"):
                ChatGPTArchive._safe_zip_members(FakeZip([
                    member("conversations.json", 4, 4),
                    member("assets/one.bin", 4, 4),
                    member("assets/two.bin", 4, 4),
                ]))

    def test_zip_total_uncompressed_bytes_is_bounded(self):
        with patch.object(chatgpt_archive, "_MAX_ZIP_TOTAL_BYTES", 15):
            with self.assertRaisesRegex(ImportFailure, "total expanded size"):
                ChatGPTArchive._safe_zip_members(FakeZip([
                    member("conversations.json", 8, 8),
                    member("assets/image.bin", 8, 8),
                ]))

    def test_zip_expansion_ratio_budget_is_enforced(self):
        with patch.object(chatgpt_archive, "_ZIP_RATIO_THRESHOLD_BYTES", 16):
            with self.assertRaisesRegex(ImportFailure, "expansion ratio"):
                ChatGPTArchive._safe_zip_members(FakeZip([
                    member("conversations.json", 1_024, 2),
                ]))

    def test_graph_node_budget_is_enforced_before_projection(self):
        with patch.object(chatgpt_graph, "_MAX_NODES", 3):
            with self.assertRaisesRegex(GraphFailure, "node budget"):
                chatgpt_graph.derive_graph(conversation(), SHA)

    def test_recall_scan_budgets_reject_long_private_text(self):
        doc = conversation()
        doc["mapping"]["user"]["message"]["content"]["parts"] = ["p" * 4096]
        with patch.object(chatgpt_recall, "MAX_SCAN_CHARS", 256):
            with self.assertRaisesRegex(RecallFailure, "text scan budget"):
                search_for_owner_review(doc, SHA, "p", {"user": candidate()},
                                        context(), now=NOW)
        with patch.object(chatgpt_recall, "MAX_SCAN_NODES", 3):
            with self.assertRaisesRegex(RecallFailure, "node scan budget"):
                search_for_owner_review(conversation(), SHA, "hello",
                                        {"user": candidate()}, context(), now=NOW)

    def test_recall_rejects_one_large_part_before_allocating_joined_text(self):
        doc = conversation()
        doc["mapping"]["user"]["message"]["content"]["parts"] = ["q" * (4 * 1024 * 1024)]
        tracemalloc.start()
        try:
            with patch.object(chatgpt_recall, "MAX_SCAN_CHARS", 256):
                with self.assertRaisesRegex(RecallFailure, "text scan budget"):
                    search_for_owner_review(doc, SHA, "q", {"user": candidate()},
                                            context(), now=NOW)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 * 1024 * 1024,
                        "oversized text must fail before allocating a concatenated copy")

    def test_verify_uses_bounded_memory_for_many_sealed_records(self):
        # 24 records of ~1 MiB each expose the old .fetchall() verification
        # strategy without consuming the hundreds of MiB in Patrick's export.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vault = root / "private"
            vault.mkdir()
            key = root / "key.bin"
            key.write_bytes(os.urandom(32))
            archive = ChatGPTArchive(vault, key)
            records = [
                {"id": f"synthetic-{i}", "mapping": {"root": {"message": {
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["x" * (1024 * 1024)]}
                }}}}
                for i in range(24)
            ]
            source = root / "synthetic.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as z:
                z.writestr("conversations.json", json.dumps(records))
            imported = archive.import_zip(source)
            tracemalloc.start()
            try:
                result = archive.verify(imported["export_sha256"])
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(result["verified"], 24)
            self.assertLess(peak, 16 * 1024 * 1024,
                            "verify() should not retain all ciphertext records in RAM")


if __name__ == "__main__":
    unittest.main()
