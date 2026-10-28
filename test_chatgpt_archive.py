"""Account-wide ChatGPT export contract: synthetic fixtures only."""
from pathlib import Path
from contextlib import closing
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from chatgpt_archive import ChatGPTArchive, ImportFailure

def conv(cid, title, extra=None):
    return {
        "id": cid, "title": title, "create_time": 1700000000.0,
        "update_time": 1700000100.0, "conversation_template_id": None,
        "mapping": {"node_1": {"id": "node_1", "message": {
            "id": "m1", "author": {"role": "user"}, "content": {
                "content_type": "text", "parts": ["private conversation text"]}}},
        "node_2": {"id": "node_2", "message": {"id":"m2",
            "author": {"role": "assistant"}, "content": {
                "content_type":"text", "parts":["a response"]}}}},
        "metadata": {"project_id": "some-other-project", "other_fields": extra},
    }

def makezip(path, parts):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as out:
        for name, contents in parts.items():
            out.writestr(name, json.dumps(contents) if not isinstance(contents, bytes) else contents)

class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "encrypted"
        self.private.mkdir()
        self.key = self.root / "key.bin"
        self.key.write_bytes(os.urandom(32))
        self.arc = ChatGPTArchive(self.private, self.key)

    def test_imports_all_numbered_files_and_preserves_unknown_metadata(self):
        export = self.root / "complete.zip"
        makezip(export, {
            "conversations.json": [conv("id-one","ordinary"),conv("id-two","project")],
            "conversations_1.json": [conv("id-three","archived",{"locked":True})],
            "images/image.bin": b"not a json message",
        })
        report = self.arc.import_zip(export)
        self.assertEqual(report["source_rows"], 3)
        self.assertEqual(report["unique_conversations"], 3)
        self.assertEqual(report["part_files"], 2)
        self.assertEqual(report["duplicate_rows"], 0)
        self.assertEqual(report["indexed_conversations"], 3)
        restored = self.arc.conversation(report["export_sha256"], "id-three")
        self.assertEqual(restored["metadata"]["other_fields"]["locked"], True)
        self.assertEqual(restored["mapping"]["node_1"]["message"]["content"]["parts"][0],
                         "private conversation text")
        self.assertEqual(self.arc.verify(report["export_sha256"])["verified"], 3)
        self.assertNotIn(b"private conversation text", (self.private / "index.sqlite3").read_bytes())
        self.assertNotIn(b"not a json message", self.arc.source_path(report["export_sha256"]).read_bytes())

    def test_reimport_is_idempotent_and_same_ids_can_have_revisions(self):
        p1 = self.root / "one.zip"
        p2 = self.root / "two.zip"
        makezip(p1, {"conversations.json":[conv("id-one","first")]})
        makezip(p2, {"conversations.json":[conv("id-one","changed")]})
        a = self.arc.import_zip(p1)
        b = self.arc.import_zip(p2)
        again = self.arc.import_zip(p1)
        self.assertEqual(again["export_sha256"],a["export_sha256"])
        self.assertEqual(self.arc.conversation(a["export_sha256"],"id-one")["title"],"first")
        self.assertEqual(self.arc.conversation(b["export_sha256"],"id-one")["title"],"changed")
        self.assertEqual(self.arc.status()["exports"], 2)

    def test_top_level_object_and_numbered_hyphen_files(self):
        p = self.root / "object.zip"
        makezip(p, {"nested/conversations-0001.json":{"conversations":[conv("other","nested")]}})
        result = self.arc.import_zip(p)
        self.assertEqual(result["unique_conversations"],1)

    def test_duplicate_identical_rows_counted_without_losing_records(self):
        p = self.root / "repeat.zip"
        record = conv("id-one","repeat")
        makezip(p,{"conversations.json":[record],
                   "conversations_1.json":[record]})
        result=self.arc.import_zip(p)
        self.assertEqual((result["source_rows"],result["duplicate_rows"],
                          result["unique_conversations"]),(2,1,1))

    def test_duplicate_conflicting_ids_fail_closed(self):
        p = self.root / "conflict.zip"
        makezip(p,{"conversations.json":[conv("id-one","one"),conv("id-one","two")]})
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"],0)

    def test_missing_or_invalid_conversation_part_fails_not_silently_skip(self):
        p = self.root / "empty.zip"
        makezip(p,{"account.json":{"name":"person"}})
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"],0)
        p2 = self.root / "bad.zip"
        with zipfile.ZipFile(p2,"w") as f:
            f.writestr("conversations.json",b"[{\"id\":\"id-one\"}, broken]")
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p2)
        self.assertEqual(self.arc.status()["exports"],0)

    def test_missing_conversation_records_cannot_count_as_complete(self):
        p = self.root / "nomessages.zip"
        makezip(p, {"conversations.json": {"other": "unsupported"}})
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"], 0)

    def test_all_empty_numbered_parts_rejected(self):
        p = self.root / "no-chats.zip"
        makezip(p, {"conversations.json":[], "conversations_1.json":[]})
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"], 0)

    def test_unknown_conversation_part_name_fails_coverage(self):
        p = self.root / "unknown-part.zip"
        makezip(p, {"conversations.json": [conv("id-one","good")],
                    "conversations-partX.json": [conv("id-two","must not skip")]})
        with self.assertRaises(ImportFailure):
            self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"], 0)

    def test_failing_final_verification_not_reported_as_completed(self):
        p = self.root / "post-commit.zip"
        makezip(p, {"conversations.json": [conv("id-one", "valid data")]})
        with patch.object(self.arc, "verify", side_effect=ImportFailure("simulated verify failure")):
            with self.assertRaises(ImportFailure):
                self.arc.import_zip(p)
        self.assertEqual(self.arc.status()["exports"], 0)
        self.assertEqual(self.arc.status()["incomplete_exports"], 1)

    def test_existing_preverified_empty_schema_is_migrated_safely(self):
        import sqlite3
        with closing(sqlite3.connect(self.arc.db_path)) as db, db:
            db.execute("DROP TABLE imports")
            db.execute("""CREATE TABLE imports (
                export_sha TEXT PRIMARY KEY, archive_name TEXT NOT NULL,
                input_bytes INTEGER NOT NULL, part_files INTEGER NOT NULL,
                source_rows INTEGER NOT NULL, unique_conversations INTEGER NOT NULL,
                duplicate_rows INTEGER NOT NULL, message_nodes INTEGER NOT NULL,
                imported_at TEXT NOT NULL)""")
        reopened = ChatGPTArchive(self.private, self.key)
        self.assertEqual(reopened.status()["exports"], 0)
        with closing(sqlite3.connect(self.arc.db_path)) as db:
            self.assertIn("verified", [c[1] for c in db.execute("PRAGMA table_info(imports)")])

    def test_wrong_key_and_ciphertext_tampering_fail(self):
        p = self.root / "test.zip"
        makezip(p,{"conversations.json":[conv("id-one","test")]})
        report=self.arc.import_zip(p)
        wrong=self.root/"wrong.bin"
        wrong.write_bytes(os.urandom(32))
        with self.assertRaises(ImportFailure):
            ChatGPTArchive(self.private, wrong)
        archive_file=self.arc.source_path(report["export_sha256"])
        with archive_file.open("r+b") as f:
            f.seek(-22,2)
            byte=f.read(1)
            f.seek(-22,2)
            f.write(bytes([byte[0]^255]))
        with self.assertRaises(ImportFailure):
            self.arc.verify(report["export_sha256"])

    def test_export_no_metadata_loss_and_no_path_extraction(self):
        p=self.root/"assets.zip"
        makezip(p,{"conversations.json":[conv("id-one","title",{"arbitrary":"preserved"})],
                   "../../outside.txt":b"do not extract this"})
        report=self.arc.import_zip(p)
        self.assertEqual(self.arc.conversation(report["export_sha256"],"id-one")
                         ["metadata"]["other_fields"]["arbitrary"],"preserved")
        self.assertFalse((self.root/"outside.txt").exists())
        self.assertEqual(self.arc.verify(report["export_sha256"])["verified"],1)

if __name__ == "__main__": unittest.main()
