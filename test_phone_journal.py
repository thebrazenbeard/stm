import concurrent.futures
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
import os
from stm_phone_journal import EncryptedJournal, JournalError

S = "phone_session_20261028"
R = "request_id_20261028"
U = "Sensitive future Vera message private"

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        f = Path(self.tmp.name)
        self.key = f / "key.bin"
        self.key.write_bytes(os.urandom(32))
        self.db = f / "journal.sqlite3"
        self.store = EncryptedJournal(self.db, self.key)

    def put(self, request_id=R, session=S, question=U):
        return self.store.append_turn(session, request_id, "vera-local:latest",
                                      question, "Private answer goes here")

    def test_encrypts_transcript_not_plaintext_in_db(self):
        self.put()
        raw = self.db.read_bytes()
        self.assertNotIn(U.encode(), raw)
        self.assertNotIn(b"Private answer goes here", raw)
        self.assertIn(U, self.store.recent(S)[0]["user"])

    def test_turn_is_durable_after_reopen(self):
        self.put()
        reopened = EncryptedJournal(self.db, self.key)
        self.assertEqual(reopened.recent(S)[0]["model"], "vera-local:latest")

    def test_lookup_request_with_integrity_and_session_isolation(self):
        self.assertIsNone(self.store.get_request(S, R))
        self.put()
        saved = self.store.get_request(S, R)
        self.assertEqual(saved["user"], U)
        self.assertEqual(saved["assistant"], "Private answer goes here")
        with self.assertRaises(JournalError):
            self.store.get_request("another_private_session", R)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE turns SET sealed=? WHERE request_id=?", (b"tampered", R))
        with self.assertRaises(JournalError):
            self.store.get_request(S, R)

    def test_idempotent_request_and_conflict(self):
        self.assertEqual(self.put(), self.put())
        with self.assertRaises(JournalError):
            self.put(question="Changed content with same id")
        self.assertEqual(self.store.count(S), 1)

    def test_session_isolation(self):
        self.put()
        self.put("request_id_second_20261028", "another_private_session")
        self.assertEqual(self.store.count(S), 1)
        self.assertEqual(self.store.count("another_private_session"), 1)

    def test_wrong_key_and_tamper_fail_closed(self):
        self.put()
        self.key.write_bytes(os.urandom(32))
        wrong = EncryptedJournal(self.db, self.key)
        with self.assertRaises(JournalError):
            wrong.recent(S)
        self.key.write_bytes(self.store._key)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE turns SET sealed=? WHERE request_id=?", (b"tampered", R))
        with self.assertRaises(JournalError):
            self.store.recent(S)

    def test_no_implicit_deletion_limited_context(self):
        for i in range(21):
            self.put(f"request_{i:04d}_20261028")
        self.assertEqual(self.store.count(S), 21)
        self.assertEqual(len(self.store.recent(S, limit=3)), 3)

    def test_concurrent_append_unique(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            ids = list(pool.map(lambda i: self.put(f"request_{i:04d}_20261028"), range(50)))
        self.assertEqual(len(set(ids)), 50)
        self.assertEqual(self.store.count(S), 50)

    def test_invalid_id_and_size_refused(self):
        with self.assertRaises(JournalError):
            self.put("x")
        with self.assertRaises(JournalError):
            self.put(question="a" * 4097)

    def test_explicit_delete_only_target_session(self):
        self.put()
        self.put("request_id_second_20261028", "another_private_session")
        self.assertEqual(self.store.delete_session(S), 1)
        self.assertEqual(self.store.count(S), 0)
        self.assertEqual(self.store.count("another_private_session"), 1)

if __name__ == "__main__":
    unittest.main()
