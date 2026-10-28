"""SQLite conversation archive contract tests on real temporary databases."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest

from stm.archive import ArchiveScope, ConversationArchive


SCOPE = ArchiveScope("local", "pat", "vera")
OTHER = ArchiveScope("local", "different", "vera")
NOW = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)


def authorizer(principal: object, action: str, scope: ArchiveScope) -> bool:
    if principal != "pat" or scope.owner_id != "pat":
        return False
    return not action.endswith(":restricted")


class ConversationArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "history.sqlite")
        self.store = ConversationArchive(self.path, authorize=authorizer)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def search(self, query: str, *, scope: ArchiveScope = SCOPE):
        return self.store.search("pat", scope, query,
                                 privacy_scopes=frozenset({"private"}))

    def append(self, content: str, *, conversation_id: str = "chat1",
               privacy: str = "private"):
        return self.store.append_turn(
            "pat", SCOPE, conversation_id=conversation_id, role="user",
            content=content, source="conversation:turn", privacy=privacy,
            event_time=NOW,
        )

    def test_cross_chat_same_owner_retrieval_and_source_attribution(self):
        first = self.append("The yellow bicycle is parked inside", conversation_id="chat1")
        second = self.append("My magenta backpack broke", conversation_id="chat2")
        hits = self.search("yellow bicycle")
        self.assertEqual([hit.turn.turn_id for hit in hits], [first.turn_id])
        self.assertEqual(hits[0].turn.source, "conversation:turn")
        self.assertEqual(hits[0].turn.event_time, NOW.isoformat())
        self.assertEqual(hits[0].turn.privacy, "private")
        self.assertIsInstance(hits[0].score, float)
        self.assertEqual(self.search("magenta")[0].turn.turn_id, second.turn_id)

    def test_owner_tenant_agent_sql_isolation(self):
        self.append("cobalt secret")
        with self.assertRaises(PermissionError):
            self.search("cobalt", scope=OTHER)
        # A trusted privileged authorizer deliberately permits every scope;
        # SQL predicates must nevertheless isolate the requested owner/agent.
        with ConversationArchive(self.path, authorize=lambda *_: True) as reader:
            for other in (OTHER, ArchiveScope("other", "pat", "vera"),
                          ArchiveScope("local", "pat", "agent2")):
                self.assertEqual(reader.search("other", other, "cobalt",
                                   privacy_scopes=frozenset({"private"})), ())
            self.assertEqual(len(reader.search("any", SCOPE, "cobalt",
                                   privacy_scopes=frozenset({"private"}))), 1)

    def test_authorizer_denies_cross_owner_and_private_labels(self):
        with self.assertRaises(PermissionError):
            self.store.append_turn("intruder", SCOPE, conversation_id="c", role="user",
                                   content="private content")
        with self.assertRaises(PermissionError):
            self.store.append_turn("pat", OTHER, conversation_id="c", role="user",
                                   content="other content")
        with self.assertRaises(PermissionError):
            self.append("classified facts", privacy="restricted")
        with ConversationArchive(self.path, authorize=lambda *_: True) as privileged:
            privileged.append_turn("host", SCOPE, conversation_id="secret-chat",
                                   role="user", content="classified orchid",
                                   privacy="restricted")
        self.assertEqual(self.search("orchid"), ())
        with self.assertRaises(PermissionError):
            self.store.search("pat", SCOPE, "classified",
                              privacy_scopes=frozenset({"private", "restricted"}))
        with self.assertRaises(PermissionError):
            self.store.search("pat", SCOPE, "classified",
                              privacy_scopes=frozenset())

    def test_correction_supersedes_prior_without_retrieving_stale_text(self):
        first = self.append("The ferry departs at thirteen")
        updated = self.store.correct("pat", SCOPE, first.turn_id,
                                     "The ferry departs at fourteen")
        self.assertNotEqual(first.turn_id, updated.turn_id)
        self.assertEqual(updated.supersedes_id, first.turn_id)
        self.assertEqual(self.search("thirteen"), ())
        self.assertEqual([hit.turn.turn_id for hit in self.search("fourteen")],
                         [updated.turn_id])
        with self.assertRaises(KeyError):
            self.store.correct("pat", SCOPE, first.turn_id, "new third correction")
        self.assertTrue(self.store.delete("pat", SCOPE, first.turn_id))
        self.assertEqual(self.search("fourteen"), ())
        self.assertFalse(self.store.delete("pat", SCOPE, first.turn_id))
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")

    def test_delete_hard_removes_payload_from_sql_and_fts(self):
        first = self.append("A rare marmalade mineral")
        self.assertTrue(self.store.delete("pat", SCOPE, first.turn_id))
        self.assertEqual(self.search("marmalade"), ())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM turns").fetchone()[0], 0)
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_fts_secure_delete_feature_probe_is_explicit(self):
        self.assertIsInstance(self.store.fts_secure_delete_enabled, bool)
        # SQLite 3.42+ documents the extension setting, but the actual probe
        # is authoritative for the packaged SQLite build in this runtime.
        if sqlite3.sqlite_version_info >= (3, 42, 0):
            self.assertTrue(self.store.fts_secure_delete_enabled)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes only")
    def test_existing_world_readable_db_and_symlink_fail_closed(self):
        exposed = Path(self.temp.name) / "exposed.sqlite"
        exposed.touch(mode=0o600)
        os.chmod(exposed, 0o644)
        with self.assertRaises(PermissionError):
            ConversationArchive(str(exposed), authorize=authorizer)

        target = Path(self.temp.name) / "safe-target.sqlite"
        target.touch(mode=0o600)
        os.chmod(target, 0o600)
        link = Path(self.temp.name) / "link.sqlite"
        link.symlink_to(target)
        with self.assertRaises(PermissionError):
            ConversationArchive(str(link), authorize=authorizer)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes only")
    def test_group_writable_parent_directory_fail_closed(self):
        unsafe = Path(self.temp.name) / "insecure"
        unsafe.mkdir(mode=0o700)
        os.chmod(unsafe, 0o770)
        try:
            with self.assertRaises(PermissionError):
                ConversationArchive(str(unsafe / "data.sqlite"), authorize=authorizer)
        finally:
            os.chmod(unsafe, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes only")
    def test_umask_022_db_wal_shm_are_0600_during_plaintext_write(self):
        # Change umask *only inside a child process*, never the test runner.
        path = Path(self.temp.name) / "umask.sqlite"
        program = """
import json, os, stat, sys
from stm.archive import ConversationArchive, ArchiveScope
os.umask(0o022)
a = ConversationArchive(sys.argv[1], authorize=lambda *_: True)
a.append_turn('host', ArchiveScope('t','o','a'), conversation_id='c',
              role='user', content='TOPSECRET_WAL_MARKER_907776')
print(json.dumps({suffix: (os.path.exists(sys.argv[1] + suffix),
                         oct(stat.S_IMODE(os.stat(sys.argv[1] + suffix).st_mode))
                         if os.path.exists(sys.argv[1] + suffix) else None)
                  for suffix in ('','-wal','-shm')}))
a.close()
"""
        result = subprocess.run(
            [sys.executable, "-c", program, str(path)], check=True,
            capture_output=True, text=True,
        )
        values = json.loads(result.stdout.strip())
        for suffix in ("", "-wal", "-shm"):
            self.assertEqual(values[suffix], [True, "0o600"], suffix)

    def test_bm25_global_corpus_frequency_cannot_affect_scope_scores(self):
        with ConversationArchive(self.path, authorize=lambda *_: True) as archive:
            alice = ArchiveScope("t", "alice", "agent")
            bob = ArchiveScope("t", "bob", "agent")
            first = archive.append_turn("host", alice, conversation_id="a",
                                        role="user", content="orchid sunset")
            archive.append_turn("host", alice, conversation_id="a",
                                role="user", content="orchid crystal sunset")
            query = lambda: archive.search("host", alice, "orchid sunset",
                                           privacy_scopes=frozenset({"private"}))
            before = [(hit.turn.turn_id, hit.score) for hit in query()]
            for n in range(75):
                archive.append_turn("host", bob, conversation_id="b",
                                    role="user", content=f"orchid sunset other {n}")
            after = [(hit.turn.turn_id, hit.score) for hit in query()]
            self.assertIn(first.turn_id, [uid for uid, _ in before])
            self.assertEqual(before, after)

    def test_other_privacy_label_does_not_change_visible_ranking(self):
        with ConversationArchive(self.path, authorize=lambda *_: True) as archive:
            first = archive.append_turn("host", SCOPE, conversation_id="public",
                                        role="user", privacy="public",
                                        content="saffron river")
            query = lambda: archive.search("host", SCOPE, "saffron river",
                                           privacy_scopes=frozenset({"public"}))
            before = [(hit.turn.turn_id, hit.score) for hit in query()]
            for n in range(50):
                archive.append_turn("host", SCOPE, conversation_id="private",
                                    role="user", privacy="private",
                                    content=f"saffron river concealed {n}")
            after = [(hit.turn.turn_id, hit.score) for hit in query()]
            self.assertEqual(before, [(first.turn_id, 2.0)])
            self.assertEqual(after, before)

    def test_older_two_term_match_survives_514_newer_one_term_matches(self):
        with ConversationArchive(self.path, authorize=lambda *_: True) as archive:
            target = archive.append_turn(
                "host", SCOPE, conversation_id="old", role="user",
                content="orion blue", event_time=NOW,
            )
            for n in range(514):
                archive.append_turn(
                    "host", SCOPE, conversation_id="recent", role="user",
                    content=f"orion filler {n}",
                    event_time=NOW + timedelta(seconds=n + 1),
                )
            hits = archive.search("host", SCOPE, "orion blue",
                                  privacy_scopes=frozenset({"private"}), limit=1)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].turn.turn_id, target.turn_id)
            self.assertEqual(hits[0].score, 2.0)

    def test_exact_word_scoring_does_not_count_substrings(self):
        big = self.append("caterpillar", conversation_id="large-word")
        small = self.append("cat", conversation_id="short-word")
        both = self.append("cat caterpillar", conversation_id="both")
        hits = self.search("cat caterpillar")
        scores = {hit.turn.turn_id: hit.score for hit in hits}
        self.assertEqual(scores[big.turn_id], 1.0)
        self.assertEqual(scores[small.turn_id], 1.0)
        self.assertEqual(scores[both.turn_id], 2.0)
        self.assertEqual(hits[0].turn.turn_id, both.turn_id)

    def test_exact_fts5_integrity_after_correction_and_reopen(self):
        first = self.append("Kite violet sunset")
        self.store.correct("pat", SCOPE, first.turn_id, "Kite indigo sunset")
        self.store.close()
        self.store = ConversationArchive(self.path, authorize=authorizer)
        self.assertEqual(self.search("violet"), ())
        self.assertEqual(len(self.search("indigo")), 1)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_safe_match_is_not_fts_syntax_injection(self):
        self.append("bravery water")
        self.assertEqual(self.search('" OR *'), ())
        self.assertEqual(self.search("water"), self.search("water"))
        with self.assertRaises(ValueError):
            self.search("***")
        with self.assertRaises(ValueError):
            self.search("a" * 4097)
        with self.assertRaises(ValueError):
            self.search(" ".join("term" for _ in range(33)))

    def test_timezone_content_and_limit_validation(self):
        with self.assertRaises(ValueError):
            self.store.append_turn("pat", SCOPE, conversation_id="c", role="user",
                                   content="good", event_time=datetime(2026, 10, 28))
        with self.assertRaises(ValueError):
            self.append("x" * 262_145)
        with self.assertRaises(ValueError):
            self.store.search("pat", SCOPE, "hi",
                              privacy_scopes=frozenset({"private"}), limit=101)
        with self.assertRaises(PermissionError):
            self.store.search(None, SCOPE, "hi",
                              privacy_scopes=frozenset({"private"}))

    def test_authorizer_exception_fails_closed_and_rolls_back(self):
        with ConversationArchive(self.path, authorize=lambda *_: 1 / 0) as failing:
            with self.assertRaises(PermissionError):
                failing.append_turn("pat", SCOPE, conversation_id="c",
                                    role="user", content="should never commit")
        self.assertEqual(self.search("should"), ())

    def test_parallel_writes_same_instance_and_reopen(self):
        def writer(n: int):
            return self.append(f"giraffe mark{n}", conversation_id=f"chat{n % 3}")

        with ThreadPoolExecutor(max_workers=8) as pool:
            turns = list(pool.map(writer, range(80)))
        self.assertEqual(len({turn.turn_id for turn in turns}), 80)
        self.store.close()
        self.store = ConversationArchive(self.path, authorize=authorizer)
        self.assertEqual(len(self.search("mark17")), 1)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_two_connections_cannot_both_correct_same_predecessor(self):
        first = self.append("The delivery is crimson")
        barrier = Barrier(2)

        def race(archive: ConversationArchive, replacement: str):
            barrier.wait(timeout=3)
            try:
                return "success", archive.correct("pat", SCOPE, first.turn_id, replacement)
            except KeyError:
                return "stale", None

        with ConversationArchive(self.path, authorize=authorizer) as second:
            with ThreadPoolExecutor(max_workers=2) as pool:
                result_a = pool.submit(race, self.store, "The delivery is scarlet")
                result_b = pool.submit(race, second, "The delivery is maroon")
                outcomes = [result_a.result(timeout=5), result_b.result(timeout=5)]
        self.assertEqual(sorted(status for status, _ in outcomes), ["stale", "success"])
        self.assertEqual(len(self.search("delivery")), 1)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM turns WHERE active=1")
                             .fetchone()[0], 1)
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")

    def test_unknown_schema_rejected(self):
        self.store.close()
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(RuntimeError):
            ConversationArchive(self.path, authorize=authorizer)


if __name__ == "__main__":
    unittest.main()
