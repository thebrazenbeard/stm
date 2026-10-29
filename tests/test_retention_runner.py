"""Host-operated retention sweeps against actual scoped SQLite storage."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import sqlite3
import unittest

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget


ALICE = ArchiveScope("synthetic", "alice", "vera")
BOB = ArchiveScope("synthetic", "bob", "vera")
PRIVATE = frozenset({"private"})


class RetentionRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "conversation.sqlite3")
        self.now = datetime.now(timezone.utc)
        self.delete_allowed = {"alice", "bob"}
        self.consent = True
        self.archive = self.open_archive()
        self.policy = RetentionPolicy(
            maximum_age=timedelta(days=1), privacy_labels=PRIVATE,
        )
        self.client = self.make_client()
        self.targets = (
            SweepTarget("alice", ALICE, PRIVATE),
            SweepTarget("bob", BOB, PRIVATE),
        )

    def tearDown(self) -> None:
        self.archive.close()
        self.temp.cleanup()

    def authorize(self, principal: object, action: str, scope: ArchiveScope) -> bool:
        if principal != scope.owner_id:
            return False
        if action in ("expire", "audit_legacy", "write_privacy:private") and principal not in self.delete_allowed:
            return False
        return True

    def open_archive(self) -> ConversationArchive:
        return ConversationArchive(self.path, authorize=self.authorize)

    def make_client(self) -> RetainedConversationArchive:
        return RetainedConversationArchive(
            self.archive, policy=self.policy,
            consent_check=lambda _principal, _scope, _verb, _privacy: self.consent,
            clock=lambda: self.now,
        )

    def append(self, scope: ArchiveScope, content: str) -> None:
        self.client.append_turn(
            scope.owner_id, scope, conversation_id="chat", role="user",
            content=content, privacy="private",
        )

    def runner(self, **kwargs: object) -> RetentionSweepRunner:
        options = {"targets": lambda: self.targets}
        options.update(kwargs)
        return RetentionSweepRunner(self.client, **options)

    def count_rows(self) -> int:
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute("SELECT count(*) FROM turns").fetchone()[0]

    def test_startup_catchup_after_offline_restart_and_no_automatic_background(self):
        for i in range(4):
            self.append(ALICE, f"expired blue candle {i}")
        self.append(BOB, "expired yellow candle")
        self.now += timedelta(days=2)
        runner = self.runner(batch_size=2, max_batches_per_target=4)
        self.assertEqual(self.count_rows(), 5)  # Construction did no deletion.

        # Simulate process interruption and recovery from the persisted DB.
        self.archive.close()
        self.archive = self.open_archive()
        self.client = self.make_client()
        recovered = self.runner(batch_size=2, max_batches_per_target=4)
        receipt = recovered.run_once()
        self.assertEqual(receipt.targets, 2)
        self.assertEqual(receipt.deleted, 5)
        self.assertTrue(receipt.complete)
        self.assertEqual(self.count_rows(), 0)
        self.assertEqual(recovered.run_once().deleted, 0)
        self.assertNotIn("blue", repr(receipt))
        self.assertNotIn("alice", repr(receipt))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES('integrity-check', 1)")

    def test_huge_backlog_is_bounded_and_receipts_never_claim_completion_early(self):
        for i in range(5):
            self.append(ALICE, f"item {i}")
        self.now += timedelta(days=3)
        run = self.runner(batch_size=2, max_batches_per_target=1,
                          targets=lambda: [self.targets[0]])
        first = run.run_once()
        self.assertEqual((first.deleted, first.pending_targets, first.complete), (2, 1, False))
        self.assertEqual(self.count_rows(), 3)
        self.assertEqual(run.run_once().deleted, 2)
        third = run.run_once()
        self.assertEqual((third.deleted, third.complete), (1, True))
        self.assertEqual(self.count_rows(), 0)

    def test_registry_validation_happens_before_any_deletion(self):
        self.append(ALICE, "expiring note")
        self.now += timedelta(days=2)
        for registry in (
            lambda: (),
            lambda: [self.targets[0], self.targets[0]],
            lambda: [self.targets[0], object()],
            lambda: [self.targets[0], self.targets[1]],
        ):
            with self.subTest(registry=registry):
                max_targets = 1 if registry() == [self.targets[0], self.targets[1]] else 64
                runner = self.runner(targets=registry, max_targets=max_targets)
                with self.assertRaises(PermissionError):
                    runner.run_once()
                self.assertEqual(self.count_rows(), 1)

        def failing_registry():
            yield self.targets[0]
            raise RuntimeError("private hidden owner details")

        with self.assertRaises(PermissionError) as error:
            self.runner(targets=failing_registry).run_once()
        self.assertNotIn("private hidden", str(error.exception))
        self.assertEqual(self.count_rows(), 1)

    def test_missing_policy_registry_identity_and_invalid_limits_fail_closed(self):
        with self.assertRaises(PermissionError):
            RetentionSweepRunner(self.archive, targets=lambda: self.targets)
        with self.assertRaises(PermissionError):
            RetentionSweepRunner(self.client, targets=None)
        with self.assertRaises(PermissionError):
            SweepTarget(None, ALICE, PRIVATE)
        with self.assertRaises(PermissionError):
            SweepTarget("alice", ALICE, frozenset())
        for options in ({"batch_size": 0}, {"batch_size": True},
                        {"batch_size": 1001}, {"max_targets": 0},
                        {"max_batches_per_target": 0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.runner(**options)

    def test_consent_revocation_does_not_prevent_required_deletion(self):
        self.append(ALICE, "post-consent cleanup marker")
        self.now += timedelta(days=2)
        self.consent = False
        summary = self.runner(targets=lambda: [self.targets[0]]).run_once()
        self.assertEqual(summary.deleted, 1)
        self.assertEqual(self.count_rows(), 0)

    def test_authority_rechecked_and_retry_is_idempotent_after_partial_progress(self):
        self.append(ALICE, "alice expiring note")
        self.append(BOB, "bob expiring note")
        self.now += timedelta(days=2)
        self.delete_allowed.remove("bob")
        with self.assertRaises(PermissionError):
            self.runner().run_once()
        self.assertEqual(self.count_rows(), 1)  # Alice committed, Bob denied.
        self.delete_allowed.add("bob")
        receipt = self.runner().run_once()
        self.assertEqual(receipt.deleted, 1)
        self.assertEqual(self.count_rows(), 0)

    def test_periodic_host_loop_runs_startup_then_stops_with_content_free_report(self):
        self.append(ALICE, "ephemeral sandcastle record")
        self.now += timedelta(days=2)
        done = Event()
        reports = []

        def on_report(receipt):
            reports.append(receipt)
            done.set()  # Deterministic stop, no sleeps or daemon thread.

        run = self.runner(targets=lambda: [self.targets[0]])
        run.run_periodically(done, interval=timedelta(minutes=1), report=on_report)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].deleted, 1)
        self.assertEqual(self.count_rows(), 0)
        with self.assertRaises(ValueError):
            run.run_periodically(Event(), interval=timedelta(0))
        with self.assertRaises(ValueError):
            run.run_periodically(Event(), interval=timedelta(microseconds=1))
        with self.assertRaises(TypeError):
            run.run_periodically(None, interval=timedelta(minutes=1))

    def test_policy_scoped_runner_does_not_touch_unmanaged_labels(self):
        expires = self.now + timedelta(hours=1)
        self.archive.append_turn(
            "alice", ALICE, conversation_id="c", role="user",
            content="unmanaged restricted label", privacy="restricted",
            expires_at=expires,
        )
        self.append(ALICE, "managed private label")
        self.now += timedelta(days=2)
        receipt = self.runner(targets=lambda: [self.targets[0]]).run_once()
        self.assertEqual(receipt.deleted, 1)
        self.assertEqual(self.count_rows(), 1)  # Not falsely claimed cleaned.


if __name__ == "__main__":
    unittest.main()
