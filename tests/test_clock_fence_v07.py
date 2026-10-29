"""Durable host-clock rollback defense: synthetic local evidence only."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm.retention_supervisor import DurableClockFence, SupervisedRetention


class DurableClockFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "clock.sqlite"
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.clock = lambda: self.now

    def test_missing_or_replaced_fence_refuses_automatic_reinitialization(self):
        with self.assertRaises(PermissionError):
            DurableClockFence(self.path, wall_clock=self.clock, initialize=False)
        with DurableClockFence(self.path, wall_clock=self.clock, initialize=True) as fence:
            fence.now()
        self.path.unlink()
        with self.assertRaises(PermissionError):
            DurableClockFence(self.path, wall_clock=self.clock, initialize=False)

    def test_first_read_and_reopen_preserve_high_water_mark(self):
        first = DurableClockFence(self.path, wall_clock=self.clock, initialize=True)
        self.assertEqual(first.now(), self.now)
        self.now += timedelta(days=46)
        self.assertEqual(first.now(), self.now)
        first.close()
        reopened = DurableClockFence(self.path, wall_clock=self.clock, initialize=False)
        self.now -= timedelta(days=20)
        with self.assertRaises(PermissionError):
            reopened.now()
        self.now += timedelta(days=21)
        self.assertEqual(reopened.now(), self.now)
        reopened.close()

    def test_independent_connections_cannot_lower_high_water_mark(self):
        earlier = DurableClockFence(self.path, wall_clock=self.clock, initialize=True)
        later = DurableClockFence(self.path, wall_clock=lambda: self.now + timedelta(hours=1), initialize=False)
        self.assertEqual(later.now(), self.now + timedelta(hours=1))
        with self.assertRaises(PermissionError):
            earlier.now()
        earlier.close()
        later.close()

    def test_invalid_naive_wall_clock_fails_closed(self):
        with DurableClockFence(self.path, wall_clock=lambda: datetime(2026, 1, 1), initialize=True) as fence:
            with self.assertRaises(ValueError):
                fence.now()

    def test_supervisor_blocks_cleanup_when_clock_rolls_back(self):
        class Recorder:
            calls = 0
            def run_once(self):
                self.calls += 1
                return self.calls
        runner = Recorder()
        with DurableClockFence(self.path, wall_clock=self.clock, initialize=True) as fence:
            supervisor = SupervisedRetention(fence, runner)
            self.assertEqual(supervisor.run_once(), 1)
            self.now += timedelta(days=2)
            self.assertEqual(supervisor.run_once(), 2)
            self.now -= timedelta(days=1)
            with self.assertRaises(PermissionError):
                supervisor.run_once()
            self.assertEqual(runner.calls, 2)

    def test_rollback_blocks_real_archived_history_reads(self):
        from stm.archive import ArchiveScope, ConversationArchive
        from stm.retention import RetainedConversationArchive, RetentionPolicy
        scope = ArchiveScope("synthetic", "owner", "vera")
        archive = ConversationArchive(
            str(Path(self.temp.name) / "archive.sqlite"),
            authorize=lambda principal, action, target: principal == "owner" and target == scope,
        )
        self.addCleanup(archive.close)
        with DurableClockFence(self.path, wall_clock=self.clock, initialize=True) as fence:
            retained = RetainedConversationArchive(
                archive,
                policy=RetentionPolicy(timedelta(days=1), frozenset({"private"})),
                consent_check=lambda *_: True,
                clock=fence.now,
            )
            retained.append_turn(
                "owner", scope, conversation_id="chat", role="user",
                content="synthetic private history", privacy="private",
            )
            self.now += timedelta(days=2)
            self.assertEqual(
                retained.search("owner", scope, "synthetic",
                                privacy_scopes=frozenset({"private"})), ()
            )
            self.now -= timedelta(days=1, hours=12)
            with self.assertRaises(PermissionError):
                retained.search("owner", scope, "synthetic",
                                privacy_scopes=frozenset({"private"}))


if __name__ == "__main__":
    unittest.main()
