"""Fail-closed binding between supervised sweeps and the durable clock."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.retention_supervisor import DurableClockFence, SupervisedRetention


class SupervisorClockBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = datetime.now(timezone.utc) + timedelta(hours=1)
        self.scope = ArchiveScope("synthetic", "owner", "vera")
        self.db = ConversationArchive(
            str(Path(self.tmp.name) / "archive.sqlite"),
            authorize=lambda principal, action, scope:
                principal == "owner" and scope == self.scope,
        )
        self.addCleanup(self.db.close)

    def retained(self, clock):
        return RetainedConversationArchive(
            self.db,
            policy=RetentionPolicy(timedelta(days=1), frozenset({"private"})),
            consent_check=lambda *_: True,
            clock=clock,
        )

    def runner(self, retained):
        return RetentionSweepRunner(
            retained,
            targets=lambda: (SweepTarget("owner",self.scope,frozenset({"private"})),),
        )

    def test_mismatched_clock_rejected_before_any_sweep(self):
        with DurableClockFence(Path(self.tmp.name)/"clock.sqlite",
                               wall_clock=lambda:self.now,initialize=True) as fence:
            wrong_clock=self.retained(lambda: self.now)
            runner=self.runner(wrong_clock)
            with self.assertRaises(PermissionError):
                SupervisedRetention(fence,runner)

    def test_unrecognized_runner_rejected(self):
        class Fake:
            def run_once(self):
                return "claimed completion"
        with DurableClockFence(Path(self.tmp.name)/"clock.sqlite",
                               wall_clock=lambda:self.now,initialize=True) as fence:
            with self.assertRaises(PermissionError):
                SupervisedRetention(fence,Fake())

    def test_genuine_bound_sweep_and_rollback_after_restart(self):
        scope=self.scope
        clock_db=Path(self.tmp.name)/"clock.sqlite"
        with DurableClockFence(clock_db,wall_clock=lambda:self.now,initialize=True) as fence:
            retained=self.retained(fence.now)
            retained.append_turn("owner",scope,conversation_id="synthetic",
                                 role="user",content="synthetic evidence",privacy="private")
            supervised=SupervisedRetention(fence,self.runner(retained))
            self.assertEqual(supervised.run_once().deleted,0)
        self.now+=timedelta(days=2)

        with DurableClockFence(clock_db,wall_clock=lambda:self.now,initialize=False) as fence:
            retained=self.retained(fence.now)
            supervised=SupervisedRetention(fence,self.runner(retained))
            self.assertEqual(supervised.run_once().deleted,1)
            self.now-=timedelta(days=1)
            with self.assertRaises(PermissionError):
                supervised.run_once()

    def test_mutating_runner_clock_after_construction_is_rejected(self):
        with DurableClockFence(Path(self.tmp.name)/"clock.sqlite",
                               wall_clock=lambda:self.now,initialize=True) as fence:
            retained=self.retained(fence.now)
            runner=self.runner(retained)
            supervisor=SupervisedRetention(fence,runner)
            runner._archive=self.retained(lambda:self.now)
            with self.assertRaises(PermissionError):
                supervisor.run_once()


if __name__=="__main__":
    unittest.main()
