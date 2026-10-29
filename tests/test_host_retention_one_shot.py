"""One-shot host retention: reports partial work as a failed maintenance run."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.retention_supervisor import DurableClockFence, SupervisedRetention
from stm.host_retention import IncompleteSweep, run_guarded_once


class HostRetentionOneShotTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now=datetime.now(timezone.utc)+timedelta(minutes=2)
        self.scope=ArchiveScope("synthetic","alice","vera")
        self.archive=ConversationArchive(
            str(Path(self.temp.name)/"archive.sqlite"),
            authorize=lambda principal,action,scope:
                principal=="alice" and scope==self.scope,
        )
        self.addCleanup(self.archive.close)
        self.fence=DurableClockFence(
            Path(self.temp.name)/"fence.sqlite",
            wall_clock=lambda:self.now,initialize=True)
        self.addCleanup(self.fence.close)
        self.retained=RetainedConversationArchive(
            self.archive,
            policy=RetentionPolicy(timedelta(days=1),frozenset({"private"})),
            consent_check=lambda *_: True,
            clock=self.fence.now,
        )
        self.receipts=[]

    def service(self, **options):
        runner=RetentionSweepRunner(self.retained,
            targets=lambda: (SweepTarget("alice",self.scope,frozenset({"private"})),),
            **options)
        return SupervisedRetention(self.fence,runner)

    def add(self,text):
        return self.retained.append_turn(
            "alice",self.scope,conversation_id="chat",
            role="user",content=text,privacy="private")

    def test_complete_one_shot_calls_content_free_audit(self):
        supervised=self.service()
        result=run_guarded_once(supervised,record=self.receipts.append)
        self.assertTrue(result.complete)
        self.assertEqual((result.deleted,result.pending_targets),(0,0))
        self.assertEqual(self.receipts,[result])
        self.add("one synthetic expired record")
        self.now+=timedelta(days=2)
        result=run_guarded_once(supervised,record=self.receipts.append)
        self.assertEqual(result.deleted,1)
        self.assertEqual(result.legacy_targets,0)
        self.assertEqual(run_guarded_once(supervised,record=self.receipts.append).deleted,0)
        self.assertNotIn("synthetic expired",repr(result))

    def test_pending_backlog_cannot_be_claimed_complete(self):
        self.add("synthetic expired one")
        self.add("synthetic expired two")
        self.now+=timedelta(days=2)
        supervised=self.service(batch_size=1,max_batches_per_target=1)
        with self.assertRaises(IncompleteSweep) as failure:
            run_guarded_once(supervised,record=self.receipts.append)
        self.assertEqual(failure.exception.report.pending_targets,1)
        self.assertFalse(self.receipts[0].complete)
        result=run_guarded_once(supervised,record=self.receipts.append)
        self.assertTrue(result.complete)
        self.assertEqual(result.deleted,1)

    def test_legacy_unretained_rows_require_separate_authority(self):
        self.archive.append_turn(
            "alice",self.scope,conversation_id="legacy",
            role="user",content="legacy synthetic",privacy="private")
        with self.assertRaises(IncompleteSweep) as failure:
            run_guarded_once(self.service(),record=self.receipts.append)
        self.assertEqual(failure.exception.report.legacy_targets,1)
        self.assertEqual(self.receipts[0].deleted,0)

    def test_audit_failure_propagates_without_redeleting(self):
        self.add("synthetic expired data")
        self.now+=timedelta(days=2)
        supervised=self.service()
        def failing(_report):
            raise OSError("audit destination unavailable")
        with self.assertRaisesRegex(OSError,"audit destination unavailable"):
            run_guarded_once(supervised,record=failing)
        result=run_guarded_once(supervised,record=self.receipts.append)
        self.assertEqual(result.deleted,0)
        self.assertTrue(result.complete)

    def test_bogus_supervisor_or_missing_recorder_rejected(self):
        with self.assertRaises(PermissionError):
            run_guarded_once(object(),record=self.receipts.append)
        with self.assertRaises(PermissionError):
            run_guarded_once(self.service(),record=None)


if __name__=="__main__":
    unittest.main()
