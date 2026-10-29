"""Synthetic one-shot host expiry example; never touches Vera's real archives."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.retention_supervisor import DurableClockFence, SupervisedRetention
from stm.host_retention import run_guarded_once


def main():
    now=datetime.now(timezone.utc)+timedelta(minutes=2)
    scope=ArchiveScope("synthetic","fixture-owner","fixture-agent")
    receipts=[]
    with TemporaryDirectory() as path:
        with DurableClockFence(
            Path(path)/"clock.sqlite",initialize=True,wall_clock=lambda:now
        ) as fence:
            archive=ConversationArchive(
                str(Path(path)/"conversation.sqlite"),
                authorize=lambda principal,action,requested:
                    principal=="fixture-owner" and requested==scope,
            )
            try:
                retained=RetainedConversationArchive(
                    archive,
                    policy=RetentionPolicy(timedelta(days=45),frozenset({"private"})),
                    consent_check=lambda *_:True,
                    clock=fence.now,
                )
                retained.append_turn(
                    "fixture-owner",scope,conversation_id="fixture-only",
                    role="user",content="synthetic expiring data",
                    privacy="private",
                )
                runner=RetentionSweepRunner(
                    retained,targets=lambda:(
                        SweepTarget("fixture-owner",scope,frozenset({"private"})),
                    ),
                )
                host=SupervisedRetention(fence,runner)
                assert run_guarded_once(host,record=receipts.append).deleted==0
                now+=timedelta(days=46)
                result=run_guarded_once(host,record=receipts.append)
                assert result.deleted==1 and result.complete
                assert all("synthetic expiring data" not in repr(item)
                           for item in receipts)
                print("SYNTHETIC_DAY45_HOST_ONESHOT_PASS, NO_REAL_ARCHIVES")
            finally:
                archive.close()


if __name__=="__main__":
    main()
