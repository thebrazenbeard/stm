"""Opt-in, synthetic-only STM to private DMS cross-repository contract probe.

Never imports user transcripts or contacts a remote service. Requires an explicit
local DMS source checkout at the exact reviewed commit; absent it, skips.
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from stm.archive import ArchiveScope, ArchiveTurn
from stm.deepmemory_handoff import DeepMemoryHandoff, HISTORICAL_ONLY, TargetGovernance
from stm.retention_window_3045 import ThirtyFortyFiveReviewPolicy

DMS_HEAD = "1961f63d92611c5a14c019fdd21e09881bf753b6"
DMS_PATH = os.environ.get("STM_PRIVATE_DMS_SOURCE")
PrivateSTMReceiver = None
if DMS_PATH:
    root = Path(DMS_PATH).resolve()
    observed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if observed != DMS_HEAD:
        raise RuntimeError("private DMS source head differs from reviewed contract")
    sys.path.insert(0, str(root / "tools"))
    from private_stm_receiver import PrivateSTMReceiver


@unittest.skipUnless(PrivateSTMReceiver is not None, "set STM_PRIVATE_DMS_SOURCE to exact reviewed DMS checkout")
class ActualPrivateDMSContract(unittest.TestCase):
    def test_real_stm_handoff_to_durable_private_receiver(self):
        now = datetime.now(timezone.utc)
        admitted = now - timedelta(days=35)
        expires = admitted + timedelta(days=45)
        scope = ArchiveScope("tenant-synthetic", "owner-synthetic", "agent-synthetic")
        principal = object()
        row = ArchiveTurn(
            turn_id="synthetic-turn", conversation_id="synthetic-conversation",
            role="user", content="An invented memory for interface qualification.",
            source="host:synthetic:source", privacy="private",
            event_time=(admitted - timedelta(hours=1)).isoformat(),
            recorded_at=admitted.isoformat(), supersedes_id=None,
            expires_at=expires.isoformat(),
        )
        target = TargetGovernance(
            destination_id="host-owned-synthetic-private",
            retention_until=now + timedelta(days=90),
            supports_deletion=True, supports_correction=True,
            supports_consent_revocation=True, private_destination=True,
            supports_scope_isolation=True,
        )
        current = {"authorized": True, "consent": True, "active": True}
        lock = threading.RLock()
        key = b"e" * 32
        receipt_key = b"r" * 32
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            def dms_auth(who, action, actual, privacy, source, dst):
                return (who is principal and current["authorized"]
                        and actual == (scope.tenant_id, scope.owner_id, scope.agent_id)
                        and privacy in (None, "private") and (dst is None or dst.destination_id == target.destination_id))
            def dms_consent(who, action, actual, privacy, source, dst):
                return current["consent"] and dms_auth(who, action, actual, privacy, source, dst)
            def make_receiver():
                return PrivateSTMReceiver(
                    directory=directory, destination_id=target.destination_id,
                    principal=principal, encryption_key=lambda: key,
                    receipt_key=lambda: receipt_key,
                    authorize=dms_auth, consent=dms_consent, clock=lambda: now,
                    policy_lease=lambda *_: lock,
                    verify_windows_acl=lambda _path: True,  # synthetic ACL stub
                )
            receiver = make_receiver()
            written = {}
            class Sink:
                def submit(self, record, *, target, idempotency_key):
                    written["record"] = record
                    written["key"] = idempotency_key
                    return receiver.submit(record, target=target, idempotency_key=idempotency_key)
            def resolve(who, actual, turn_id):
                if who is principal and actual == scope and current["active"] and turn_id == row.turn_id:
                    return row
                return None
            def authorize(who, action, actual, privacy):
                return (who is principal and current["authorized"]
                        and actual == scope and action == "long_term_export"
                        and privacy in (None, "private"))
            def consent(who, actual, turn_id, privacy, dst):
                return (who is principal and current["consent"] and actual == scope
                        and turn_id == row.turn_id and privacy == "private" and dst == target)
            handoff = DeepMemoryHandoff(
                policy=ThirtyFortyFiveReviewPolicy(), resolve_live_turn=resolve,
                authorize=authorize, consent=consent,
                verify_target=lambda dst, actual, privacy: dst == target and actual == scope and privacy == "private",
                sink=Sink(), verify_receipt=receiver.verify_receipt,
                clock=lambda: now,
            )
            receipt = handoff.submit(principal, scope, row.turn_id, target=target)
            self.assertEqual(receipt.source_version_digest, written["record"].source_version_digest)
            self.assertEqual(written["record"].result_semantics, HISTORICAL_ONLY)
            self.assertEqual(receipt.verification, "HOST_VERIFIED_EXTERNAL_RECEIPT")
            self.assertEqual(receipt.idempotency_key, written["key"])
            independent = make_receiver()  # reopen on fresh SQLite connection
            self.assertTrue(independent.verify_receipt(
                receiver.submit(written["record"], target=target, idempotency_key=written["key"]),
                written["record"], written["key"],
            ))
            second = handoff.submit(principal, scope, row.turn_id, target=target)
            self.assertEqual(first := receipt.idempotency_key, second.idempotency_key)
            with closing(sqlite3.connect(directory / "private_stm.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM records").fetchone()[0], 1)
                encrypted = db.execute("SELECT ciphertext FROM records").fetchone()[0]
            self.assertNotIn(row.content.encode("utf-8"), encrypted)
            current["consent"] = False
            with self.assertRaises(PermissionError):
                handoff.submit(principal, scope, row.turn_id, target=target)
            self.assertEqual(independent.revoke_scope(
                scope=(scope.tenant_id, scope.owner_id, scope.agent_id)), 1)
            self.assertTrue(current["active"])  # handoff never deletes the STM source
