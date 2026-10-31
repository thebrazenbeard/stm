"""Source-level shared-reader replay tests; in-memory anchor is NOT a host."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock, Thread
import copy
import secrets
import sqlite3
import tempfile
import unittest

from stm.auth_broker import (
    ConversationCredentialSpec, HmacConversationBroker, HmacCredentialIssuer,
)
from stm.host_replay import GENESIS, HostAnchoredJtiConsumer
from stm.models import SessionKey


class CloneableFakeAnchor:
    """Deliberately copyable negative control. NEVER production authority."""

    def __init__(self):
        self._lock = RLock()
        self.state = {}
        self.claimed = set()

    def provision(self, scope):
        with self._lock:
            if scope in self.state:
                raise ValueError("duplicate scope")
            self.state[scope] = (0, GENESIS)

    def claim_provisioning(self, scope):
        with self._lock:
            if scope in self.claimed or scope not in self.state:
                return False
            self.claimed.add(scope)
            return True

    def current(self, scope):
        with self._lock:
            return self.state.get(scope)

    def compare_advance(self, scope, epoch, old, new):
        with self._lock:
            if self.state.get(scope) != (epoch, old):
                return False
            self.state[scope] = (epoch + 1, new)
            return True

    def snapshot(self):
        with self._lock:
            return copy.deepcopy((self.state, self.claimed))

    def restore(self, snapshot):
        with self._lock:
            self.state, self.claimed = copy.deepcopy(snapshot)


@dataclass(frozen=True)
class FakeTransport:
    bearer: str
    peer: str


class HostAnchoredJtiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "replay.sqlite"
        self.anchor = CloneableFakeAnchor()
        self.now = int(datetime.now(timezone.utc).timestamp())
        self.digest_key = secrets.token_bytes(32)
        self.params = dict(anchor=self.anchor, host_id="host-1", issuer="trusted-host",
                           principal_id="principal-1", digest_key=self.digest_key,
                           clock=lambda: self.now)
        self.first = HostAnchoredJtiConsumer(self.path, **self.params)
        self.anchor.provision(self.first.scope)
        self.first.provision_new()

    def again(self):
        return HostAnchoredJtiConsumer(self.path, **self.params)

    def reserve(self, consumer, jti="secret-opaque-jti-1"):
        return consumer("trusted-host", "owner-one", jti, self.now + 60)

    def test_cross_reader_replay_denied_and_no_raw_jti_in_ledger(self):
        self.assertTrue(self.reserve(self.first))
        self.assertFalse(self.reserve(self.again()))
        self.assertNotIn(b"secret-opaque-jti-1", self.path.read_bytes())

    def test_concurrent_readers_one_winner(self):
        results = []
        def worker():
            results.append(self.reserve(self.again(), "same-token-2"))
        threads = [Thread(target=worker) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 9)

    def test_restored_sqlite_snapshot_rejected_when_anchor_intact(self):
        copy_path = Path(self.temp.name) / "snapshot.sqlite"
        src = sqlite3.connect(self.path)
        dst = sqlite3.connect(copy_path)
        src.backup(dst)
        src.close()
        dst.close()
        self.assertTrue(self.reserve(self.first, "older-token"))
        self.path.write_bytes(copy_path.read_bytes())
        with self.assertRaises(PermissionError):
            self.reserve(self.again(), "older-token")

    def test_dual_rollback_is_known_unresolved_host_falsifier(self):
        copy_path = Path(self.temp.name) / "snapshot.sqlite"
        with closing(sqlite3.connect(self.path)) as src, closing(sqlite3.connect(copy_path)) as dst:
            src.backup(dst)
        old_anchor = self.anchor.snapshot()
        self.assertTrue(self.reserve(self.first, "dual-token"))
        self.path.write_bytes(copy_path.read_bytes())
        self.anchor.restore(old_anchor)
        self.assertTrue(self.reserve(self.again(), "dual-token"),
                        "cloneable synthetic anchor cannot prove host antirollback")

    def test_deleted_ledger_fails_closed(self):
        self.path.unlink()
        with self.assertRaises(PermissionError):
            self.reserve(self.again())
        with self.assertRaises(PermissionError):
            self.again().provision_new()

    def test_real_hmac_issuer_and_broker_use_shared_consumer(self):
        current = datetime.fromtimestamp(self.now, timezone.utc)
        hmac_key = secrets.token_bytes(32)
        issuer = HmacCredentialIssuer(hmac_key, issuer="trusted-host", audience="stm",
                                      clock=lambda: current)
        spec = ConversationCredentialSpec(
            subject="owner-one", session=SessionKey("tenant", "owner", "model", "session"),
            conversation_id="conversation", privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({"archive_read"}), channel_binding="host-os-peer",
            max_working_ttl_seconds=60, archive_consent=True,
            archive_retention_seconds=3600,
        )
        request = FakeTransport(issuer.issue(spec), "host-os-peer")
        def broker(consumer):
            return HmacConversationBroker(
                hmac_key, issuer="trusted-host", audience="stm",
                token_from_request=lambda req: req.bearer,
                channel_binding_from_request=lambda req: req.peer,
                is_revoked=lambda *_: False, clock=lambda: current,
                single_use=True, consume_jti=consumer)
        self.assertIsNotNone(broker(self.first).resolve(request))
        with self.assertRaisesRegex(PermissionError, "replay"):
            broker(self.again()).resolve(request)

    def test_wrong_issuer_invalid_jti_and_expired_fail_closed(self):
        self.assertFalse(self.first("other-issuer", "owner-one", "x", self.now + 60))
        self.assertFalse(self.first("trusted-host", "owner-one", "💀", self.now + 60))
        self.assertFalse(self.first("trusted-host", "owner-one", "x", self.now - 1))
        self.assertFalse(self.first("trusted-host", "owner-one", "x", self.now + 301))

if __name__ == "__main__":
    unittest.main()
