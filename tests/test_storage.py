"""Unittest-only storage tests; no network, external model, or database."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm.models import CapacityExceeded, MemoryRecord, SessionKey, VersionConflict
from stm.storage import InMemoryStore
from stm.history import HISTORICAL_ONLY, HistoricalEvidence, HistoricalEvidenceBridge


T0 = datetime(2026, 10, 28, 16, 0, tzinfo=timezone.utc)


def scope(*, tenant="t1", owner="o1", agent="a1", session="s1") -> SessionKey:
    return SessionKey(tenant, owner, agent, session)


def item(id: str, *, key: SessionKey | None = None, pinned=False,
         created_at=T0, expires_at=None, version=1, origin="direct") -> MemoryRecord:
    return MemoryRecord(
        id=id, scope=key or scope(), content=f"working observation {id}",
        role="user", source="turn:7", kind="observation", privacy="private",
        pinned=pinned, created_at=created_at, updated_at=created_at,
        expires_at=expires_at, version=version, origin=origin,
    )


class MutableClock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.clock = MutableClock()
        self.store = InMemoryStore(max_items_per_session=3, max_sessions=4,
                                   clock=self.clock)

    def test_scope_isolation_all_four_identity_dimensions(self):
        roots = [scope(), scope(tenant="t2"), scope(owner="o2"),
                 scope(agent="a2"), scope(session="s2")]
        for n, key in enumerate(roots):
            self.store.add(item("identical-id", key=key))
            self.assertEqual(self.store.get(key, "identical-id").scope, key)
            self.assertEqual(self.store.list(key)[0].scope, key)
            if n == 3:
                # max_sessions is four; don't attempt a fifth until one is gone.
                self.assertFalse(self.store.delete(key, "different-id"))
                self.assertEqual(self.store.clear(key), 1)
        self.assertEqual(self.store.stats(roots[-1])["items"], 1)
        self.assertIsNone(self.store.get(scope(owner="unknown"), "identical-id"))
        self.assertFalse(self.store.delete(scope(owner="unknown"), "identical-id"))
        self.assertIsNotNone(self.store.get(scope(), "identical-id"))

    def test_capacity_evicts_oldest_unpinned_and_protects_pinned(self):
        self.store.add(item("keep", pinned=True))
        self.store.add(item("old", created_at=T0 + timedelta(seconds=1)))
        self.store.add(item("new", created_at=T0 + timedelta(seconds=2)))
        self.store.add(item("incoming", created_at=T0 + timedelta(seconds=3)))
        self.assertEqual([r.id for r in self.store.list(scope())],
                         ["keep", "new", "incoming"])
        self.assertEqual(self.store.stats(scope())["evictions"], 1)

    def test_capacity_refusal_when_all_pinned_keeps_existing(self):
        for n in range(3):
            self.store.add(item(str(n), pinned=True))
        with self.assertRaises(CapacityExceeded):
            self.store.add(item("surplus"))
        self.assertEqual({r.id for r in self.store.list(scope())}, {"0", "1", "2"})
        self.assertEqual(self.store.stats(scope())["evictions"], 0)

    def test_session_limit_refuses_unrelated_scope(self):
        for n in range(4):
            self.store.add(item("a", key=scope(owner=str(n))))
        with self.assertRaises(CapacityExceeded):
            self.store.add(item("a", key=scope(owner="fifth")))
        self.assertEqual(self.store.stats(scope(owner="0"))["active_sessions"], 4)

    def test_ttl_purges_pinned_and_regular_and_declines_expired_admission(self):
        expiration = T0 + timedelta(seconds=5)
        self.store.add(item("regular", expires_at=expiration))
        self.store.add(item("pinned", pinned=True, expires_at=expiration))
        self.clock.now = expiration
        self.assertEqual(self.store.prune(scope()), 2)
        self.assertEqual(self.store.list(scope()), [])
        self.assertEqual(self.store.stats(scope())["expirations"], 2)
        with self.assertRaises(ValueError):
            self.store.add(item("already-due", expires_at=expiration))

    def test_corrections_cas_stale_version_and_source_integrity(self):
        original = item("a")
        self.store.add(original)
        corrected = original.corrected("corrected observation", T0 + timedelta(seconds=1))
        self.store.replace(scope(), corrected, expected_version=1)
        self.assertEqual(self.store.get(scope(), "a").version, 2)
        with self.assertRaises(VersionConflict):
            self.store.replace(scope(), corrected, expected_version=1)
        with self.assertRaises(PermissionError):
            self.store.replace(scope(owner="other"), corrected, expected_version=2)
        with self.assertRaises(ValueError):
            self.store.replace(scope(), replace(corrected, source="unverified",
                                                version=3), expected_version=2)
        with self.assertRaises(ValueError):
            self.store.replace(scope(), replace(corrected, origin="historical",
                                                version=3), expected_version=2)
        self.assertEqual(self.store.get(scope(), "a"), corrected)
        self.assertTrue(self.store.delete(scope(), "a"))
        self.assertFalse(self.store.delete(scope(), "a"))

    def test_concurrent_writes_have_no_leaks_or_over_capacity(self):
        store = InMemoryStore(max_items_per_session=20, max_sessions=2,
                              clock=self.clock)
        keys = (scope(owner="left"), scope(owner="right"))

        def write(n):
            key = keys[n % 2]
            record = item(str(n), key=key,
                          created_at=T0 + timedelta(microseconds=n))
            store.add(record)

        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(write, range(300)))
        for key in keys:
            records = store.list(key)
            self.assertEqual(len(records), 20)
            self.assertEqual(len({r.id for r in records}), 20)
            self.assertTrue(all(record.scope == key for record in records))
            self.assertEqual(store.stats(key)["evictions"], 130)

    def test_checkpoint_roundtrip_private_scope_checksum(self):
        first = item("one", origin="historical")
        self.store.add(first)
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            digest = self.store.checkpoint(scope(), path)
            self.assertEqual(len(digest), 64)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.store.checkpoint(scope(), path)
            fresh = InMemoryStore(clock=self.clock)
            self.assertEqual(fresh.restore(scope(), path), 1)
            self.assertEqual(fresh.get(scope(), "one"), first)
            with self.assertRaises(FileExistsError):
                fresh.restore(scope(), path)
            with self.assertRaises(PermissionError):
                fresh.restore(scope(owner="attacker"), path)
            self.assertEqual(fresh.stats(scope(owner="attacker"))["items"], 0)

    def test_corrupt_checkpoint_never_partially_replaces_records(self):
        self.store.add(item("original"))
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            self.store.checkpoint(scope(), path)
            body = json.loads(path.read_text())
            body["body"]["records"][0]["content"] = "tampered"
            path.write_text(json.dumps(body))
            with self.assertRaises(ValueError):
                self.store.restore(scope(), path, overwrite=True)
            self.assertEqual(self.store.get(scope(), "original").content,
                             "working observation original")

    def test_recovery_drops_expired_rows(self):
        self.store.add(item("short-lived", expires_at=T0 + timedelta(seconds=1)))
        self.store.add(item("survivor"))
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            self.store.checkpoint(scope(), path)
            self.clock.now = T0 + timedelta(seconds=10)
            fresh = InMemoryStore(clock=self.clock)
            self.assertEqual(fresh.restore(scope(), path), 1)
            self.assertEqual([r.id for r in fresh.list(scope())], ["survivor"])

    def test_restoration_refuses_oversized_payload_without_mutation(self):
        self.store.add(item("survivor"))
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "big-checkpoint.json"
            path.write_text("x" * 400)
            small_store = InMemoryStore(clock=self.clock, max_checkpoint_bytes=200)
            small_store.add(item("keep"))
            with self.assertRaises(CapacityExceeded):
                small_store.restore(scope(), path, overwrite=True)
            self.assertEqual([r.id for r in small_store.list(scope())], ["keep"])


class HistoricalBoundaryTests(unittest.TestCase):
    def test_explicit_privacy_and_historical_only_semantics(self):
        key = scope()
        calls = []

        def fetch(query, session, privacy, limit):
            calls.append((query, session, privacy, limit))
            return [HistoricalEvidence(
                memory_id="historical:1", excerpt="a historical event",
                source_ids=("source:3",), privacy_scope="private",
                provenance_ceiling="direct quotation", currentness_rule="revalidate",
                event_time="2024-01-01", recorded_at=None, ledger_path="ledger/a.jsonl",
                retrieved_at=T0,
            )]

        bridge = HistoricalEvidenceBridge(fetch)
        with self.assertRaises(PermissionError):
            bridge.search("event", scope=key, authorized_privacy_scopes=frozenset())
        self.assertEqual(calls, [])
        with self.assertRaises(PermissionError):
            bridge.search("event", scope=key,
                          authorized_privacy_scopes=frozenset({"public"}))
        records = bridge.search("event", scope=key,
                                authorized_privacy_scopes=frozenset({"private"}))
        self.assertEqual(records[0].result_semantics, HISTORICAL_ONLY)
        self.assertFalse(hasattr(bridge, "admit"))
        self.assertFalse(hasattr(bridge, "write"))

    def test_wrong_result_type_and_forbidden_authority_claim(self):
        key = scope()
        with self.assertRaises(ValueError):
            HistoricalEvidence(
                memory_id="h1", excerpt="text", source_ids=("s1",),
                privacy_scope="private", provenance_ceiling="source",
                currentness_rule="revalidate", event_time=None, recorded_at=None,
                ledger_path="ledger/a.jsonl", retrieved_at=T0,
                result_semantics="CURRENT_AUTHORITY",
            )
        bridge = HistoricalEvidenceBridge(lambda *_: [item("live")])
        with self.assertRaises(TypeError):
            bridge.search("context", scope=key,
                          authorized_privacy_scopes=frozenset({"private"}))


if __name__ == "__main__":
    unittest.main()
