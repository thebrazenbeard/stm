"""Contract checks for read-only, scoped historical conversation evidence."""

from datetime import timezone
import os
import tempfile
import unittest

from stm.archive import ArchiveHit, ArchiveScope, ArchiveTurn, ConversationArchive
from stm.archive_adapter import ArchiveHistoryReader
from stm.history import HistoricalEvidenceBridge, HISTORICAL_ONLY
from stm.models import SessionKey


class RecordingArchive:
    def __init__(self, hits=()):
        self.hits = hits
        self.calls = []

    def search(self, principal, scope, query, *, privacy_scopes, limit):
        self.calls.append((principal, scope, query, privacy_scopes, limit))
        return self.hits


def hit(*, privacy="private", source="conversation:chat1", turn_id="turn:1",
        conversation_id="old / chat"):
    return ArchiveHit(
        turn=ArchiveTurn(
            turn_id=turn_id,
            conversation_id=conversation_id,
            role="user",
            content="The cobalt bike was sold last month.",
            source=source,
            privacy=privacy,
            event_time="2026-10-01T12:00:00+00:00",
            recorded_at="2026-10-01T12:03:00+00:00",
            supersedes_id=None,
        ),
        score=-1.5,
    )


class ArchiveAdapterTests(unittest.TestCase):
    def setUp(self):
        self.scope = SessionKey("tenant-A", "owner-A", "agent-A", "new-chat")
        self.principal = object()

    def test_adapter_preserves_source_and_explicit_historical_semantics(self):
        backend = RecordingArchive((hit(),))
        reader = ArchiveHistoryReader(backend, self.principal)
        result = reader.search("cobalt bicycle", scope=self.scope,
                               authorized_privacy_scopes=frozenset({"private"}), limit=4)

        self.assertEqual(backend.calls, [(
            self.principal, ArchiveScope("tenant-A", "owner-A", "agent-A"),
            "cobalt bicycle", frozenset({"private"}), 4,
        )])
        self.assertEqual(len(result), 1)
        evidence = result[0]
        self.assertEqual(evidence.memory_id, "turn:1")
        self.assertEqual(evidence.excerpt, "The cobalt bike was sold last month.")
        self.assertEqual(evidence.source_ids, ("turn:1", "conversation:chat1"))
        self.assertEqual(evidence.privacy_scope, "private")
        self.assertEqual(evidence.event_time, "2026-10-01T12:00:00+00:00")
        self.assertEqual(evidence.recorded_at, "2026-10-01T12:03:00+00:00")
        self.assertEqual(evidence.result_semantics, HISTORICAL_ONLY)
        self.assertIn("historical", evidence.provenance_ceiling)
        self.assertIn("verify", evidence.currentness_rule)
        self.assertIn("old%20%2F%20chat/turn%3A1", evidence.ledger_path)
        self.assertEqual(evidence.retrieved_at.tzinfo, timezone.utc)

    def test_bridge_accepts_reader_without_promoting_to_stm(self):
        backend = RecordingArchive((hit(),))
        reader = ArchiveHistoryReader(backend, self.principal)
        bridge = HistoricalEvidenceBridge(
            lambda query, scope, privacy, limit: reader.search(
                query, scope=scope, authorized_privacy_scopes=privacy, limit=limit,
            )
        )
        evidence = bridge.search(
            "bike", scope=self.scope,
            authorized_privacy_scopes=frozenset({"private"}), limit=1,
        )
        self.assertEqual(evidence[0].result_semantics, HISTORICAL_ONLY)
        self.assertFalse(hasattr(reader, "append_turn"))
        self.assertFalse(hasattr(reader, "admit"))

    def test_privacy_violation_from_untrusted_backend_is_rejected(self):
        backend = RecordingArchive((hit(privacy="shared"),))
        with self.assertRaises(PermissionError):
            ArchiveHistoryReader(backend, self.principal).search(
                "bike", scope=self.scope,
                authorized_privacy_scopes=frozenset({"private"}),
            )

    def test_backend_result_overflow_is_rejected(self):
        backend = RecordingArchive((hit(), hit(turn_id="turn:2")))
        with self.assertRaises(ValueError):
            ArchiveHistoryReader(backend, self.principal).search(
                "bike", scope=self.scope,
                authorized_privacy_scopes=frozenset({"private"}), limit=1,
            )

    def test_invalid_requests_fail_before_backend_access(self):
        backend = RecordingArchive((hit(),))
        reader = ArchiveHistoryReader(backend, self.principal)
        for arguments, error in (
            ({"query": "", "scope": self.scope,
              "authorized_privacy_scopes": frozenset({"private"})}, ValueError),
            ({"query": "bike", "scope": object(),
              "authorized_privacy_scopes": frozenset({"private"})}, PermissionError),
            ({"query": "bike", "scope": self.scope,
              "authorized_privacy_scopes": frozenset()}, PermissionError),
            ({"query": "bike", "scope": self.scope,
              "authorized_privacy_scopes": frozenset({"private"}), "limit": 0}, ValueError),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(error):
                reader.search(**arguments)
        self.assertEqual(backend.calls, [])

    def test_principal_is_required(self):
        with self.assertRaises(ValueError):
            ArchiveHistoryReader(RecordingArchive(), None)
        with self.assertRaises(ValueError):
            ArchiveHistoryReader(None, object())

    def test_real_archive_recovers_old_conversation_as_evidence_not_active_memory(self):
        """A different chat under the same owner can be searched only with a grant."""
        with tempfile.TemporaryDirectory() as directory:
            archive = ConversationArchive(
                os.path.join(directory, "conversation.sqlite3"),
                authorize=lambda principal, action, scope: (
                    principal == "verified-host-principal"
                    and scope == ArchiveScope("tenant-A", "owner-A", "agent-A")
                ),
            )
            try:
                archive.append_turn(
                    "verified-host-principal",
                    ArchiveScope("tenant-A", "owner-A", "agent-A"),
                    conversation_id="old-chat", role="user",
                    content="The octagonal telescope is in my workshop.",
                    source="user:old-chat:turn-1", privacy="private",
                )
                reader = ArchiveHistoryReader(archive, "verified-host-principal")
                evidence = reader.search(
                    "octagonal telescope", scope=self.scope,
                    authorized_privacy_scopes=frozenset({"private"}),
                )
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].source_ids[1], "user:old-chat:turn-1")
                self.assertEqual(evidence[0].result_semantics, HISTORICAL_ONLY)
                with self.assertRaises(PermissionError):
                    ArchiveHistoryReader(archive, "unverified-caller").search(
                        "octagonal telescope", scope=self.scope,
                        authorized_privacy_scopes=frozenset({"private"}),
                    )
                other_owner = SessionKey("tenant-A", "owner-B", "agent-A", "new-chat")
                with self.assertRaises(PermissionError):
                    reader.search("octagonal telescope", scope=other_owner,
                                  authorized_privacy_scopes=frozenset({"private"}))
            finally:
                archive.close()


if __name__ == "__main__":
    unittest.main()
