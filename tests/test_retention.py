"""Host-governed retention policy exercised against real SQLite archives."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import (
    MAX_RETENTION, RetainedConversationArchive, RetentionPolicy,
)


SCOPE = ArchiveScope("tenant-one", "owner-one", "vera")
OTHER = ArchiveScope("tenant-one", "owner-two", "vera")


def authorize(principal: object, verb: str, scope: ArchiveScope) -> bool:
    return principal == scope.owner_id and scope == SCOPE and not verb.endswith(":restricted")


class RetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "retention.sqlite")
        self.archive = ConversationArchive(self.path, authorize=authorize)
        self.current_time = datetime.now(timezone.utc)
        self.consent_allowed = True
        self.policy = RetentionPolicy(
            maximum_age=timedelta(days=2),
            privacy_labels=frozenset({"private", "public"}),
        )
        self.consent_calls: list[tuple[str, str]] = []

        def consent(principal, scope, operation, privacy):
            self.consent_calls.append((operation, privacy))
            return self.consent_allowed and principal == "owner-one" and scope == SCOPE

        self.consent = consent
        self.client = self.make_client()

    def tearDown(self) -> None:
        self.archive.close()
        self.tmp.cleanup()

    def make_client(self, policy=None):
        return RetainedConversationArchive(
            self.archive, policy=self.policy if policy is None else policy,
            consent_check=self.consent, clock=lambda: self.current_time,
        )

    def append(self, content="topaz retrieval beacon", **kwargs):
        return self.client.append_turn(
            "owner-one", SCOPE, conversation_id="chat-1", role="user",
            content=content, **kwargs,
        )

    def search(self, query="topaz"):
        return self.client.search(
            "owner-one", SCOPE, query, privacy_scopes=frozenset({"private"}),
        )

    def sweep(self, **kwargs):
        return self.client.sweep(
            "owner-one", SCOPE, privacy_scopes=frozenset({"private"}), **kwargs,
        )

    def test_policy_must_be_explicit_and_positive_and_bounded(self):
        for age in (timedelta(0), timedelta(days=-1), MAX_RETENTION + timedelta(seconds=1)):
            with self.subTest(age=age), self.assertRaises(ValueError):
                RetentionPolicy(age, frozenset({"private"}))
        for labels in (frozenset(), frozenset({""}), frozenset({"private", 3}), {"private"}):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                RetentionPolicy(timedelta(days=1), labels)
        with self.assertRaises(PermissionError):
            RetainedConversationArchive(self.archive, policy=None, consent_check=self.consent)
        with self.assertRaises(PermissionError):
            RetainedConversationArchive(self.archive, policy=self.policy, consent_check=None)

    def test_consent_controls_append_and_read_and_revocation(self):
        self.consent_allowed = False
        with self.assertRaises(PermissionError):
            self.append()
        self.consent_allowed = True
        row = self.append()
        self.assertIsNotNone(row.expires_at)
        self.assertEqual(len(self.search()), 1)
        self.assertEqual(self.consent_calls[:2], [
            ("archive_write", "private"), ("archive_write", "private"),
        ])
        self.consent_allowed = False
        with self.assertRaises(PermissionError):
            self.search()
        # Consent withdrawal must NOT block the host's authorized deletion.
        self.assertTrue(self.client.delete("owner-one", SCOPE, row.turn_id))
        self.consent_allowed = True
        self.assertEqual(self.search(), ())

    def test_explicit_expiration_is_saved_and_recovered_after_reopen(self):
        first = self.append(requested_age=timedelta(days=1))
        self.assertEqual(
            datetime.fromisoformat(first.expires_at),
            self.current_time + timedelta(days=1),
        )
        self.archive.close()
        self.archive = ConversationArchive(self.path, authorize=authorize)
        self.client = self.make_client()
        self.assertEqual([h.turn.turn_id for h in self.search()], [first.turn_id])
        self.current_time += timedelta(days=1, seconds=1)
        self.assertEqual(self.search(), ())
        preview = self.sweep(dry_run=True)
        self.assertEqual((preview.candidates, preview.deleted), (1, 0))
        self.assertEqual(self.sweep().deleted, 1)
        self.assertEqual(self.sweep().candidates, 0)

    def test_requested_ttl_must_not_exceed_policy(self):
        for age in (timedelta(0), timedelta(days=-1), timedelta(days=3), "one hour"):
            with self.subTest(age=age), self.assertRaises(ValueError):
                self.append(requested_age=age)
        self.assertEqual(self.search(), ())

    def test_scope_privacy_and_impersonation_rejected(self):
        with self.assertRaises(PermissionError):
            self.client.append_turn(
                "intruder", SCOPE, conversation_id="c", role="user", content="fraud",
            )
        with self.assertRaises(PermissionError):
            self.client.append_turn(
                "owner-one", OTHER, conversation_id="c", role="user", content="fraud",
            )
        with self.assertRaises(PermissionError):
            self.append(privacy="restricted")
        self.append()
        with self.assertRaises(PermissionError):
            self.client.search(
                "owner-one", SCOPE, "topaz",
                privacy_scopes=frozenset({"restricted"}),
            )
        with self.assertRaises(PermissionError):
            self.client.sweep(
                "owner-one", OTHER,
                privacy_scopes=frozenset({"private"}),
            )

    def test_dry_run_and_batches_never_expose_text(self):
        self.append("never report this private payload")
        self.append("and never report this one either")
        self.current_time += timedelta(days=3)
        preview = self.sweep(limit=1, dry_run=True)
        self.assertEqual((preview.candidates, preview.deleted, preview.limit), (1, 0, 1))
        self.assertNotIn("payload", repr(preview))
        self.assertNotIn("private", repr(preview))
        self.assertEqual(self.sweep(limit=1).deleted, 1)
        self.assertEqual(self.sweep(limit=1).deleted, 1)
        self.assertEqual(self.sweep(limit=1).deleted, 0)
        for invalid in (0, 1001, -1, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.sweep(limit=invalid)

    def test_legacy_policyless_rows_never_recalled_by_wrapper(self):
        self.archive.append_turn(
            "owner-one", SCOPE, conversation_id="legacy", role="user",
            content="legacy amber note",
        )
        self.assertEqual(
            self.client.search(
                "owner-one", SCOPE, "amber",
                privacy_scopes=frozenset({"private"}),
            ), (),
        )

    def test_correction_does_not_extend_retention_deadline(self):
        first = self.append()
        corrected = self.archive.correct(
            "owner-one", SCOPE, first.turn_id, "corrected topaz beacon",
        )
        self.assertEqual(corrected.expires_at, first.expires_at)
        self.current_time += timedelta(days=3)
        self.assertEqual(self.search(), ())
        self.assertEqual(self.sweep().deleted, 2)


if __name__ == "__main__":
    unittest.main()
