"""Adversarial, synthetic 30/45-day retention and historical handoff tests.

These compose the real SQLite archive, retention wrapper, review policy and
optional handoff boundary. The test sink has no network or DMS credentials.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from stm import ArchiveScope, ConversationArchive, SessionKey
from stm.deepmemory_handoff import DeepMemoryHandoff, HandoffUnverified, TargetGovernance
from stm.handoff_policy import HandoffReviewQueue, HandoffReviewTicket
from stm.core import STM
from stm.retention import RetainedConversationArchive
from stm.retention_window_3045 import LOCAL_EXPIRE_AFTER, ThirtyFortyFiveWindow
from stm.vera_bridge import VerifiedConversation


PRIVATE = frozenset({"private"})
HOST = "synthetic-host-principal"
SCOPE = ArchiveScope("synthetic-tenant", "synthetic-owner", "vera")
OTHER = ArchiveScope("synthetic-tenant", "other-owner", "vera")
CONTENT = "Mauve paperclip calibration"


class FakePrivateSink:
    """Deliberately untrusted in-memory transport, not a DMS implementation."""

    def __init__(self) -> None:
        self.requests = []
        self.raise_on_submit = False

    def submit(self, record, *, target, idempotency_key):
        self.requests.append((record, target, idempotency_key))
        if self.raise_on_submit:
            raise OSError("synthetic transport interrupted")
        return {"external_record_id": "synthetic:receipt-01", "key": idempotency_key}


class ThirtyFortyFiveAdversarialTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = ConversationArchive(
            str(Path(temporary.name) / "synthetic-history.sqlite"),
            authorize=lambda principal, action, scope: principal == HOST and scope == SCOPE,
        )
        self.addCleanup(self.archive.close)
        self.window = ThirtyFortyFiveWindow()
        self.now = datetime.now(timezone.utc) - timedelta(milliseconds=50)
        self.consent_to_archive = True
        self.retained = self.window.retained_archive(
            self.archive,
            consent_check=lambda principal, scope, action, privacy: (
                self.consent_to_archive and principal == HOST
                and scope == SCOPE and privacy == "private"
            ),
            clock=lambda: self.now,
        )
        self.turn = self.retained.append_turn(
            HOST, SCOPE, conversation_id="synthetic-conversation", role="user",
            content=CONTENT, source="synthetic:conversation:1",
        )
        self.admitted = datetime.fromisoformat(self.turn.recorded_at)
        self.expires = datetime.fromisoformat(self.turn.expires_at)
        self.sink = FakePrivateSink()
        self.consent_for_target = set()
        self.verified_targets = set()
        self.receipt_verified = True
        self.target = TargetGovernance(
            destination_id="synthetic-governed-history",
            retention_until=self.expires + timedelta(days=30),
            supports_deletion=True, supports_correction=True,
            supports_consent_revocation=True, private_destination=True,
            supports_scope_isolation=True,
        )
        self.verified_targets.add(self.target)

    def _live(self, principal, scope, turn_id):
        # SQL searches are scoped, currently active and expiration-filtered;
        # never use a caller-supplied ArchiveTurn as proof of live ownership.
        hits = self.archive.search(
            principal, scope, "Mauve", privacy_scopes=PRIVATE, now=self.now,
        )
        return next((hit.turn for hit in hits if hit.turn.turn_id == turn_id), None)

    def _handoff(self):
        return DeepMemoryHandoff(
            policy=self.window.review_policy,
            resolve_live_turn=self._live,
            authorize=lambda principal, operation, scope, privacy: (
                principal == HOST and scope == SCOPE and operation == "long_term_export"
                and privacy in (None, "private")
            ),
            consent=lambda principal, scope, turn_id, privacy, target: (
                (principal, scope, turn_id, privacy, target) in self.consent_for_target
            ),
            verify_target=lambda target, scope, privacy: (
                target in self.verified_targets and scope == SCOPE and privacy == "private"
            ),
            sink=self.sink,
            verify_receipt=lambda receipt, record, key: (
                self.receipt_verified and isinstance(receipt, dict)
                and receipt.get("key") == key
            ),
            clock=lambda: self.now,
        )

    def _authorize_target(self, target=None):
        target = target or self.target
        self.consent_for_target.add((HOST, SCOPE, self.turn.turn_id, "private", target))

    def _sweep_at_expiry(self):
        self.now = self.expires
        with patch("stm.retention_window_3045._wall_utc", lambda: self.now):
            return self.retained.sweep(HOST, SCOPE, privacy_scopes=PRIVATE)

    def _bridge_args(self, *, retention_days=45):
        opaque_request = object()
        grant = VerifiedConversation(
            principal=HOST,
            session=SessionKey(SCOPE.tenant_id, SCOPE.owner_id, SCOPE.agent_id,
                               "synthetic-conversation"),
            conversation_id="synthetic-conversation", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            max_working_ttl_seconds=600,
            archive_consent=True,
            archive_retention_seconds=retention_days * 86400,
        )
        return opaque_request, dict(
            archive=self.archive, retained=self.retained, stm=STM(),
            resolve=lambda request: grant if request is opaque_request else None,
            authorize=lambda verified, action, privacy: (
                verified is grant and privacy == "private" and action == "archive_write:user"
            ),
            verify_enforcement=lambda verified, archive: (
                verified is grant and archive is self.archive
            ),
            clock=lambda: self.now,
        )

    def test_day_29_wont_send_even_when_target_contract_is_consented(self):
        self._authorize_target()
        self.now = self.admitted + timedelta(days=29, hours=23, minutes=59)
        with self.assertRaisesRegex(PermissionError, "not eligible"):
            self._handoff().submit(HOST, SCOPE, self.turn.turn_id, target=self.target)
        self.assertEqual(self.sink.requests, [])

    def test_day_30_requires_distinct_exact_retention_consent(self):
        self.now = self.admitted + timedelta(days=30)
        handoff = self._handoff()
        self.assertTrue(self.window.review_policy.evaluate(
            self.turn, now=self.now, current_consent=True, current_authority=True,
        ).ready_for_review)
        # Review consent never turns into a long-term export grant.
        with self.assertRaisesRegex(PermissionError, "export consent"):
            handoff.submit(HOST, SCOPE, self.turn.turn_id, target=self.target)
        self.assertEqual(self.sink.requests, [])
        self._authorize_target()
        receipt = handoff.submit(HOST, SCOPE, self.turn.turn_id, target=self.target)
        self.assertEqual(receipt.destination_id, self.target.destination_id)
        self.assertEqual(len(self.sink.requests), 1)
        self.assertEqual(self.sink.requests[0][0].content, CONTENT)
        self.assertEqual(len(self.archive.search(
            HOST, SCOPE, "Mauve", privacy_scopes=PRIVATE,
        )), 1)  # A verified export does not erase source early.

    def test_target_retention_extension_needs_a_new_full_contract_consent(self):
        self.now = self.admitted + timedelta(days=30)
        self._authorize_target()
        extended = replace(self.target, retention_until=self.target.retention_until + timedelta(days=365))
        self.verified_targets.add(extended)  # Even a verified target is insufficient.
        with self.assertRaisesRegex(PermissionError, "export consent"):
            self._handoff().submit(HOST, SCOPE, self.turn.turn_id, target=extended)
        self.assertEqual(self.sink.requests, [])

    def test_day_45_removes_source_despite_failed_external_sink(self):
        self._authorize_target()
        self.now = self.admitted + timedelta(days=31)
        self.sink.raise_on_submit = True
        with self.assertRaises(HandoffUnverified):
            self._handoff().submit(HOST, SCOPE, self.turn.turn_id, target=self.target)
        self.assertEqual(len(self.sink.requests), 1)
        self.assertEqual(len(self.archive.search(
            HOST, SCOPE, "Mauve", privacy_scopes=PRIVATE,
        )), 1)
        audit = self._sweep_at_expiry()
        self.assertEqual(audit.deleted, 1)
        self.assertEqual(self.archive.search(
            HOST, SCOPE, "Mauve", privacy_scopes=PRIVATE,
        ), ())
        with self.assertRaises(PermissionError):
            self._handoff().submit(HOST, SCOPE, self.turn.turn_id, target=self.target)

    def test_unverified_receipt_still_allows_hard_local_expiry(self):
        self._authorize_target()
        self.now = self.admitted + timedelta(days=31)
        self.receipt_verified = False
        with self.assertRaises(HandoffUnverified):
            self._handoff().submit(HOST, SCOPE, self.turn.turn_id, target=self.target)
        self.assertEqual(self._sweep_at_expiry().deleted, 1)
        self.assertEqual(self.archive.search(HOST, SCOPE, "Mauve", privacy_scopes=PRIVATE), ())

    def test_pending_review_ticket_cannot_pause_local_expiry(self):
        queue = HandoffReviewQueue(
            self.window.review_policy,
            authorize=lambda principal, action, scope: principal == HOST and scope == SCOPE,
            consent_check=lambda principal, scope, privacy: (
                principal == HOST and scope == SCOPE and privacy == "private"
            ),
            resolve_live_turn=self._live,
        )
        self.now = self.admitted + timedelta(days=30)
        ticket = queue.offer(HOST, SCOPE, self.turn, now=self.now)
        self.assertIsInstance(ticket, HandoffReviewTicket)
        self.assertEqual(len(queue.pending(HOST, SCOPE, now=self.now)), 1)
        self.assertEqual(self._sweep_at_expiry().deleted, 1)
        self.assertEqual(queue.pending(HOST, SCOPE, now=self.now), ())

    def test_future_clock_cannot_extend_source_expiry_to_day_50(self):
        count_before = self.archive._db.execute("SELECT count(*) FROM turns").fetchone()[0]
        self.now = datetime.now(timezone.utc) + timedelta(days=5)
        with self.assertRaisesRegex(PermissionError, "clock skew"):
            self.retained.append_turn(
                HOST, SCOPE, conversation_id="skew", role="user",
                content="Synthetic cobalt ruler", source="synthetic:skew",
            )
        count_after = self.archive._db.execute("SELECT count(*) FROM turns").fetchone()[0]
        self.assertEqual(count_after, count_before)
        self.assertLessEqual(self.expires - self.admitted, LOCAL_EXPIRE_AFTER)

    def test_scope_impersonation_denied_before_export_and_archive_read(self):
        self._authorize_target()
        self.now = self.admitted + timedelta(days=31)
        with self.assertRaises(PermissionError):
            self._handoff().submit(HOST, OTHER, self.turn.turn_id, target=self.target)
        with self.assertRaises(PermissionError):
            self.archive.search(HOST, OTHER, "Mauve", privacy_scopes=PRIVATE)
        with self.assertRaises(PermissionError):
            self.retained.sweep(HOST, OTHER, privacy_scopes=PRIVATE)
        self.assertEqual(self.sink.requests, [])

    def test_late_correction_keeps_ancestor_deadline_but_misses_review(self):
        corrected = self.archive.correct(HOST, SCOPE, self.turn.turn_id,
                                         "Mauve paperclip corrected")
        self.assertEqual(corrected.expires_at, self.turn.expires_at)
        self.assertEqual(corrected.supersedes_id, self.turn.turn_id)
        # A synthetic late correction gets a fresh admission time in day 20,
        # without resetting original local expiry. It cannot reach day 30.
        late = replace(corrected, recorded_at=(self.expires - timedelta(days=25)).isoformat())
        result = self.window.review_policy.evaluate(
            late, now=self.expires - timedelta(days=1),
            current_consent=True, current_authority=True,
        )
        self.assertFalse(result.ready_for_review)
        self.assertEqual(result.reason, "review_after_or_at_source_expiry")
        self.assertEqual(self._sweep_at_expiry().deleted, 2)
        self.assertEqual(self.archive.search(HOST, SCOPE, "Mauve", privacy_scopes=PRIVATE), ())

    def test_guarded_bridge_archives_with_a_real_45_day_source_deadline(self):
        request, args = self._bridge_args()
        bridge = self.window.vera_bridge(**args)
        persisted = bridge.archive_turn(request, "Synthetic jade compass")
        recorded = datetime.fromisoformat(persisted.recorded_at)
        deadline = datetime.fromisoformat(persisted.expires_at)
        self.assertLessEqual(deadline - recorded, LOCAL_EXPIRE_AFTER)
        self.assertEqual(persisted.source, "vera-local-conversation:synthetic-conversation")

    def test_guarded_bridge_refuses_46_day_capability_before_archive_write(self):
        request, args = self._bridge_args(retention_days=46)
        bridge = self.window.vera_bridge(**args)
        with self.assertRaises(PermissionError):
            bridge.archive_turn(request, "Synthetic jade compass")
        self.assertEqual(self.archive.search(
            HOST, SCOPE, "jade", privacy_scopes=PRIVATE,
        ), ())

    def test_guarded_bridge_requires_host_verifier_and_exact_bounded_wrapper(self):
        _, args = self._bridge_args()
        without_verifier = dict(args, verify_enforcement=None)
        with self.assertRaises(PermissionError):
            self.window.vera_bridge(**without_verifier)
        ordinary_wrapper = RetainedConversationArchive(
            self.archive, policy=self.window.retention_policy,
            consent_check=lambda principal, scope, operation, privacy: True,
        )
        with self.assertRaises(PermissionError):
            self.window.vera_bridge(**dict(args, retained=ordinary_wrapper))

    def test_guarded_bridge_rejects_future_clock_before_persistence(self):
        request, args = self._bridge_args()
        bridge = self.window.vera_bridge(**args)
        self.now = datetime.now(timezone.utc) + timedelta(days=5)
        with self.assertRaisesRegex(PermissionError, "clock skew"):
            bridge.archive_turn(request, "Synthetic jade compass")
        self.assertEqual(self.archive.search(
            HOST, SCOPE, "jade", privacy_scopes=PRIVATE,
        ), ())


if __name__ == "__main__":
    unittest.main()
