"""Independent adversarial review of the optional v0.5 handoff boundaries.

These tests are synthetic, and deliberately do not send any text to a remote
destination. They are not evidence of an installed VeraOS/Android memory link.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest

from stm import STM, SessionKey, VerifiedConversation
from stm.archive import ArchiveScope, ArchiveTurn
from stm.deepmemory_handoff import DeepMemoryHandoff, HandoffUnverified, TargetGovernance
from stm.handoff_policy import HandoffPolicy, HandoffReviewQueue
from stm.windows_host_auth import WindowsPeerMemoryGateway


class PrivateSink:
    """A durable-like in-process test double, not a DMS writer."""

    def __init__(self):
        self.calls = []
        self.accepted = {}
        self.after_send = lambda: None

    def submit(self, record, *, target, idempotency_key):
        assert target.private_destination is True
        self.calls.append((record, idempotency_key))
        self.accepted.setdefault(idempotency_key, record)
        self.after_send()
        return {"external_record_id": "private-record-1", "idempotency_key": idempotency_key}


class HandoffAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.scope = ArchiveScope("tenant", "owner", "vera")
        self.other = ArchiveScope("different-tenant", "owner", "vera")
        self.turn = ArchiveTurn(
            turn_id="t1", conversation_id="c1", role="user",
            content="Synthetic private conversation, not personal data",
            source="vera:conversation:c1:t1", privacy="private",
            event_time=(self.now - timedelta(days=180)).isoformat(),
            recorded_at=(self.now - timedelta(days=31)).isoformat(),
            supersedes_id=None, expires_at=(self.now + timedelta(days=3)).isoformat(),
        )
        self.source_live = True
        self.consent = True
        self.target = TargetGovernance(
            destination_id="private-vault", retention_until=self.now + timedelta(days=45),
            supports_deletion=True, supports_correction=True,
            supports_consent_revocation=True, private_destination=True,
            supports_scope_isolation=True,
        )
        self.sink = PrivateSink()
        self.policy = HandoffPolicy()

        def resolve(principal, scope, turn_id):
            if (principal == "verified-owner" and scope == self.scope
                    and self.source_live and turn_id == self.turn.turn_id):
                return self.turn
            return None

        def authorize(principal, action, scope, privacy):
            return (principal == "verified-owner" and scope == self.scope
                    and action == "long_term_export" and privacy in (None, "private"))

        def consent(principal, scope, turn_id, privacy, destination):
            return (self.consent and principal == "verified-owner"
                    and scope == self.scope and turn_id == "t1"
                    and privacy == "private"
                    and destination.destination_id == "private-vault")

        def verify_target(target, scope, label):
            return target == self.target and scope == self.scope and label == "private"

        def verify_receipt(receipt, record, key):
            return (receipt.get("idempotency_key") == key
                    and self.sink.accepted.get(key) == record)

        self.export = DeepMemoryHandoff(
            policy=self.policy, resolve_live_turn=resolve,
            authorize=authorize, consent=consent, verify_target=verify_target,
            sink=self.sink, verify_receipt=verify_receipt,
            clock=lambda: self.now,
        )

    def send(self, *, scope=None, target=None):
        return self.export.submit(
            "verified-owner", scope if scope is not None else self.scope, "t1",
            target=target if target is not None else self.target,
        )

    def test_review_threshold_not_event_time_and_expiry_before_transfer(self):
        # Imported event_time is much older; only admission/recorded_at counts.
        self.turn = replace(self.turn, recorded_at=(self.now - timedelta(days=29)).isoformat())
        with self.assertRaises(PermissionError):
            self.send()
        self.assertEqual(self.sink.calls, [])

        # A 30-day archive TTL ending at the 30-day review boundary cannot
        # satisfy a transfer-after-day-30 policy. There is no silent bypass.
        self.turn = replace(
            self.turn,
            recorded_at=(self.now - timedelta(days=31)).isoformat(),
            expires_at=(self.now - timedelta(days=1)).isoformat(),
        )
        with self.assertRaises(PermissionError):
            self.send()
        self.assertEqual(self.sink.calls, [])

    def test_public_append_only_target_cannot_receive_private_content(self):
        public_target = replace(self.target, private_destination=False,
                                supports_deletion=False)
        with self.assertRaises(PermissionError):
            self.send(target=public_target)
        self.assertEqual(self.sink.calls, [])

    def test_wrong_tenant_cannot_export_or_promote(self):
        with self.assertRaises(PermissionError):
            self.send(scope=self.other)
        self.assertEqual(self.sink.calls, [])

    def test_source_correction_or_deletion_invalidates_previously_live_export(self):
        self.source_live = False
        with self.assertRaises(PermissionError):
            self.send()
        self.assertEqual(self.sink.calls, [])

    def test_separate_long_term_consent_required_even_if_source_exists(self):
        self.consent = False
        with self.assertRaises(PermissionError):
            self.send()
        self.assertEqual(self.sink.calls, [])

    def test_replay_idempotency_is_sink_responsibility(self):
        first = self.send()
        second = self.send()
        self.assertEqual(first.idempotency_key, second.idempotency_key)
        self.assertEqual(len(self.sink.accepted), 1)
        self.assertEqual(len(self.sink.calls), 2)

    def test_consent_revoked_mid_transfer_cannot_be_reported_as_accepted(self):
        self.sink.after_send = lambda: setattr(self, "consent", False)
        with self.assertRaises(HandoffUnverified):
            self.send()
        # Transmission already happened. This is a deployment-level problem
        # requiring an atomically revocable destination and compensation.
        self.assertEqual(len(self.sink.calls), 1)
        self.assertTrue(self.source_live)

    def test_pending_review_terminates_on_revocation(self):
        scope = self.scope

        def authorized(principal, action, target_scope):
            return (principal == "verified-owner" and target_scope == scope
                    and action in {"handoff_review_offer", "handoff_review_list",
                                   "handoff_review_invalidate",
                                   "handoff_review_privacy:private"})

        queue = HandoffReviewQueue(
            self.policy, authorize=authorized,
            consent_check=lambda principal, target_scope, privacy: self.consent,
            resolve_live_turn=lambda principal, target_scope, id: (
                self.turn if self.source_live and target_scope == scope and id == "t1"
                else None
            ),
        )
        ticket = queue.offer("verified-owner", scope, self.turn, now=self.now)
        self.assertEqual(ticket.state, "pending")
        self.consent = False
        self.assertEqual(queue.pending("verified-owner", scope, now=self.now), ())
        self.consent = True
        self.assertEqual(queue.pending("verified-owner", scope, now=self.now), ())

    def test_review_ticket_does_not_retain_private_source_free_text(self):
        # The archive accepts any nonblank source attribution, including
        # strings containing personal information. The review queue promises
        # content-free metadata and should not copy that uncontrolled field.
        self.turn = replace(
            self.turn,
            source="User-supplied provenance with private answer: redacted-secret-991",
        )
        queue = HandoffReviewQueue(
            self.policy,
            authorize=lambda principal, action, scope: (
                principal == "verified-owner" and scope == self.scope),
            consent_check=lambda principal, scope, label: self.consent,
            resolve_live_turn=lambda principal, scope, tid: self.turn,
        )
        ticket = queue.offer("verified-owner", self.scope, self.turn, now=self.now)
        self.assertNotIn("redacted-secret-991", repr(ticket))


class WindowsSourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        grant = VerifiedConversation(
            principal=object(), session=SessionKey("tenant", "owner", "vera", "chat"),
            conversation_id="c1", privacy_scopes=frozenset({"private"}),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
            max_working_ttl_seconds=60,
        )
        self.gateway = WindowsPeerMemoryGateway(
            "adversarial-test", stm=STM(), sid_grants={"S-1-5-21-1000": grant},
        )

    def test_request_json_cannot_claim_windows_sid_or_archive(self):
        for payload in (
            {"operation": "remember", "text": "x", "sid": "S-1-5-21-1000"},
            {"operation": "remember", "text": "x", "owner_id": "owner"},
            {"operation": "remember", "text": "x", "archive_consent": True},
            {"operation": "archive", "text": "x"},
        ):
            with self.subTest(payload=payload):
                response = self.gateway._authenticated_dispatch(
                    "S-1-5-21-1000", json.dumps(payload).encode(),
                )
                self.assertEqual(response["status"], "DENIED_OR_HELD")

    def test_unknown_windows_sid_cannot_read_or_write(self):
        result = self.gateway._authenticated_dispatch(
            "S-1-5-21-6666", b'{"operation":"remember","text":"secret"}',
        )
        self.assertEqual(result["status"], "DENIED_OR_HELD")


if __name__ == "__main__":
    unittest.main()
