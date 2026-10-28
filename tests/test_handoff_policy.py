"""Review eligibility is not a DMS export capability."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from stm.archive import ArchiveScope, ArchiveTurn
from stm.handoff_policy import (
    HandoffEligibility, HandoffPolicy, HandoffReviewQueue,
    HandoffReviewTicket,
)


NOW = datetime.now(timezone.utc)
SCOPE = ArchiveScope("tenant", "owner", "vera")
OTHER = ArchiveScope("tenant", "other-owner", "vera")


def turn(
    turn_id: str = "turn-1", *,
    recorded: datetime = NOW - timedelta(days=31),
    expires: datetime | None = NOW + timedelta(days=14),
    source: str = "vera-local-conversation:conversation-one",
    supersedes: str | None = None,
    privacy: str = "private",
    role: str = "user",
) -> ArchiveTurn:
    return ArchiveTurn(
        turn_id=turn_id,
        conversation_id="conversation-one",
        role=role,
        content="sensitive workspace conversation",
        source=source,
        privacy=privacy,
        event_time=(NOW - timedelta(days=450)).isoformat(),
        recorded_at=recorded.isoformat(),
        supersedes_id=supersedes,
        expires_at=expires.isoformat() if expires is not None else None,
    )


class HandoffPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = HandoffPolicy()

    def assess(self, item=None, *, when=NOW, consent=True, authority=True):
        return self.policy.evaluate(
            item or turn(), now=when, current_consent=consent,
            current_authority=authority,
        )

    def test_at_day_30_review_only_and_not_day_29(self):
        older = turn(recorded=NOW - timedelta(days=30, seconds=1))
        younger = turn(recorded=NOW - timedelta(days=29))
        self.assertTrue(self.assess(older).ready_for_review)
        self.assertEqual(self.assess(older).reason, "ready_for_review_only")
        self.assertFalse(self.assess(younger).eligible)
        self.assertEqual(self.assess(younger).reason, "not_yet_due")
        # The policy contains no export action; the result has no content.
        self.assertNotIn("sensitive workspace", repr(self.assess(older)))

    def test_threshold_at_exact_day_30_with_host_clock_ahead(self):
        future = NOW + timedelta(days=10)
        row = turn(recorded=future - timedelta(days=30),
                   expires=future + timedelta(days=30))
        self.assertTrue(self.assess(row, when=future).ready_for_review)
        self.assertFalse(self.assess(row, when=NOW).ready_for_review)

    def test_review_age_cannot_exceed_source_hard_expiry(self):
        source_expiry = NOW - timedelta(days=1)
        row = turn(recorded=NOW - timedelta(days=31), expires=source_expiry)
        self.assertEqual(self.assess(row).reason, "source_expired")
        # Even a still-live record cannot be reviewed at the same instant its
        # source retention expires (a 30d TTL + 30d review age is impossible).
        row = turn(recorded=NOW - timedelta(days=3),
                   expires=NOW + timedelta(days=27))
        self.assertEqual(self.assess(row).reason, "review_after_or_at_source_expiry")

    def test_imported_old_event_does_not_backdate_review_eligibility(self):
        fresh = turn(recorded=NOW - timedelta(hours=2),
                     expires=NOW + timedelta(days=45))
        self.assertEqual(self.assess(fresh).reason, "not_yet_due")

    def test_source_retention_over_library_ceiling_never_enters_queue(self):
        too_long = turn(recorded=NOW - timedelta(days=31),
                        expires=NOW + timedelta(days=91))
        self.assertEqual(self.assess(too_long).reason, "invalid_source_retention")

    def test_consent_privacy_auth_and_provenance_fail_closed(self):
        self.assertEqual(self.assess(consent=False).reason, "review_consent_required")
        self.assertEqual(self.assess(authority=False).reason, "review_authority_required")
        self.assertEqual(self.assess(turn(privacy="secret")).reason,
                         "privacy_not_allowed")
        self.assertEqual(self.assess(turn(role="system")).reason, "invalid_provenance")
        self.assertEqual(self.assess(turn(source="s" * 2049)).reason, "oversized_provenance")
        self.assertEqual(self.assess(turn(expires=None)).reason,
                         "source_has_no_retention_policy")
        self.assertEqual(self.assess(replace(turn(), recorded_at="yesterday")).reason,
                         "invalid_provenance")
        with self.assertRaises(ValueError):
            self.assess(when=NOW.replace(tzinfo=None))
        with self.assertRaises(TypeError):
            self.assess(consent=1)
        with self.assertRaises(ValueError):
            HandoffPolicy(review_age=timedelta(days=91))
        with self.assertRaises(ValueError):
            HandoffPolicy(privacy_labels=frozenset())


class HandoffReviewQueueTests(unittest.TestCase):
    def setUp(self):
        self.live: dict[tuple[ArchiveScope, str], ArchiveTurn] = {}
        self.consent = {"owner": True, "other-owner": True}

        def authorize(principal, action, scope):
            return (principal == scope.owner_id and
                    action in {"handoff_review_offer", "handoff_review_list",
                               "handoff_review_invalidate",
                               "handoff_review_privacy:private"})

        def consent_check(principal, scope, privacy):
            return self.consent.get(principal, False) and privacy == "private"

        def resolve(principal, scope, turn_id):
            return self.live.get((scope, turn_id))

        self.queue = HandoffReviewQueue(
            HandoffPolicy(), authorize=authorize,
            consent_check=consent_check, resolve_live_turn=resolve,
        )
        self.row = turn()
        self.live[(SCOPE, self.row.turn_id)] = self.row

    def test_offer_idempotent_and_contains_no_conversation_text(self):
        first = self.queue.offer("owner", SCOPE, self.row, now=NOW)
        second = self.queue.offer("owner", SCOPE, self.row, now=NOW)
        self.assertIsInstance(first, HandoffReviewTicket)
        self.assertEqual(first, second)
        self.assertNotIn(self.row.content, repr(first))
        self.assertEqual(self.queue.pending("owner", SCOPE, now=NOW), (first,))
        self.assertEqual(self.queue.pending("other-owner", OTHER, now=NOW), ())

    def test_untrusted_source_free_text_is_not_retained_in_review_ticket(self):
        source = "Untrusted source with private answer: redacted-secret-991"
        with_source = replace(self.row, source=source)
        self.live[(SCOPE, with_source.turn_id)] = with_source
        ticket = self.queue.offer("owner", SCOPE, with_source, now=NOW)
        self.assertIsInstance(ticket, HandoffReviewTicket)
        self.assertFalse(hasattr(ticket, "source"))
        self.assertNotIn("redacted-secret-991", repr(ticket))
        self.assertNotIn(source, repr(self.queue.pending("owner", SCOPE, now=NOW)))

    def test_cross_scope_impersonation_denied_and_source_not_verified(self):
        with self.assertRaises(PermissionError):
            self.queue.offer("intruder", SCOPE, self.row, now=NOW)
        with self.assertRaises(PermissionError):
            self.queue.pending("owner", OTHER, now=NOW)
        self.assertEqual(self.queue.offer("other-owner", OTHER, self.row, now=NOW),
                         HandoffEligibility(False, "source_not_current", None, None))

    def test_revocation_removes_visibility_and_terminal_tombstone(self):
        item = self.queue.offer("owner", SCOPE, self.row, now=NOW)
        self.assertIsInstance(item, HandoffReviewTicket)
        self.consent["owner"] = False
        self.assertEqual(self.queue.pending("owner", SCOPE, now=NOW), ())
        self.consent["owner"] = True
        # Re-grant cannot reopen old review ticket after revocation.
        again = self.queue.offer("owner", SCOPE, self.row, now=NOW)
        self.assertEqual(again.state, "invalidated")

    def test_correction_invalidates_ancestor_and_new_version_requeues(self):
        old_ticket = self.queue.offer("owner", SCOPE, self.row, now=NOW)
        corrected = turn("turn-2", supersedes="turn-1")
        self.live.pop((SCOPE, "turn-1"))
        self.live[(SCOPE, "turn-2")] = corrected
        self.assertEqual(self.queue.pending("owner", SCOPE, now=NOW), ())
        second = self.queue.offer("owner", SCOPE, corrected, now=NOW)
        self.assertIsInstance(second, HandoffReviewTicket)
        self.assertNotEqual(old_ticket.turn_id, second.turn_id)
        self.assertEqual([item.turn_id for item in self.queue.pending("owner", SCOPE, now=NOW)],
                         ["turn-2"])
        self.queue.invalidate("owner", SCOPE, "turn-1")
        self.assertEqual(self.queue.pending("owner", SCOPE, now=NOW), ())

    def test_deleted_and_mutated_source_never_reexported(self):
        self.queue.offer("owner", SCOPE, self.row, now=NOW)
        self.live[(SCOPE, self.row.turn_id)] = replace(self.row, content="mutated")
        self.assertEqual(self.queue.pending("owner", SCOPE, now=NOW), ())
        self.live.pop((SCOPE, self.row.turn_id))
        self.assertEqual(self.queue.offer("owner", SCOPE, self.row, now=NOW).reason,
                         "source_not_current")

    def test_expiration_clears_pending_even_without_host_notification(self):
        due_soon = turn(expires=NOW + timedelta(seconds=1))
        self.live[(SCOPE, due_soon.turn_id)] = due_soon
        self.queue.offer("owner", SCOPE, due_soon, now=NOW)
        later = NOW + timedelta(seconds=2)
        self.assertEqual(self.queue.pending("owner", SCOPE, now=later), ())

    def test_concurrent_duplicate_offers_do_not_duplicate_tickets(self):
        def submit(_):
            return self.queue.offer("owner", SCOPE, self.row, now=NOW)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(submit, range(40)))
        self.assertEqual(len({id(item) for item in results}), 1)
        self.assertEqual(len(self.queue.pending("owner", SCOPE, now=NOW)), 1)

    def test_queue_capacity_is_bounded_and_never_evicts_terminal_tombstones(self):
        first = turn("bounded-one")
        second = turn("bounded-two")
        live = {first.turn_id: first, second.turn_id: second}
        queue = HandoffReviewQueue(
            HandoffPolicy(),
            authorize=lambda principal, action, scope: principal == "owner" and scope == SCOPE,
            consent_check=lambda principal, scope, privacy: privacy == "private",
            resolve_live_turn=lambda principal, scope, turn_id: live.get(turn_id),
            max_tickets=1,
        )
        queue.offer("owner", SCOPE, first, now=NOW)
        queue.invalidate("owner", SCOPE, first.turn_id)
        with self.assertRaises(MemoryError):
            queue.offer("owner", SCOPE, second, now=NOW)
        with self.assertRaises(ValueError):
            HandoffReviewQueue(
                HandoffPolicy(), authorize=lambda *_: True,
                consent_check=lambda *_: True, resolve_live_turn=lambda *_: None,
                max_tickets=0,
            )


if __name__ == "__main__":
    unittest.main()
