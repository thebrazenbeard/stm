"""User-selected day-30 review / day-45 hard expiry contract, synthetic only."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from stm import ArchiveScope, ArchiveTurn, ConversationArchive, RetentionPolicy, SessionKey, STM
from stm.retention_window_3045 import (
    LOCAL_EXPIRE_AFTER, REVIEW_AFTER, REVIEW_PERIOD,
    ThirtyFortyFiveReviewPolicy, ThirtyFortyFiveWindow,
)
from stm.vera_bridge import VerifiedConversation


SCOPE = ArchiveScope("synthetic", "owner", "vera")
PRIVATE = frozenset({"private"})


class ThirtyFortyFiveWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive = ConversationArchive(
            str(Path(self.temp.name) / "history.sqlite"),
            authorize=lambda principal, action, scope: (
                principal == "host" and scope == SCOPE
            ),
        )
        self.addCleanup(self.archive.close)
        self.window = ThirtyFortyFiveWindow()
        self.consent = True
        self.admission = datetime.now(timezone.utc) - timedelta(milliseconds=100)
        self.current = self.admission
        self.retained = self.window.retained_archive(
            self.archive, consent_check=lambda principal, scope, action, label: (
                self.consent and principal == "host" and scope == SCOPE
                and label == "private"
            ), clock=lambda: self.current,
        )

    def write(self):
        return self.retained.append_turn(
            "host", SCOPE, conversation_id="chat-1", role="user",
            content="Synthetic mauve paperclip", source="test:chat-1:turn-1",
        )

    def test_exact_adopted_durations_and_default_private_scope(self):
        self.assertEqual(REVIEW_AFTER, timedelta(days=30))
        self.assertEqual(LOCAL_EXPIRE_AFTER, timedelta(days=45))
        self.assertEqual(REVIEW_PERIOD, timedelta(days=15))
        self.assertEqual(self.window.retention_policy.maximum_age, LOCAL_EXPIRE_AFTER)
        self.assertEqual(self.window.review_policy.review_age, REVIEW_AFTER)
        self.assertEqual(self.window.privacy_labels, PRIVATE)

    def test_actual_archive_admission_receives_no_more_than_45_days(self):
        original = self.write()
        recorded = datetime.fromisoformat(original.recorded_at)
        expiry = datetime.fromisoformat(original.expires_at)
        self.assertLessEqual(expiry, recorded + LOCAL_EXPIRE_AFTER)
        self.assertGreater(expiry, recorded + REVIEW_AFTER)
        with self.assertRaises(ValueError):
            self.retained.append_turn(
                "host", SCOPE, conversation_id="chat", role="user",
                content="Do not extend", requested_age=timedelta(days=46),
            )

    def test_review_not_day_29_and_eligible_exact_day_30(self):
        original = self.write()
        recorded = datetime.fromisoformat(original.recorded_at)
        before = self.window.review_policy.evaluate(
            original, now=recorded + timedelta(days=30, microseconds=-1),
            current_consent=True, current_authority=True,
        )
        at = self.window.review_policy.evaluate(
            original, now=recorded + timedelta(days=30),
            current_consent=True, current_authority=True,
        )
        self.assertFalse(before.ready_for_review)
        self.assertEqual(before.reason, "not_yet_due")
        self.assertTrue(at.ready_for_review)
        self.assertEqual(at.reason, "ready_for_review_only")

    def test_missing_consent_or_authority_prevents_review(self):
        original = self.write()
        reviewed = datetime.fromisoformat(original.recorded_at) + REVIEW_AFTER
        for consent, authority in ((False, True), (True, False)):
            with self.subTest(consent=consent, authority=authority):
                self.assertFalse(self.window.review_policy.evaluate(
                    original, now=reviewed,
                    current_consent=consent, current_authority=authority,
                ).ready_for_review)

    def test_sweep_at_day_45_even_after_consent_withdrawal(self):
        original = self.write()
        expiry = datetime.fromisoformat(original.expires_at)
        # Simulated wall-clock passage only for the trusted scheduler check.
        # Real wall-time is used for admission and cannot be fast-forwarded by
        # an untrusted caller via the strict helper.
        with patch("stm.retention_window_3045._wall_utc", lambda: self.current):
            self.current = expiry - timedelta(microseconds=1)
            before = self.retained.sweep("host", SCOPE, privacy_scopes=PRIVATE)
            self.assertEqual(before.deleted, 0)
            self.consent = False
            self.current = expiry
            at = self.retained.sweep("host", SCOPE, privacy_scopes=PRIVATE)
            self.assertEqual(at.deleted, 1)
        self.assertFalse(self.archive.delete("host", SCOPE, original.turn_id))

    def test_clock_ahead_five_days_rejected_before_any_write(self):
        self.current = datetime.now(timezone.utc) + timedelta(days=5)
        with self.assertRaises(PermissionError):
            self.write()
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns"
        ).fetchone()[0], 0)

    def test_clock_behind_five_days_rejected_before_any_write(self):
        self.current = datetime.now(timezone.utc) - timedelta(days=5)
        with self.assertRaises(PermissionError):
            self.write()
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns"
        ).fetchone()[0], 0)

    def test_longer_source_record_cannot_be_reviewed_as_30_45(self):
        original = self.write()
        recorded = datetime.fromisoformat(original.recorded_at)
        forged = replace(original, expires_at=(recorded + timedelta(days=90)).isoformat())
        result = self.window.review_policy.evaluate(
            forged, now=recorded + REVIEW_AFTER,
            current_consent=True, current_authority=True,
        )
        self.assertFalse(result.ready_for_review)
        self.assertEqual(result.reason, "source_exceeds_day_45_limit")

    def test_record_corrected_late_in_source_life_not_backdated(self):
        original = self.write()
        original_expiry = datetime.fromisoformat(original.expires_at)
        corrected = replace(
            original, turn_id="synthetic-corrected", supersedes_id=original.turn_id,
            recorded_at=(original_expiry - timedelta(days=29)).isoformat(),
        )
        assessed = self.window.review_policy.evaluate(
            corrected, now=original_expiry - timedelta(days=1),
            current_consent=True, current_authority=True,
        )
        self.assertFalse(assessed.ready_for_review)
        self.assertEqual(assessed.reason, "review_after_or_at_source_expiry")

    def test_bridge_grant_must_stay_within_private_45_day_bound(self):
        grant = VerifiedConversation(
            principal=object(), session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        self.window.validate_bridge_grant(grant)
        with self.assertRaises(PermissionError):
            self.window.validate_bridge_grant(replace(
                grant, archive_retention_seconds=46 * 86400,
            ))
        with self.assertRaises(PermissionError):
            self.window.validate_bridge_grant(replace(grant, archive_consent=False))
        with self.assertRaises(PermissionError):
            self.window.validate_bridge_grant(replace(
                grant, privacy_scopes=frozenset({"shared"}),
            ))

    def test_guarded_bridge_enforces_day_45_and_archive_identity(self):
        grant = VerifiedConversation(
            principal="host", session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        requests = {"opaque": grant}
        gate_calls = []
        bridge = self.window.vera_bridge(
            STM(), archive=self.archive, retained=self.retained,
            resolve=lambda request: requests[request],
            authorize=lambda checked, action, label: (
                checked is requests["opaque"] and action == "archive_write:user"
                and label == "private"
            ),
            verify_enforcement=lambda checked, archive: (
                gate_calls.append((checked, archive)) or True
            ),
            clock=lambda: self.current,
        )
        row = bridge.archive_turn("opaque", "Synthetic bridge-bound history")
        self.assertEqual(len(gate_calls), 1)
        self.assertLessEqual(
            datetime.fromisoformat(row.expires_at),
            datetime.fromisoformat(row.recorded_at) + LOCAL_EXPIRE_AFTER,
        )
        requests["opaque"] = replace(grant, archive_retention_seconds=46 * 86400)
        with self.assertRaises(PermissionError):
            bridge.archive_turn("opaque", "Overlong 46-day history")
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns"
        ).fetchone()[0], 1)

    def test_guarded_bridge_rejects_clock_skew_and_missing_scheduler_verification(self):
        grant = VerifiedConversation(
            principal="host", session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=10),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        bridge = self.window.vera_bridge(
            STM(), archive=self.archive, retained=self.retained,
            resolve=lambda request: grant,
            authorize=lambda checked, action, label: True,
            verify_enforcement=lambda checked, archive: False,
            clock=lambda: self.current,
        )
        with self.assertRaises(PermissionError):
            bridge.archive_turn("request", "Scheduler not verified")
        self.current = datetime.now(timezone.utc) + timedelta(days=5)
        with self.assertRaises(PermissionError):
            bridge.archive_turn("request", "Clock skew must not extend retention")
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns"
        ).fetchone()[0], 0)
        with self.assertRaises(PermissionError):
            self.window.vera_bridge(
                STM(), archive=self.archive, retained=self.retained,
                resolve=lambda request: grant, authorize=lambda *_: True,
                verify_enforcement=None,
            )

    def test_guarded_bridge_rechecks_retained_consent_after_withdrawal(self):
        grant = VerifiedConversation(
            principal="host", session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        bridge = self.window.vera_bridge(
            STM(), archive=self.archive, retained=self.retained,
            resolve=lambda request: grant,
            authorize=lambda checked, action, label: True,
            verify_enforcement=lambda checked, archive: True,
            clock=lambda: self.current,
        )
        self.consent = False
        with self.assertRaises(PermissionError):
            bridge.archive_turn("request", "Must not archive after consent withdrawal")
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns",
        ).fetchone()[0], 0)
        self.consent = True
        bridge.archive_turn("request", "Explicit renewed consent")
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns",
        ).fetchone()[0], 1)

    def test_guarded_bridge_denies_post_construction_wrapper_policy_drift(self):
        grant = VerifiedConversation(
            principal="host", session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        bridge = self.window.vera_bridge(
            STM(), archive=self.archive, retained=self.retained,
            resolve=lambda request: grant,
            authorize=lambda checked, action, label: True,
            verify_enforcement=lambda checked, archive: True,
            clock=lambda: self.current,
        )
        original_policy = self.retained._policy
        self.retained._policy = RetentionPolicy(
            maximum_age=timedelta(days=90), privacy_labels=PRIVATE,
        )
        with self.assertRaises(PermissionError):
            bridge.archive_turn("request", "Misconfigured retention wrapper")
        self.assertEqual(self.archive._db.execute(
            "SELECT count(*) FROM turns",
        ).fetchone()[0], 0)
        self.retained._policy = original_policy

    def test_guarded_bridge_history_read_requires_fresh_consent(self):
        grant = VerifiedConversation(
            principal="host", session=SessionKey("synthetic", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=PRIVATE,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120, archive_consent=True,
            archive_retention_seconds=45 * 86400,
        )
        bridge = self.window.vera_bridge(
            STM(), archive=self.archive, retained=self.retained,
            resolve=lambda request: grant,
            authorize=lambda checked, action, label: True,
            verify_enforcement=lambda checked, archive: True,
            clock=lambda: self.current,
        )
        bridge.archive_turn("request", "Synthetic current-only evidence")
        self.assertEqual(len(bridge.recall_history(
            "request", "current-only", privacy_scopes=PRIVATE,
        )), 1)
        self.consent = False
        with self.assertRaises(PermissionError):
            bridge.recall_history("request", "current-only", privacy_scopes=PRIVATE)

    def test_generic_review_window_cannot_be_renamed_as_30_45(self):
        with self.assertRaises(ValueError):
            ThirtyFortyFiveReviewPolicy(review_age=timedelta(days=25))
        with self.assertRaises(ValueError):
            ThirtyFortyFiveWindow(privacy_labels=frozenset())


if __name__ == "__main__":
    unittest.main()
