"""Synthetic-only boundary checks for historical account-export candidates."""

from datetime import datetime, timedelta, timezone
import unittest

from chatgpt_memory_policy import (
    CandidateDisposition, HistoricalCandidate, OwnerContext, Privacy,
    RECALL_SCOPE, RetentionState, ThirdPartyScreen, classify_candidate,
    retention_state,
)


NOW = datetime(2026, 10, 29, 20, 0, tzinfo=timezone.utc)


def candidate(**overrides):
    defaults = dict(
        owner_key="synthetic-owner-1",
        export_ref="opaque-export",
        conversation_ref="opaque-conversation",
        message_ref="opaque-node",
        author_role="user",
        privacy=Privacy.PRIVATE_ACCOUNT,
        third_party_screen=ThirdPartyScreen.SCREENED_ABSENT,
        event_time=datetime(2021, 1, 1, tzinfo=timezone.utc),
        event_time_quality="source_recorded",
    )
    defaults.update(overrides)
    return HistoricalCandidate(**defaults)


def owner(**overrides):
    defaults = dict(
        owner_key="synthetic-owner-1",
        principal_verified=True,
        opted_in=True,
        consent_scope=RECALL_SCOPE,
        consent_valid_at=NOW - timedelta(days=1),
    )
    defaults.update(overrides)
    return OwnerContext(**defaults)


class MemoryPolicyTests(unittest.TestCase):
    def test_default_denies_unauthenticated_owner(self):
        result = classify_candidate(candidate(), OwnerContext(), now=NOW)
        self.assertEqual(result.disposition, CandidateDisposition.DENIED)
        self.assertEqual(result.reason, "owner_authentication_required")

    def test_owner_identity_mismatch_denied_even_if_verified(self):
        result = classify_candidate(candidate(), owner(owner_key="someone-else"), now=NOW)
        self.assertEqual(result.disposition, CandidateDisposition.DENIED)

    def test_truthy_nonboolean_authentication_never_grants_review(self):
        for forged in ("false", "true", 1, [1], {"verified": True}):
            with self.subTest(forged_type=type(forged).__name__):
                result = classify_candidate(candidate(), owner(principal_verified=forged), now=NOW)
                self.assertEqual(result.disposition, CandidateDisposition.DENIED)
                self.assertEqual(result.reason, "owner_authentication_required")

    def test_truthy_nonboolean_opt_in_never_grants_review(self):
        for forged in ("false", "true", 1, [1], {"opted_in": True}):
            with self.subTest(forged_type=type(forged).__name__):
                result = classify_candidate(candidate(), owner(opted_in=forged), now=NOW)
                self.assertEqual(result.disposition, CandidateDisposition.DENIED)
                self.assertEqual(result.reason, "explicit_recall_review_consent_required")

    def test_consent_requires_exact_scope_and_explicit_opt_in(self):
        for context in (
            owner(opted_in=False),
            owner(consent_scope="some-other-scope"),
            owner(consent_scope=None),
        ):
            with self.subTest(context=context):
                self.assertEqual(classify_candidate(candidate(), context, now=NOW).disposition,
                                 CandidateDisposition.DENIED)

    def test_future_consent_does_not_qualify_past_request(self):
        result = classify_candidate(candidate(), owner(consent_valid_at=NOW + timedelta(seconds=1)), now=NOW)
        self.assertEqual(result.disposition, CandidateDisposition.DENIED)

    def test_unknown_or_third_party_privacy_quarantined(self):
        for privacy in (Privacy.UNKNOWN, Privacy.THIRD_PARTY):
            with self.subTest(privacy=privacy):
                self.assertEqual(classify_candidate(candidate(privacy=privacy), owner(), now=NOW).disposition,
                                 CandidateDisposition.QUARANTINED)

    def test_unknown_or_present_third_party_material_quarantined(self):
        for screen in (ThirdPartyScreen.UNKNOWN, ThirdPartyScreen.PRESENT):
            with self.subTest(screen=screen):
                self.assertEqual(classify_candidate(candidate(third_party_screen=screen), owner(), now=NOW).disposition,
                                 CandidateDisposition.QUARANTINED)

    def test_assistant_or_tool_authored_material_quarantined(self):
        for role in ("assistant", "tool", "system", "developer", "fake-system-in-chat"):
            with self.subTest(role=role):
                self.assertEqual(classify_candidate(candidate(author_role=role), owner(), now=NOW).disposition,
                                 CandidateDisposition.QUARANTINED)

    def test_superseded_source_quarantined(self):
        result = classify_candidate(candidate(superseded_by_ref="corrected-node"), owner(), now=NOW)
        self.assertEqual(result.disposition, CandidateDisposition.QUARANTINED)

    def test_screened_owner_source_only_eligible_for_review_and_no_effect(self):
        record = candidate(
            event_time=datetime(2005, 1, 1, tzinfo=timezone.utc),
            corrects_message_ref="old-node",
        )
        result = classify_candidate(record, owner(), now=NOW)
        self.assertEqual(result.disposition, CandidateDisposition.REVIEW_ELIGIBLE)
        self.assertEqual(result.reason, "historical_source_for_owner_review_only")
        self.assertFalse(result.may_promote_to_present_fact)
        self.assertFalse(result.may_change_identity)
        self.assertFalse(result.may_change_weights)
        self.assertFalse(result.may_grant_authority)
        self.assertFalse(result.may_send_to_model)

    def test_repr_masks_opaque_private_references(self):
        secret_ref = "opaque-sensitive-reference"
        self.assertNotIn(secret_ref, repr(candidate(message_ref=secret_ref)))
        self.assertNotIn("synthetic-owner-1", repr(owner()))

    def test_rejects_naive_or_invalid_source_event_timestamps(self):
        with self.assertRaises(ValueError):
            candidate(event_time=datetime(2020, 1, 1))
        with self.assertRaises(ValueError):
            candidate(event_time_quality="certainty-100%")

    def test_archive_source_never_subject_to_stm_30_45_day_expiry(self):
        for when in (NOW, NOW + timedelta(days=10000)):
            self.assertEqual(retention_state(source_class="chatgpt_account_export", now=when),
                             RetentionState.SOURCE_POLICY_SEPARATE)

    def test_new_consent_stm_review_and_expiry_boundaries(self):
        self.assertEqual(retention_state(source_class="new_consented_stm", now=NOW,
                                         admitted_at=NOW-timedelta(days=29)), RetentionState.ACTIVE)
        self.assertEqual(retention_state(source_class="new_consented_stm", now=NOW,
                                         admitted_at=NOW-timedelta(days=30)), RetentionState.REVIEW_ELIGIBLE)
        self.assertEqual(retention_state(source_class="new_consented_stm", now=NOW,
                                         admitted_at=NOW-timedelta(days=44)), RetentionState.REVIEW_ELIGIBLE)
        self.assertEqual(retention_state(source_class="new_consented_stm", now=NOW,
                                         admitted_at=NOW-timedelta(days=45)), RetentionState.EXPIRED)

    def test_retention_fails_closed_on_unknown_class_and_future_time(self):
        with self.assertRaises(ValueError):
            retention_state(source_class="unknown", now=NOW)
        with self.assertRaises(ValueError):
            retention_state(source_class="new_consented_stm", now=NOW, admitted_at=NOW + timedelta(seconds=1))
        with self.assertRaises(ValueError):
            retention_state(source_class="chatgpt_account_export", now=NOW, admitted_at=NOW)


if __name__ == "__main__":
    unittest.main()
