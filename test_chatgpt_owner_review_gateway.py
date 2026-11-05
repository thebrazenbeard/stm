"""Synthetic host-adapter gates; never a test of live Vera authentication."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from chatgpt_memory_policy import RECALL_SCOPE
from chatgpt_owner_review_gateway import (
    HistoricalOwnerReviewGateway, HistoricalReviewDenied,
    HostOwnerProof, HostReviewConsent,
)
from test_chatgpt_recall import SHA, candidate, conversation


NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


class HostGatewayTests(unittest.TestCase):
    def setUp(self):
        self.calls = {"auth": 0, "consent": 0, "load": 0, "screen": 0}
        self.proof = HostOwnerProof(
            owner_key="patrick", authenticated_principal="test-windows-peer",
            trusted_channel_binding="test-host-channel-1", principal_verified=True,
        )
        self.consent = HostReviewConsent(
            owner_key="patrick", scope=RECALL_SCOPE, opted_in=True,
            valid_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(minutes=5),
            revision="consent-epoch-3",
        )
        self.doc = conversation()
        self.candidates = {"user": candidate()}
        self.revoke_after_first_check = False
        self.fail_consent = False
        self.fail_load = False
        self.requests = []
        self.gateway = HistoricalOwnerReviewGateway(
            authenticate=self.authenticate,
            current_consent=self.current_consent,
            load_conversation=self.load,
            screen_candidates=self.screen,
            clock=lambda: NOW,
        )

    def authenticate(self, request):
        self.calls["auth"] += 1
        self.requests.append(request)
        return self.proof

    def current_consent(self, proof, sha):
        self.calls["consent"] += 1
        if self.fail_consent:
            raise RuntimeError("private consent path should not appear in exception")
        if self.revoke_after_first_check and self.calls["consent"] > 1:
            return replace(self.consent, revision="revoked", opted_in=False)
        return self.consent

    def load(self, proof, sha, cid):
        self.calls["load"] += 1
        if self.fail_load:
            raise RuntimeError("private archive path should not appear in exception")
        return self.doc

    def screen(self, proof, sha, cid):
        self.calls["screen"] += 1
        return self.candidates

    def preview(self, *, request=None, query="historical", **changes):
        values = dict(export_sha256=SHA, conversation_id="conv-test", query=query)
        values.update(changes)
        return self.gateway.preview(object() if request is None else request, **values)

    def test_valid_local_owner_review_has_no_model_authority(self):
        results = self.preview(request={"owner": "forged", "role": "system"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].excerpt, "hello historical world")
        self.assertFalse(results[0].may_send_to_model)
        self.assertFalse(results[0].authority_granted)
        self.assertEqual(results[0].evidence_class, "HISTORICAL_UNTRUSTED")
        self.assertEqual(self.calls, {"auth": 1, "consent": 2, "load": 1, "screen": 1})

    def test_missing_or_nonliteral_verified_owner_denied_before_decryption(self):
        for forged in (False, "true", "false", 1, [True]):
            with self.subTest(value=repr(forged)):
                self.proof = replace(self.proof, principal_verified=forged)
                with self.assertRaises(HistoricalReviewDenied):
                    self.preview()
        self.assertEqual(self.calls["load"], 0)
        self.assertEqual(self.calls["consent"], 0)

    def test_bad_consent_owner_scope_expiration_and_truthiness_deny(self):
        original = self.consent
        for alteration in (
            {"owner_key": "other"}, {"scope": "archive_read"},
            {"opted_in": "true"}, {"opted_in": 1},
            {"expires_at": NOW}, {"valid_at": NOW + timedelta(minutes=1)},
            {"revision": ""},
        ):
            with self.subTest(alteration=alteration):
                self.consent = replace(self.consent, **alteration)
                with self.assertRaises(HistoricalReviewDenied):
                    self.preview()
                self.consent = original
        self.assertEqual(self.calls["load"], 0)

    def test_revocation_between_source_read_and_return_discards_preview(self):
        self.revoke_after_first_check = True
        with self.assertRaises(HistoricalReviewDenied):
            self.preview()
        self.assertEqual(self.calls["load"], 1)
        self.assertEqual(self.calls["consent"], 2)

    def test_wrong_conversation_binding_does_not_screen_or_return(self):
        self.doc = dict(conversation(), id="different-owner-source")
        with self.assertRaises(HistoricalReviewDenied):
            self.preview()
        self.assertEqual(self.calls["load"], 1)
        self.assertEqual(self.calls["screen"], 0)

    def test_unauthorized_or_unscreened_content_never_returns(self):
        self.candidates = {"answer": candidate("answer")}
        self.assertEqual(self.preview(query="assistant"), ())
        self.candidates = {}
        self.assertEqual(self.preview(), ())

    def test_query_limits_precede_authentication_and_source_access(self):
        for query in ("", " " * 4, "x" * 129, 12):
            with self.subTest(query=str(query)[:20]), self.assertRaises(HistoricalReviewDenied):
                self.preview(query=query)
        for altered in ({"max_hits": True}, {"max_hits": 21},
                        {"active_branch_only": "false"},
                        {"export_sha256": "wrong"}, {"conversation_id": ""}):
            with self.subTest(altered=altered), self.assertRaises(HistoricalReviewDenied):
                self.preview(**altered)
        self.assertEqual(self.calls, {"auth": 0, "consent": 0, "load": 0, "screen": 0})

    def test_host_errors_are_fail_closed_without_private_exception_text(self):
        self.fail_consent = True
        with self.assertRaises(HistoricalReviewDenied) as error:
            self.preview()
        self.assertNotIn("private consent path", str(error.exception))
        self.fail_consent = False
        self.fail_load = True
        with self.assertRaises(HistoricalReviewDenied) as error:
            self.preview()
        self.assertNotIn("private archive path", str(error.exception))

    def test_callback_configuration_and_proof_repr_are_bounded(self):
        self.assertNotIn("test-windows-peer", repr(self.proof))
        with self.assertRaises(TypeError):
            HistoricalOwnerReviewGateway(
                authenticate=None, current_consent=self.current_consent,
                load_conversation=self.load, screen_candidates=self.screen,
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
