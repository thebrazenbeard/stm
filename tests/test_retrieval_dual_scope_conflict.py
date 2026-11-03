"""Source-only negative controls: contradictory identity labels cannot pass STM retrieval.

All records are synthetic. The direct fields and nested scope must agree
before a candidate can enter scoring or optional embedding.
"""
from datetime import datetime, timezone
import unittest

from stm.retrieval import ContextRetriever


NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
AUTHORIZED = {
    "tenant_id": "synthetic-tenant",
    "owner_id": "synthetic-owner",
    "agent_id": "synthetic-agent",
    "session_id": "synthetic-session",
}


def candidate(*, conflicting_field=None):
    record = {
        "id": "synthetic-record",
        "content": "synthetic retrieval boundary test",
        **AUTHORIZED,
        "scope": dict(AUTHORIZED),
    }
    if conflicting_field is not None:
        record["scope"][conflicting_field] = "different-" + conflicting_field
    return record


class DualScopeRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.retriever = ContextRetriever()

    def test_conflicting_direct_and_nested_identity_fails_closed(self):
        for field in AUTHORIZED:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "conflicting direct and nested scope"):
                    self.retriever.rank(
                        "synthetic", [candidate(conflicting_field=field)],
                        scope=dict(AUTHORIZED), now=NOW,
                    )

    def test_equality_spoofed_identity_does_not_bypass_scope_guard(self):
        class SpoofedStr(str):
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        record = candidate()
        record["owner_id"] = SpoofedStr("not-the-authorized-owner")
        with self.assertRaisesRegex(ValueError, "scope identity must be"):
            self.retriever.rank(
                "synthetic", [record], scope=dict(AUTHORIZED), now=NOW,
            )

        requested = dict(AUTHORIZED)
        requested["owner_id"] = SpoofedStr("not-the-authorized-owner")
        with self.assertRaisesRegex(ValueError, "requested scope must be"):
            self.retriever.rank(
                "synthetic", [candidate()], scope=requested, now=NOW,
            )

    def test_matching_direct_and_nested_identity_remains_usable(self):
        result = self.retriever.rank(
            "synthetic", [candidate()], scope=dict(AUTHORIZED), now=NOW,
        )
        self.assertEqual([item.record["id"] for item in result], ["synthetic-record"])


if __name__ == "__main__":
    unittest.main()
