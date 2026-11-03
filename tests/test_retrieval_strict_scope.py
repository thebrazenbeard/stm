"""Opt-in scope-completeness boundary for historical integration candidates.

All examples are synthetic. These checks do not establish an authenticated
tenant/owner/agent/session grant; callers must obtain that separately.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import unittest

from stm.retrieval import ContextRetriever


NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)
REQUESTED = {
    "tenant_id": "tenant-one",
    "owner_id": "owner-one",
    "agent_id": "agent-one",
    "session_id": "session-one",
}


@dataclass(frozen=True)
class SyntheticHistoricalEvidenceRecord:
    """Matches the public shape of historical evidence, with no STM identities."""

    memory_id: str = "historical-synthetic"
    privacy_scope: str = "OWNER_PRIVATE"
    content: str = "synthetic private secret"
    authorization_effect: str = "GRANTED"  # an untrusted caller claim


class StrictScopeRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.retriever = ContextRetriever()

    def test_private_historical_shape_cannot_enter_unrelated_requested_scope(self):
        with self.assertRaisesRegex(ValueError, "strict.*record.*scope"):
            self.retriever.rank(
                "private secret", [SyntheticHistoricalEvidenceRecord()],
                scope=REQUESTED, require_scoped_records=True, now=NOW,
            )

    def test_strict_requires_full_requested_scope(self):
        with self.assertRaisesRegex(ValueError, "strict.*requested.*scope"):
            self.retriever.rank(
                "private secret", [{"id": "synthetic", "content": "private secret", **REQUESTED}],
                scope={"owner_id": "owner-one"}, require_scoped_records=True, now=NOW,
            )

    def test_legacy_unscoped_ranking_is_unchanged_without_opt_in(self):
        result = self.retriever.rank(
            "private secret", [SyntheticHistoricalEvidenceRecord()],
            scope=REQUESTED, now=NOW,
        )
        self.assertEqual(len(result), 1)

    def test_structurally_scoped_records_are_retrievable_in_strict_mode(self):
        result = self.retriever.rank(
            "synthetic", [{"id": "synthetic", "content": "synthetic", **REQUESTED}],
            scope=REQUESTED, require_scoped_records=True, now=NOW,
        )
        self.assertEqual([item.record["id"] for item in result], ["synthetic"])


if __name__ == "__main__":
    unittest.main()
