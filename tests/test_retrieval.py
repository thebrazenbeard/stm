"""Standalone confirmation fixtures for STM retrieval. Run: python -m unittest -v."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import unittest

from stm.retrieval import ContextRetriever


NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Scope:
    tenant_id: str
    owner_id: str
    agent_id: str
    session_id: str


@dataclass(frozen=True)
class Record:
    id: str
    content: str
    scope: Scope
    updated_at: datetime = NOW
    expires_at: datetime | None = None
    deleted: bool = False
    source: str = "conversation"
    kind: str = "observation"
    topic: str = "default"
    privacy: str = "private"


def item(id: str, content: str, *, tenant: str = "t1", owner: str = "alice", agent: str = "a1", session: str = "one", hours: int = 0, **kw) -> Record:
    return Record(id, content, Scope(tenant, owner, agent, session), updated_at=NOW - timedelta(hours=hours), **kw)


class StaticEmbedder:
    def embed(self, text):
        return [1., 0.] if ("hamster" in text or "rodent" in text) else [0., 1.]


class BrokenEmbedder:
    def embed(self, text):
        raise RuntimeError("embedder offline")


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.retriever = ContextRetriever()

    def rank(self, query, records, **kw):
        return self.retriever.rank(query, records, scope=Scope("t1", "alice", "a1", "one"), now=NOW, **kw)

    def test_relevance_beats_unrelated_recency(self):  # E1
        records = [item("a", "I locked the bicycle in the red garage", hours=300),
                   item("b", "Today I drank mint tea", hours=0),
                   item("c", "The sky was gray", hours=1)]
        result = self.rank("where is the bicycle garage", records)
        self.assertEqual(result[0].record.id, "a")
        self.assertIn("bicycle", result[0].matched_terms)
        self.assertGreater(result[0].score, result[1].score)

    def test_identity_filters_before_scoring_and_embedding(self):  # E2
        records = [item("own", "The hamster sleeps in the pantry"),
                   item("other-owner", "The hamster is hidden in the garage", owner="bob"),
                   item("other-session", "The hamster escaped the cage", session="two"),
                   item("other-tenant", "The hamster escaped the home", tenant="t2"),
                   item("other-agent", "The hamster escaped the drawer", agent="a2")]
        result = self.rank("hamster", records)
        self.assertEqual([x.record.id for x in result], ["own"])
        semantic = ContextRetriever(embedder=StaticEmbedder())
        result = semantic.rank("hamster", records, scope=Scope("t1", "alice", "a1", "one"), now=NOW)
        self.assertEqual([x.record.id for x in result], ["own"])

    def test_missing_scope_fails_closed(self):
        with self.assertRaises(ValueError):
            self.retriever.rank("secret", [item("x", "secret")], now=NOW)
        with self.assertRaises(ValueError):
            self.retriever.rank("secret", [item("x", "secret")], owner_id="alice", now=NOW)

    def test_dedup_preserves_all_origins(self):  # E3
        first = item("first", "The project code is STM", source="user", hours=3)
        second = item("second", "the project CODE is STM", source="document", hours=1)
        third = item("third", "A separate fact about testing")
        result = self.rank("project STM", [first, second, third])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].record.id, "second")
        self.assertEqual(result[0].provenance_ids, ("second", "first"))
        self.assertEqual(result[0].provenance_records, (second, first))

    def test_dedup_never_merges_distinct_operators(self):
        result = self.rank("x", [item("greater", "x > y"), item("less", "x < y")])
        self.assertEqual(len(result), 2)
        self.assertEqual({r.record.id for r in result}, {"greater", "less"})

    def test_token_budget_skips_oversized_and_never_overflows(self):  # E4
        records = [item("large", "python " * 20), item("small", "python")]
        result = self.rank("python", records, token_budget=3, token_counter=lambda text: len(text.split()))
        self.assertEqual([x.record.id for x in result], ["small"])
        self.assertLessEqual(sum(x.token_cost for x in result), 3)
        self.assertEqual(self.rank("python", records, token_budget=0), [])
        with self.assertRaises(ValueError):
            self.rank("python", records, token_budget=-1)

    def test_contradiction_is_only_a_flag(self):
        records = [item("active", "deployment is active"),
                   item("inactive", "deployment is not active"),
                   item("other", "the deployment is in another region")]
        result = self.rank("deployment", records)
        by_id = {x.record.id: x for x in result}
        self.assertEqual(by_id["active"].potential_contradictions, ("inactive",))
        self.assertEqual(by_id["inactive"].potential_contradictions, ("active",))
        self.assertEqual(by_id["other"].potential_contradictions, ())

    def test_expired_and_deleted_are_invisible(self):
        result = self.rank("launch", [item("current", "launch planned"),
                                      item("expired", "launch canceled", expires_at=NOW),
                                      item("deleted", "launch secret", deleted=True)])
        self.assertEqual([x.record.id for x in result], ["current"])

    def test_optional_semantic_affects_relevance_not_authority(self):
        r = ContextRetriever(embedder=StaticEmbedder(), semantic_weight=.8)
        result = r.rank("rodent", [item("hamster", "hamster")], scope=Scope("t1", "alice", "a1", "one"), now=NOW)
        self.assertTrue(result[0].semantic_used)
        self.assertGreater(result[0].score, 0.7)

    def test_embedding_failure_policy(self):
        r = ContextRetriever(embedder=BrokenEmbedder(), embedding_errors="fallback")
        result = r.rank("piano", [item("x", "piano")], scope=Scope("t1", "alice", "a1", "one"), now=NOW)
        self.assertFalse(result[0].semantic_used)
        with self.assertRaises(RuntimeError):
            ContextRetriever(embedder=BrokenEmbedder()).rank("piano", [item("x", "piano")], scope=Scope("t1", "alice", "a1", "one"), now=NOW)

    def test_hierarchy_groups_without_merging_evidence(self):
        result = self.rank("work", [item("a", "work plan", topic="project"), item("b", "work schedule", topic="calendar")])
        grouped = self.retriever.group_by_topic(result)
        self.assertEqual({g.topic for g in grouped}, {"project", "calendar"})
        self.assertEqual(sum(len(g.results) for g in grouped), 2)

    def test_long_conversation_still_finds_old_relevant_context(self):
        records = [item("old", "renewal password stored in secure vault", hours=1000)]
        records.extend(item(f"noise-{n}", f"irrelevant message about lunch number {n}", hours=30) for n in range(2000))
        result = self.rank("renewal vault password", records, limit=3)
        self.assertEqual(result[0].record.id, "old")

    def test_negative_values_are_rejected(self):
        with self.assertRaises(ValueError):
            self.rank("test", [item("x", "test")], limit=-1)
        with self.assertRaises(ValueError):
            self.rank("test", [item("x", "test")], token_counter=lambda _: -1)
        with self.assertRaises(ValueError):
            self.rank("test", [item("x", "test")], token_counter=lambda _: 2.5)


if __name__ == "__main__":
    unittest.main()
