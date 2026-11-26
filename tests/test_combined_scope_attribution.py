"""Synthetic composition controls: attribution must follow scope admission."""
from datetime import datetime, timezone
import unittest
from stm.retrieval import ContextRetriever

NOW = datetime(2026, 11, 26, tzinfo=timezone.utc)
SCOPE = dict(tenant_id="fictional-tenant", owner_id="fictional-owner",
             agent_id="fictional-agent", session_id="fictional-session")

def row(identifier, role, **changes):
    return dict(id=identifier, content="I agree", role=role,
                source="fictional:dialogue", kind="observation",
                origin="direct", privacy="private", **SCOPE) | changes

class EmbedCounter:
    def __init__(self): self.calls = 0
    def embed(self, text):
        self.calls += 1
        return [1.0]

class Combined(unittest.TestCase):
    def test_conflicting_same_text_rejected_before_embedding(self):
        counter = EmbedCounter()
        r = ContextRetriever(preserve_attribution=True, embedder=counter)
        with self.assertRaisesRegex(ValueError, "conflicting direct and nested scope"):
            r.rank("agree", [row("a", "user"),
                     row("b", "assistant", scope=SCOPE | {"owner_id":"foreign"})],
                   scope=SCOPE, now=NOW)
        self.assertEqual(counter.calls, 0)

    def test_valid_distinct_speakers_survive_and_foreign_excluded(self):
        r = ContextRetriever(preserve_attribution=True)
        rows = r.rank("agree", [row("a","user"), row("b","assistant"),
                      row("c","user",owner_id="foreign")],
                      scope=SCOPE, now=NOW)
        self.assertEqual({(x.record["id"],x.record["role"]) for x in rows},
                         {("a","user"),("b","assistant")})

    def test_legitimate_duplicates_keep_provenance(self):
        r = ContextRetriever(preserve_attribution=True)
        rows = r.rank("agree", [row("a","user"),row("b","user"),row("c","assistant")],
                      scope=SCOPE, now=NOW)
        self.assertEqual(len(rows), 2)
        self.assertEqual({frozenset(x.provenance_ids) for x in rows},
                         {frozenset(("a","b")),frozenset(("c",))})

if __name__ == "__main__":
    unittest.main(verbosity=2)

