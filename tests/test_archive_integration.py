"""Public integration: historical conversation evidence cannot silently enter working STM."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from stm import ArchiveHistoryReader, ArchiveScope, ConversationArchive, STM
from stm.history import HISTORICAL_ONLY, HistoricalEvidenceBridge


class ArchiveIntegrationTests(unittest.TestCase):
    def test_multiple_conversations_remain_historical_until_explicit_use(self):
        principal = object()
        scope = ArchiveScope("tenant", "patrick", "vera")

        def authorize(actor, action, requested):
            return (actor is principal and requested == scope
                    and action in {"append", "search", "read_privacy:private", "write_privacy:private"})

        with TemporaryDirectory() as folder:
            with ConversationArchive(str(Path(folder) / "history.db"), authorize=authorize) as archive:
                archive.append_turn(principal, scope, conversation_id="earlier-chat", role="user",
                                    content="The museum meeting is Wednesday", source="turn:5")
                archive.append_turn(principal, scope, conversation_id="other-chat", role="user",
                                    content="The museum meeting is Thursday", source="turn:11")
                stm = STM()
                session = stm.open_session(tenant_id="tenant", owner_id="patrick",
                                           agent_id="vera", session_id="today")
                self.assertEqual(session.retrieve("museum"), [])

                bridge = HistoricalEvidenceBridge(
                    lambda query, active_scope, privacies, limit: ArchiveHistoryReader(
                        archive, principal
                    ).search(query, scope=active_scope, authorized_privacy_scopes=privacies,
                             limit=limit)
                )
                hits = bridge.search("museum", scope=session.key,
                                     authorized_privacy_scopes=frozenset({"private"}), limit=4)
                self.assertEqual(len(hits), 2)
                self.assertTrue(all(hit.result_semantics == HISTORICAL_ONLY for hit in hits))
                self.assertTrue(all(hit.source_ids[0] == hit.memory_id for hit in hits))
                # Retrieval did not admit either historical turn to active STM.
                self.assertEqual(session.retrieve("museum"), [])
                self.assertEqual(session.stats()["items"], 0)


if __name__ == "__main__":
    unittest.main()
