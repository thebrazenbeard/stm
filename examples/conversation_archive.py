"""Synthetic, offline demonstration of authorized cross-conversation evidence.

The simple principal/authorizer below are ONLY for this trusted local example.
They do not authenticate callers in a real Vera host or production service.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from stm.archive import ArchiveScope, ConversationArchive
from stm.archive_adapter import ArchiveHistoryReader
from stm.history import HistoricalEvidenceBridge, HISTORICAL_ONLY
from stm.models import SessionKey


@dataclass(frozen=True)
class DemoPrincipal:
    """Local fixture only; anyone who can instantiate it can forge its value."""

    owner: str


def demo_authorize(principal: object, action: str, scope: ArchiveScope) -> bool:
    """Toy policy. Replace with a trusted, host-authenticated permission check."""

    return (
        isinstance(principal, DemoPrincipal)
        and principal.owner == scope.owner_id
        and scope.tenant_id == "demo"
        and action in {
            "append", "search", "correct", "delete",
            "read_privacy:private", "write_privacy:private",
        }
    )


def main() -> None:
    with TemporaryDirectory(prefix="stm-v02-history-") as temp:
        db_path = str(Path(temp) / "conversation.sqlite3")
        alice = DemoPrincipal(owner="alice")
        scope = ArchiveScope(tenant_id="demo", owner_id="alice", agent_id="vera")
        current_session = SessionKey(
            tenant_id="demo", owner_id="alice", agent_id="vera", session_id="chat-current"
        )

        archive = ConversationArchive(db_path, authorize=demo_authorize)
        first = archive.append_turn(
            alice, scope, conversation_id="chat-january", role="user",
            content="The project codename is Cedar.", source="chat-january:turn-1",
            privacy="private",
        )
        old_schedule = archive.append_turn(
            alice, scope, conversation_id="chat-february", role="user",
            content="The compiler review is Friday.", source="chat-february:turn-3",
            privacy="private",
        )

        # The archive intentionally searches across conversation IDs, but only
        # inside the caller's authorized tenant/owner/agent/privacy scope.
        reader = ArchiveHistoryReader(archive, alice)
        bridge = HistoricalEvidenceBridge(
            lambda query, session_scope, visibility, limit: reader.search(
                query, scope=session_scope,
                authorized_privacy_scopes=visibility, limit=limit,
            )
        )
        hits = bridge.search(
            "compiler review", scope=current_session,
            authorized_privacy_scopes=frozenset({"private"}), limit=5,
        )
        assert hits and hits[0].result_semantics == HISTORICAL_ONLY
        print("Historical source IDs:", hits[0].source_ids)
        print("Historical evidence (untrusted):", hits[0].excerpt)

        corrected = archive.correct(
            alice, scope, old_schedule.turn_id,
            "The compiler review moved to Thursday.",
        )
        assert corrected.supersedes_id == old_schedule.turn_id
        assert not archive.search(
            alice, scope, "Friday", privacy_scopes=frozenset({"private"})
        )
        print("Corrected evidence:", corrected.turn_id)

        # Delete a separate turn so subsequent reopening demonstrates both
        # persistence of the correction and logical deletion from search.
        assert archive.delete(alice, scope, first.turn_id)
        assert not archive.search(
            alice, scope, "Cedar", privacy_scopes=frozenset({"private"})
        )
        archive.close()

        reopened = ConversationArchive(db_path, authorize=demo_authorize)
        try:
            surviving = reopened.search(
                alice, scope, "Thursday", privacy_scopes=frozenset({"private"})
            )
            assert surviving and surviving[0].turn.turn_id == corrected.turn_id
            print("Recovered corrected turn:", surviving[0].turn.content)
        finally:
            reopened.close()

    print("Demo finished. No personal data retained outside the temporary directory.")


if __name__ == "__main__":
    main()
