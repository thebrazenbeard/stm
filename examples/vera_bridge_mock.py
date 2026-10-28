"""Synthetic host-broker integration smoke. NOT genuine Vera authentication.

Only toy data and an in-process mock identity are used. The gate purges on
write but has NO recurring job or backup policy; never deploy it as-is.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from stm import (
    ArchiveScope, ConversationArchive, SessionKey, STM,
    VeraConversationBridge, VerifiedConversation,
)


def main() -> None:
    now = datetime.now(timezone.utc)
    trusted_principal = object()  # Synthetic only; real host verifies credentials.
    request_handle = object()    # Opaque broker-only lookup key.
    key = SessionKey("synthetic", "demo-user", "vera", "conversation-2")
    scope = ArchiveScope(key.tenant_id, key.owner_id, key.agent_id)
    grant = VerifiedConversation(
        principal=trusted_principal,
        session=key,
        conversation_id="conversation-2",
        privacy_scopes=frozenset({"private"}),
        expires_at=now + timedelta(minutes=5),
        max_working_ttl_seconds=90,
        archive_consent=True,
        archive_retention_seconds=3600,
    )

    def resolve(opaque: object) -> VerifiedConversation:
        if opaque is not request_handle:
            raise PermissionError("unauthenticated")
        return grant

    def authorize_bridge(candidate: VerifiedConversation, operation: str,
                         privacy: str) -> bool:
        return (candidate is grant and privacy == "private" and operation in {
            "working_write:user", "archive_write:user", "archive_read",
        })

    def authorize_archive(candidate: object, operation: str,
                          requested_scope: ArchiveScope) -> bool:
        return (candidate is trusted_principal and requested_scope == scope
                and operation in {
                    "append", "search", "delete", "write_privacy:private",
                    "read_privacy:private",
                })

    class MockOnWriteGate:
        # Does NOT replace a real scheduler and managed backup lifecycle.
        def verify(self, checked_grant: VerifiedConversation,
                   store: ConversationArchive) -> bool:
            store.expire_due(checked_grant.principal, scope,
                             privacy_scopes=frozenset({"private"}))
            return checked_grant is grant

    with TemporaryDirectory() as temporary:
        with ConversationArchive(str(Path(temporary) / "archive.sqlite3"),
                                 authorize=authorize_archive) as archive:
            bridge = VeraConversationBridge(
                STM(), resolve=resolve, authorize=authorize_bridge,
                archive=archive, retention_gate=MockOnWriteGate(),
            )
            bridge.remember(request_handle, "Synthetic cedar schedule: Sunday")
            archived = bridge.archive_turn(
                request_handle, "Synthetic violet beacon is in the study",
            )
            recall = bridge.recall_history(
                request_handle, "violet beacon",
                privacy_scopes=frozenset({"private"}),
            )
            assert len(recall) == 1 and recall[0].memory_id == archived.turn_id
            assert archived.expires_at is not None
            print("Synthetic broker recall: 1 cited historical record; expires_at set")
            try:
                bridge.recall_history(object(), "violet",
                                      privacy_scopes=frozenset({"private"}))
            except PermissionError:
                print("Unauthenticated handle denied")
            else:
                raise AssertionError("failed-closed broker rule bypassed")


if __name__ == "__main__":
    main()
