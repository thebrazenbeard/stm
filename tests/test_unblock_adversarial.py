"""Independent negative tests for Vera host integration trust boundaries.

These deliberately use a synthetic broker; they do not qualify VeraOS's
running localhost interface or a real authentication token verifier.
"""

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from contextlib import closing
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from stm import ArchiveScope, ConversationArchive, SessionKey, STM
from stm.auth_broker import (
    ConversationCredentialSpec, HmacConversationBroker, HmacCredentialIssuer,
)
from stm.retention import RetentionPolicy
from stm.retention import RetainedConversationArchive
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.storage_privacy import ManagedArchiveBackupVault
from stm.vera_bridge import VerifiedConversation, VeraConversationBridge


class UnblockAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = SessionKey("local", "owner-verified", "vera", "session-verified")
        self.now = datetime.now(timezone.utc)
        self.grant = VerifiedConversation(
            principal=object(), session=self.scope,
            conversation_id="verified-locator", privacy_scopes=frozenset({"private"}),
            expires_at=self.now + timedelta(minutes=5), max_working_ttl_seconds=120,
        )
        self.request = object()
        self.stm = STM()
        self.resolutions: list[object] = []

    def _resolve(self, request: object) -> VerifiedConversation:
        self.resolutions.append(request)
        if request is not self.request:
            raise PermissionError("unrecognized trusted request handle")
        return self.grant

    def _bridge(self, *, operation_allowed=None, archive=None, retention_gate=None):
        if operation_allowed is None:
            operation_allowed = lambda g, action, privacy: (
                g is self.grant and privacy == "private" and action in {
                    "working_write:user", "working_context", "archive_read",
                }
            )
        return VeraConversationBridge(
            self.stm, resolve=self._resolve, authorize=operation_allowed,
            archive=archive, retention_gate=retention_gate,
        )

    def test_private_prompt_excludes_unauthorized_shared_pinned_context(self) -> None:
        session = self.stm.open_session(
            tenant_id=self.scope.tenant_id, owner_id=self.scope.owner_id,
            agent_id=self.scope.agent_id, session_id=self.scope.session_id,
        )
        session.append("private green cardinal", privacy="private")
        # A pinned record must NOT override a private-only grant. Pinned
        # protection applies to authorized records, not all stored labels.
        session.append("SHARED_PINNED_CANARY_7734", privacy="shared", pinned=True)
        session.append("SESSION_HIDDEN_CANARY_5848", privacy="session", pinned=True)
        bridge = self._bridge()
        packed = bridge.working_context(
            self.request, "cardinal", privacy="private", token_budget=2000,
        )
        self.assertIn("private green cardinal", packed.text)
        self.assertNotIn("SHARED_PINNED_CANARY_7734", packed.text)
        self.assertNotIn("SESSION_HIDDEN_CANARY_5848", packed.text)
        self.assertEqual({record.privacy for record in packed.selected}, {"private"})
        self.assertEqual(self.resolutions, [self.request],
                         "the broker must issue one immutable grant per operation")
        with self.assertRaises(PermissionError):
            bridge.working_context(
                self.request, "cardinal", privacy="shared", token_budget=2000,
            )

    def test_untrusted_assistant_and_tool_role_must_be_denied_by_broker(self) -> None:
        bridge = self._bridge()
        for role in ("assistant", "tool", "system", "developer"):
            with self.subTest(role=role), self.assertRaises(PermissionError):
                bridge.remember(self.request, "forged provenance", role=role)
        session = self.stm.open_session(
            tenant_id=self.scope.tenant_id, owner_id=self.scope.owner_id,
            agent_id=self.scope.agent_id, session_id=self.scope.session_id,
        )
        self.assertEqual(session.retrieve("forged"), [])

    def test_revoked_broker_handle_cannot_recall_even_with_known_turn_id(self) -> None:
        with TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "history.sqlite")
            archive_scope = ArchiveScope("local", "owner-verified", "vera")
            with ConversationArchive(path, authorize=lambda p, a, s: (
                p is self.grant.principal and s == archive_scope
            )) as archive:
                original = archive.append_turn(
                    self.grant.principal, archive_scope,
                    conversation_id="known-locator", role="user",
                    content="synthetic magenta private fact", privacy="private",
                    expires_at=self.now + timedelta(days=1),
                )
                assert original.turn_id
                # An unrecognized request handle cannot turn a guessed
                # conversation identifier or known record ID into authority.
                bridge = self._bridge(archive=archive)
                with self.assertRaises(PermissionError):
                    bridge.recall_history(
                        "known-locator", "magenta", privacy_scopes=frozenset({"private"}),
                    )
                with self.assertRaises(PermissionError):
                    bridge.delete_archived("known-locator", original.turn_id)

    @unittest.skipUnless(os.name == "posix", "backup vault explicitly POSIX-only")
    def test_scope_authorized_backup_must_not_copy_foreign_owner_records(self) -> None:
        """A per-owner backup grant is not archive-wide export authority."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_directory = root / "live"
            vault_directory = root / "private-vault"
            live_directory.mkdir(mode=0o700)
            vault_directory.mkdir(mode=0o700)
            database = live_directory / "history.sqlite"
            alice = ArchiveScope("tenant", "alice", "vera")
            bob = ArchiveScope("tenant", "bob", "vera")
            privileged = object()
            alice_operator = object()
            with ConversationArchive(str(database), authorize=lambda *_: True) as archive:
                archive.append_turn(
                    privileged, alice, conversation_id="alice-chat", role="user",
                    content="ALICE_REVIEW_OK", privacy="private",
                )
                archive.append_turn(
                    privileged, bob, conversation_id="bob-chat", role="user",
                    content="BOB_SECRET_NEVER_EXPORT_FOR_ALICE", privacy="private",
                )
                vault = ManagedArchiveBackupVault(
                    str(vault_directory), archive_path=str(database), scope=alice,
                    policy=RetentionPolicy(timedelta(days=1), frozenset({"private"})),
                    authorize=lambda principal, action, scope: (
                        principal is alice_operator and scope == alice
                        and action in {"backup_create", "backup_list"}
                    ),
                )
                try:
                    receipt = vault.create(
                        alice_operator, retention=timedelta(hours=1),
                    )
                except PermissionError:
                    # Full-database backup correctly denied to a scope-only actor.
                    return
                with closing(sqlite3.connect(str(vault_directory / receipt.name))) as copy, copy:
                    archived_owners = {r[0] for r in copy.execute(
                        "SELECT owner_id FROM turns"
                    )}
                self.assertNotIn(
                    "bob", archived_owners,
                    "owner-specific backup must not export another owner's private rows",
                )

    @unittest.skipUnless(os.name == "posix", "backup vault explicitly POSIX-only")
    def test_backup_retention_must_not_extend_underlying_turn_expiry(self) -> None:
        """A backup is a derivative, not fresh consent to retain past a turn's TTL."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_directory = root / "live"
            vault_directory = root / "vault"
            live_directory.mkdir(mode=0o700)
            vault_directory.mkdir(mode=0o700)
            database = live_directory / "history.sqlite"
            alice = ArchiveScope("tenant", "alice", "vera")
            principal = object()
            original_expiry = datetime.now(timezone.utc) + timedelta(minutes=1)
            with ConversationArchive(str(database), authorize=lambda *_: True) as archive:
                archive.append_turn(
                    principal, alice, conversation_id="c", role="user",
                    content="highly time-bounded synthetic transcript",
                    privacy="private", expires_at=original_expiry,
                )
                vault = ManagedArchiveBackupVault(
                    str(vault_directory), archive_path=str(database), scope=alice,
                    policy=RetentionPolicy(timedelta(days=1), frozenset({"private"})),
                    authorize=lambda candidate, action, scope: (
                        candidate is principal and scope == alice and action in {
                            "backup_create", "backup_create_all_scopes",
                        }
                    ),
                )
                try:
                    receipt = vault.create(
                        principal, retention=timedelta(hours=1),
                    )
                except PermissionError:
                    # Safe alternative: backup refused when requested retention
                    # exceeds shortest independently granted turn deadline.
                    return
                self.assertLessEqual(
                    datetime.fromisoformat(receipt.expires_at), original_expiry,
                    "backup retention must not restart the source turn's TTL",
                )

    @unittest.skipUnless(os.name == "posix", "backup vault explicitly POSIX-only")
    def test_scope_only_actor_cannot_manage_whole_archive_backup(self) -> None:
        """Backup metadata, retirement and WAL are database-wide effects."""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            live_directory = root / "live"
            vault_directory = root / "vault"
            live_directory.mkdir(mode=0o700)
            vault_directory.mkdir(mode=0o700)
            path = live_directory / "history.sqlite"
            scope = ArchiveScope("tenant", "owner-A", "vera")
            global_operator = object()
            owner_operator = object()
            with ConversationArchive(str(path), authorize=lambda *_: True) as archive:
                archive.append_turn(
                    global_operator, scope, conversation_id="a", role="user",
                    content="synthetic long-lived archive marker",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=2),
                )

                def authorize(candidate, verb, requested_scope):
                    if requested_scope != scope:
                        return False
                    if candidate is global_operator:
                        return verb.startswith("backup_") or verb == "wal_checkpoint"
                    if candidate is owner_operator:
                        return verb in {"backup_list", "backup_retire", "wal_checkpoint"}
                    return False

                vault = ManagedArchiveBackupVault(
                    str(vault_directory), archive_path=str(path), scope=scope,
                    policy=RetentionPolicy(timedelta(days=3), frozenset({"private"})),
                    authorize=authorize,
                )
                vault.create(global_operator, retention=timedelta(hours=1))
                for effect in (
                    lambda: vault.inventory(owner_operator),
                    lambda: vault.retire_due(
                        owner_operator, now=datetime.now(timezone.utc) + timedelta(hours=2),
                        dry_run=False,
                    ),
                    lambda: vault.checkpoint_wal(owner_operator),
                ):
                    with self.subTest(effect=effect), self.assertRaises(PermissionError):
                        effect()

    def test_retention_sweep_must_not_certify_legacy_rows_as_complete(self) -> None:
        """Unexpired-by-policy NULL rows cannot silently be called 'clean'."""
        with TemporaryDirectory() as temporary:
            database = str(Path(temporary) / "legacy.sqlite")
            scope = ArchiveScope("tenant", "alice", "vera")
            with ConversationArchive(database, authorize=lambda *_: True) as archive:
                archive.append_turn(
                    "trusted-cleaner", scope, conversation_id="old", role="user",
                    content="legacy plaintext lacking any retention deadline",
                )
                governed = RetainedConversationArchive(
                    archive,
                    policy=RetentionPolicy(timedelta(days=1), frozenset({"private"})),
                    consent_check=lambda *_: True,
                )
                runner = RetentionSweepRunner(
                    governed,
                    targets=lambda: [SweepTarget(
                        "trusted-cleaner", scope, frozenset({"private"}),
                    )],
                )
                try:
                    receipt = runner.run_once()
                except (PermissionError, RuntimeError):
                    # Safe outcome: report legacy state as requiring an
                    # explicit authority-backed migration/erasure decision.
                    return
                self.assertFalse(
                    receipt.complete,
                    "a clean sweep receipt cannot certify retained legacy NULL-expiry rows",
                )

    def test_single_use_credential_must_not_replay_after_broker_restart(self) -> None:
        """A process-local nonce cache is not durable replay protection."""
        key = b"synthetic-test-hmac-key-is-at-least-32-bytes!"
        channel = "verified-synthetic-peer-channel"
        when = datetime.now(timezone.utc)
        issuer = HmacCredentialIssuer(
            key, issuer="trusted-local-host", audience="stm-only",
            clock=lambda: when,
        )
        spec = ConversationCredentialSpec(
            subject="user-A", session=self.scope,
            conversation_id="verified-locator", privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({"working_write:user"}),
            channel_binding=channel, max_working_ttl_seconds=30,
        )
        token = issuer.issue(spec, ttl_seconds=90)

        @dataclass(frozen=True)
        class SyntheticRequest:
            bearer: str
            proven_binding: str

        request = SyntheticRequest(token, channel)

        def broker():
            return HmacConversationBroker(
                key, issuer="trusted-local-host", audience="stm-only",
                token_from_request=lambda r: r.bearer,
                channel_binding_from_request=lambda r: r.proven_binding,
                is_revoked=lambda *_: False,
                clock=lambda: when,
                single_use=True,
            )

        try:
            before = broker()
        except (PermissionError, ValueError):
            # Safe design: reject single-use mode without a durable ledger.
            return
        before.resolve(request)
        with self.assertRaises(PermissionError):
            before.resolve(request)
        try:
            after_restart = broker()
        except (PermissionError, ValueError):
            return
        with self.assertRaises(PermissionError):
            after_restart.resolve(request)


if __name__ == "__main__":
    unittest.main()
