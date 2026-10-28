"""Synthetic backup-vault, SQLite snapshot and WAL safety regressions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import closing
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import quote

from stm.archive import ArchiveScope, ConversationArchive
from stm.retention import RetentionPolicy
from stm.storage_privacy import ManagedArchiveBackupVault


SCOPE = ArchiveScope("local", "test-owner", "vera")


@unittest.skipUnless(os.name == "posix", "POSIX-only ACL implementation")
class ManagedBackupVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = root / "archive.sqlite3"
        self.vault_path = root / "backups"
        self.vault_path.mkdir(mode=0o700)
        self.principal = object()
        self.now = datetime.now(timezone.utc)
        self.policy = RetentionPolicy(timedelta(days=2), frozenset({"private"}))
        self.archive = ConversationArchive(str(self.db_path), authorize=lambda *_: True)
        self.archive.append_turn(self.principal, SCOPE, conversation_id="chat-one",
                                 role="user", content="lavender synthetic snapshot",
                                 expires_at=self.now + timedelta(days=2))

        def authorize(candidate, operation, scope):
            return candidate is self.principal and scope == SCOPE and operation in {
                "backup_create", "backup_create_all_scopes", "backup_list",
                "backup_list_all_scopes", "backup_retire",
                "backup_retire_all_scopes", "wal_checkpoint",
                "wal_checkpoint_all_scopes",
            }

        self.authorize = authorize
        self.vault = ManagedArchiveBackupVault(
            str(self.vault_path), archive_path=str(self.db_path),
            scope=SCOPE, policy=self.policy, authorize=authorize,
        )

    def tearDown(self) -> None:
        self.archive.close()
        self.temp.cleanup()

    def test_online_snapshot_is_consistent_source_attributed_and_private(self) -> None:
        receipt = self.vault.create(self.principal, retention=timedelta(days=1),
                                    now=self.now)
        snapshot = self.vault_path / receipt.name
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt.bytes, snapshot.stat().st_size)
        self.assertEqual(len(receipt.sha256), 64)
        self.archive.append_turn(self.principal, SCOPE, conversation_id="chat-two",
                                 role="user", content="amber added after snapshot",
                                 expires_at=self.now + timedelta(days=2))
        # Snapshots are immutable evidence; opening them read-write could
        # manufacture new WAL/SHM derivatives inside the private vault.
        with closing(sqlite3.connect(
            f"file:{quote(str(snapshot), safe='/')}?mode=ro&immutable=1", uri=True,
        )) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM turns").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        records = self.vault.inventory(self.principal)
        self.assertEqual(records.managed, (receipt,))
        self.assertEqual(records.unmanaged_names, ())

    def test_bounded_expiry_dry_run_and_idempotent_retirement(self) -> None:
        receipt = self.vault.create(self.principal, retention=timedelta(hours=1),
                                    now=self.now)
        preview = self.vault.retire_due(self.principal,
                                        now=self.now + timedelta(hours=2))
        self.assertEqual((preview.due, preview.removed, preview.dry_run), (1, 0, True))
        self.assertEqual((preview.remaining, preview.complete), (1, False))
        self.assertTrue((self.vault_path / receipt.name).exists())
        applied = self.vault.retire_due(self.principal, dry_run=False,
                                        now=self.now + timedelta(hours=2))
        self.assertEqual((applied.due, applied.removed), (1, 1))
        self.assertEqual((applied.remaining, applied.complete), (0, True))
        self.assertFalse((self.vault_path / receipt.name).exists())
        self.assertEqual(self.vault.inventory(self.principal).managed, ())
        self.assertEqual(self.vault.retire_due(self.principal, dry_run=False).due, 0)

    def test_unknown_files_remain_visible_and_are_never_deleted(self) -> None:
        receipt = self.vault.create(self.principal, retention=timedelta(seconds=1),
                                    now=self.now)
        unknown = self.vault_path / "other-unmanaged.sqlite3"
        unknown.write_text("unmanaged data", encoding="utf-8")
        os.chmod(unknown, 0o600)
        self.assertIn(unknown.name, self.vault.inventory(self.principal).unmanaged_names)
        self.vault.retire_due(self.principal,
                              now=self.now + timedelta(days=1), dry_run=False)
        self.assertTrue(unknown.exists())
        self.assertFalse((self.vault_path / receipt.name).exists())

    def test_authorization_is_enforced_before_every_external_effect(self) -> None:
        imposter = object()
        for method in (
            lambda: self.vault.create(imposter, retention=timedelta(days=1)),
            lambda: self.vault.inventory(imposter),
            lambda: self.vault.retire_due(imposter, dry_run=False),
            lambda: self.vault.checkpoint_wal(imposter),
        ):
            with self.subTest(method=method), self.assertRaises(PermissionError):
                method()
        self.assertEqual(tuple(self.vault_path.iterdir()), ())

    def test_symlink_replacement_cannot_be_purged(self) -> None:
        receipt = self.vault.create(self.principal, retention=timedelta(seconds=1),
                                    now=self.now)
        path = self.vault_path / receipt.name
        path.unlink()
        outside = Path(self.temp.name) / "do-not-delete.txt"
        outside.write_text("synthetic, preserve", encoding="utf-8")
        path.symlink_to(outside)
        with self.assertRaises(PermissionError):
            self.vault.retire_due(self.principal,
                                  now=self.now + timedelta(days=1), dry_run=False)
        self.assertEqual(outside.read_text(encoding="utf-8"), "synthetic, preserve")

    def test_modified_snapshot_refuses_auto_deletion(self) -> None:
        receipt = self.vault.create(self.principal, retention=timedelta(seconds=1),
                                    now=self.now)
        path = self.vault_path / receipt.name
        with path.open("ab") as output:
            output.write(b"modified-after-registration")
        with self.assertRaises(PermissionError):
            self.vault.retire_due(self.principal,
                                  now=self.now + timedelta(days=1), dry_run=False)
        self.assertTrue(path.exists())

    def test_missing_manifest_in_existing_vault_fails_closed(self) -> None:
        stray = self.vault_path / "old_unknown.sqlite3"
        stray.write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "uninitialized nonempty"):
            self.vault.create(self.principal, retention=timedelta(days=1))
        self.assertTrue(stray.exists())

    def test_unsafe_parent_and_relative_paths_rejected(self) -> None:
        os.chmod(self.vault_path, 0o755)
        try:
            with self.assertRaises(PermissionError):
                ManagedArchiveBackupVault(str(self.vault_path),
                                         archive_path=str(self.db_path),
                                         scope=SCOPE, policy=self.policy,
                                         authorize=self.authorize)
        finally:
            os.chmod(self.vault_path, 0o700)
        with self.assertRaises(ValueError):
            ManagedArchiveBackupVault("relative-vault", archive_path=str(self.db_path),
                                     scope=SCOPE, policy=self.policy,
                                     authorize=self.authorize)

    def test_lock_prevents_concurrent_or_stale_manifest_mutation(self) -> None:
        lock = self.vault_path / "stm-backup-index.lock"
        lock.write_text("stale", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "busy or has an unresolved stale lock"):
            self.vault.inventory(self.principal)
        self.assertTrue(lock.exists())

    def test_sqlite_wal_checkpoint_reports_success_without_erasure_claim(self) -> None:
        result = self.vault.checkpoint_wal(self.principal)
        self.assertEqual(result.busy, 0)
        self.assertIsInstance(result.log_pages, int)
        self.assertIsInstance(result.checkpointed_pages, int)
        hits = self.archive.search(self.principal, SCOPE, "lavender",
                                   privacy_scopes=frozenset({"private"}))
        self.assertEqual(len(hits), 1)

    def test_policy_age_limit_and_unsafe_inputs(self) -> None:
        for invalid in (timedelta(0), timedelta(days=-1), timedelta(days=3)):
            with self.assertRaises(ValueError):
                self.vault.create(self.principal, retention=invalid)
        for invalid_limit in (0, 101, True):
            with self.assertRaises(ValueError):
                self.vault.retire_due(self.principal, limit=invalid_limit)

    def test_archive_wide_capability_is_distinct_from_single_scope_grants(self) -> None:
        other = ArchiveScope("local", "different-owner", "vera")
        self.archive.append_turn(self.principal, other, conversation_id="other-chat",
                                 role="user", content="other private tenant data",
                                 expires_at=self.now + timedelta(days=1))
        def scope_only(principal, operation, scope):
            return (principal is self.principal and scope == SCOPE
                    and operation == "backup_create")
        unprivileged = ManagedArchiveBackupVault(
            str(self.vault_path), archive_path=str(self.db_path), scope=SCOPE,
            policy=self.policy, authorize=scope_only,
        )
        with self.assertRaisesRegex(PermissionError, "backup authorization denied"):
            unprivileged.create(self.principal, retention=timedelta(days=1))
        self.assertEqual(tuple(self.vault_path.iterdir()), ())

    def test_backup_expires_no_later_than_earliest_contained_record(self) -> None:
        sooner = self.now + timedelta(minutes=10)
        self.archive.append_turn(self.principal, SCOPE, conversation_id="chat-two",
                                 role="user", content="urgent short retention",
                                 expires_at=sooner)
        receipt = self.vault.create(self.principal, retention=timedelta(days=1))
        self.assertLessEqual(datetime.fromisoformat(receipt.expires_at), sooner)

    def test_policyless_and_expired_records_block_full_snapshot(self) -> None:
        self.archive.append_turn(self.principal, SCOPE, conversation_id="chat-old",
                                 role="user", content="policyless legacy evidence")
        # A known ineligible source must be refused BEFORE SQLite opens a
        # plaintext backup destination, not merely unlinked after copying.
        actual_connect = sqlite3.connect
        destination_opens = []

        def traced_connect(database, *args, **kwargs):
            if str(database).startswith(str(self.vault_path)):
                destination_opens.append(str(database))
            return actual_connect(database, *args, **kwargs)

        with patch("stm.storage_privacy.sqlite3.connect", side_effect=traced_connect):
            with self.assertRaisesRegex(PermissionError, "policyless"):
                self.vault.create(self.principal, retention=timedelta(hours=1))
        self.assertEqual(destination_opens, [])
        self.assertEqual(tuple(self.vault_path.iterdir()), ())

    def test_consent_revocation_can_invalidate_all_known_backup_copies(self) -> None:
        first = self.vault.create(self.principal, retention=timedelta(days=1))
        second = self.vault.create(self.principal, retention=timedelta(days=1))
        unrelated = self.vault_path / "external-copy.sqlite3"
        unrelated.write_text("external data", encoding="utf-8")
        self.assertEqual(self.vault.retire_all(
            self.principal, reason="consent_revoked", limit=1,
        ).due, 1)
        self.assertTrue((self.vault_path / first.name).exists())
        with self.assertRaises(ValueError):
            self.vault.retire_all(self.principal, reason="unknown event", dry_run=False)
        first_batch = self.vault.retire_all(
            self.principal, reason="source_turn_deleted", limit=1, dry_run=False,
        )
        self.assertEqual((first_batch.removed, first_batch.remaining,
                          first_batch.complete), (1, 1, False))
        self.assertTrue((self.vault_path / second.name).exists())
        second_batch = self.vault.retire_all(
            self.principal, reason="source_turn_deleted", dry_run=False,
        )
        self.assertEqual((second_batch.removed, second_batch.remaining,
                          second_batch.complete), (1, 0, True))
        self.assertTrue(unrelated.exists())
        self.assertEqual(self.vault.inventory(self.principal).managed, ())


if __name__ == "__main__":
    unittest.main()
