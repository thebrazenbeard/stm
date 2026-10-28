"""End-to-end synthetic Vera-host composition tests, never live Vera data.

The bridge only accepts a trusted host's verified principal. Tests here use a
synthetic broker and a real SQLite store plus retention runner; a separate
cryptographic-broker test below will exercise credential verification itself.
No HTTP localhost identity or deployed Vera service is implied.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from stm import STM, SessionKey
from stm.archive import ArchiveScope, ConversationArchive
from stm.history import HISTORICAL_ONLY
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.vera_bridge import VeraConversationBridge, VerifiedConversation
from stm.auth_broker import (
    ConversationCredentialSpec, HmacConversationBroker, HmacCredentialIssuer,
)


class HostEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "local.sqlite3")
        self.now = datetime.now(timezone.utc)
        self.scope = ArchiveScope("tenant", "owner", "vera")
        self.other = ArchiveScope("tenant", "another-owner", "vera")
        self.principal = object()  # Only an in-process test fixture.
        self.token = object()
        self.other_token = object()
        self.consent = True
        self.grant = VerifiedConversation(
            principal=self.principal,
            session=SessionKey("tenant", "owner", "vera", "new-session"),
            conversation_id="conversation-new",
            privacy_scopes=frozenset({"private"}),
            expires_at=self.now + timedelta(minutes=10),
            max_working_ttl_seconds=30,
            archive_consent=True,
            archive_retention_seconds=30,
        )
        self.archive = self.open_archive()
        self.addCleanup(lambda: self.archive.close())
        self.policy = RetentionPolicy(timedelta(seconds=30), frozenset({"private"}))
        self.retained = self.make_retained()
        self.runner = self.make_runner()
        self.bridge = self.make_bridge()

    def open_archive(self) -> ConversationArchive:
        return ConversationArchive(self.path, authorize=lambda principal, action, scope: (
            principal is self.principal
            and scope == self.scope
            and action in {
                "append", "search", "correct", "delete", "expire", "audit_legacy",
                "write_privacy:private", "read_privacy:private",
            }
        ))

    def make_retained(self) -> RetainedConversationArchive:
        return RetainedConversationArchive(
            self.archive, policy=self.policy,
            consent_check=lambda p, s, op, label: (
                self.consent and p is self.principal and s == self.scope
                and label == "private"
            ),
            clock=lambda: self.now,
        )

    def make_runner(self) -> RetentionSweepRunner:
        return RetentionSweepRunner(
            self.retained,
            targets=lambda: (SweepTarget(
                self.principal, self.scope, frozenset({"private"}),
            ),),
            batch_size=2, max_batches_per_target=4,
        )

    def resolve(self, opaque: object) -> VerifiedConversation:
        if opaque is not self.token:
            raise PermissionError("host did not authenticate this handle")
        return replace(self.grant, archive_consent=self.consent)

    @staticmethod
    def authorized(grant: VerifiedConversation, action: str, privacy: str) -> bool:
        return privacy == "private" and action in {
            "working_write:user", "working_context", "archive_write:user",
            "archive_read",
        }

    def make_bridge(self) -> VeraConversationBridge:
        class RetentionGate:
            def __init__(gate, outer: HostEndToEndTests):
                gate.outer = outer

            def verify(gate, grant: VerifiedConversation,
                       store: ConversationArchive) -> bool:
                outer = gate.outer
                if store is not outer.archive or grant.principal is not outer.principal:
                    return False
                if grant.archive_retention_seconds > outer.policy.maximum_age.total_seconds():
                    return False
                return outer.runner.run_once().complete

        return VeraConversationBridge(
            STM(clock=lambda: self.now), resolve=self.resolve,
            authorize=self.authorized, archive=self.archive,
            retention_gate=RetentionGate(self), clock=lambda: self.now,
        )

    def test_two_conversations_are_attributed_but_not_promoted(self) -> None:
        first = self.bridge.archive_turn(self.token, "Synthetic violet chart is valid")
        self.grant = replace(self.grant, conversation_id="conversation-next",
                             session=SessionKey("tenant", "owner", "vera", "later-session"))
        self.bridge.remember(self.token, "Synthetic cedar note in working context")
        hits = self.bridge.recall_history(
            self.token, "violet chart", privacy_scopes=frozenset({"private"}),
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].memory_id, first.turn_id)
        self.assertEqual(hits[0].result_semantics, HISTORICAL_ONLY)
        self.assertEqual(hits[0].source_ids[1],
                         "vera-local-conversation:conversation-new")
        current = self.bridge.working_context(self.token, "cedar",
                                              privacy="private", token_budget=512)
        self.assertIn("cedar note", current.text)
        self.assertNotIn("violet chart", current.text)

    def test_retention_catch_up_after_restart_and_consent_withdrawal(self) -> None:
        first = self.bridge.archive_turn(self.token, "Synthetic pine journal marker")
        self.assertIsNotNone(first.expires_at)
        self.consent = False
        with self.assertRaises(PermissionError):
            self.bridge.recall_history(self.token, "pine journal",
                                       privacy_scopes=frozenset({"private"}))
        self.archive.close()
        self.archive = self.open_archive()
        self.retained = self.make_retained()
        self.runner = self.make_runner()
        self.now += timedelta(seconds=31)
        report = self.runner.run_once()
        self.assertEqual(report.deleted, 1)
        self.assertTrue(report.complete)
        self.assertEqual(self.runner.run_once().deleted, 0)
        with closing(sqlite3.connect(self.path)) as raw, raw:
            self.assertEqual(raw.execute("SELECT count(*) FROM turns").fetchone()[0], 0)
            raw.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")

    def test_unverified_handles_and_cross_owner_scope_are_blocked(self) -> None:
        self.bridge.archive_turn(self.token, "Synthetic brass lantern memory")
        for forged in (None, self.other_token, "owner", self.grant):
            with self.subTest(forged=type(forged).__name__), self.assertRaises(PermissionError):
                self.bridge.recall_history(forged, "brass lantern",
                                           privacy_scopes=frozenset({"private"}))
        self.grant = replace(self.grant,
                             session=SessionKey("tenant", "another-owner", "vera", "new-session"),
                             conversation_id="conversation-new")
        # Even a valid-looking conversation locator cannot jump SQL owners.
        with self.assertRaises(PermissionError):
            self.bridge.recall_history(self.token, "brass lantern",
                                       privacy_scopes=frozenset({"private"}))


@dataclass(frozen=True)
class SyntheticTransportRequest:
    bearer: str
    # This is assigned by synthetic host test machinery. In production it
    # must come from verified socket/peer evidence, not client request JSON.
    authenticated_channel: str


class CryptographicBrokerEndToEndTests(unittest.TestCase):
    """Real MAC verification + a distinct host-only cleanup service identity."""

    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "signed.sqlite3")
        self.now = datetime.now(timezone.utc)
        self.scope = ArchiveScope("local", "signed-owner", "vera")
        self.session = SessionKey("local", "signed-owner", "vera", "new-chat")
        self.revoked = False
        self.host_cleanup_principal = object()
        self.issuer = HmacCredentialIssuer(
            b"integration-fixture-secret-key-at-least-32-bytes!",
            issuer="synthetic-verified-host", audience="vera-stm",
            clock=lambda: self.now,
        )
        self.broker = HmacConversationBroker(
            b"integration-fixture-secret-key-at-least-32-bytes!",
            issuer="synthetic-verified-host", audience="vera-stm",
            token_from_request=lambda req: req.bearer,
            channel_binding_from_request=lambda req: req.authenticated_channel,
            is_revoked=lambda issuer, subject, jti: self.revoked,
            clock=lambda: self.now,
        )
        self.credential = self.issuer.issue(ConversationCredentialSpec(
            subject="synthetic-owner-subject", session=self.session,
            conversation_id="signed-chat", privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({
                "working_write:user", "working_context", "archive_write:user",
                "archive_store", "archive_read",
            }),
            channel_binding="host-peer-credential-A",
            max_working_ttl_seconds=30,
            archive_consent=True, archive_retention_seconds=20,
        ), ttl_seconds=90)
        self.request = SyntheticTransportRequest(self.credential, "host-peer-credential-A")

        def authorize_archive(principal, operation, scope):
            if principal is self.host_cleanup_principal:
                # A separately authenticated host cleanup service may ONLY
                # expire eligible data in the registry-approved owner scope.
                return scope == self.scope and operation in {
                    "expire", "audit_legacy", "write_privacy:private",
                }
            return self.broker.authorize_archive(principal, operation, scope)

        self.archive = ConversationArchive(self.path, authorize=authorize_archive)
        self.addCleanup(lambda: self.archive.close())
        self.policy = RetentionPolicy(timedelta(seconds=20), frozenset({"private"}))

        def retained() -> RetainedConversationArchive:
            return RetainedConversationArchive(
                self.archive, policy=self.policy,
                consent_check=lambda *_: False,
                clock=lambda: self.now,
            )

        self.create_retained = retained
        self.runner = RetentionSweepRunner(
            self.create_retained(),
            targets=lambda: (SweepTarget(
                self.host_cleanup_principal, self.scope, frozenset({"private"}),
            ),),
        )

        class Gate:
            def __init__(gate, outer):
                gate.outer = outer

            def verify(gate, grant, store):
                return (store is gate.outer.archive
                        and grant.archive_retention_seconds <= gate.outer.policy.maximum_age.total_seconds()
                        and gate.outer.runner.run_once().complete)

        self.bridge = VeraConversationBridge(
            STM(clock=lambda: self.now), resolve=self.broker.resolve,
            authorize=self.broker.authorize,
            archive=self.archive, retention_gate=Gate(self),
            clock=lambda: self.now,
        )

    def test_signed_credentials_bind_context_and_reject_forgery(self) -> None:
        working = self.bridge.remember(self.request, "synthetic opal chart today")
        self.assertEqual(working.scope, self.session)
        packed = self.bridge.working_context(
            self.request, "opal", privacy="private", token_budget=512,
        )
        self.assertIn("opal chart", packed.text)
        wrong_binding = SyntheticTransportRequest(self.credential, "other-host-peer")
        with self.assertRaises(PermissionError):
            self.bridge.remember(wrong_binding, "forged host conversation")
        tampered = SyntheticTransportRequest(
            self.credential[:-1] + ("A" if self.credential[-1] != "A" else "B"),
            "host-peer-credential-A",
        )
        with self.assertRaises(PermissionError):
            self.bridge.remember(tampered, "tampered host conversation")
        with self.assertRaises(PermissionError):
            self.bridge.remember(self.request, "assistant impersonation",
                                 role="assistant")

    def test_signed_other_owner_same_locator_cannot_recall(self) -> None:
        record = self.bridge.archive_turn(
            self.request, "synthetic tungsten atlas private",
        )
        another = self.issuer.issue(ConversationCredentialSpec(
            subject="separate-owner", session=SessionKey(
                "local", "other-signed-owner", "vera", "new-chat",
            ),
            # The locator deliberately looks identical; only signed owner
            # and scope must decide whether an archive record is visible.
            conversation_id="signed-chat",
            privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({"archive_read", "archive_store"}),
            channel_binding="other-trusted-peer",
            max_working_ttl_seconds=30, archive_consent=True,
            archive_retention_seconds=20,
        ), ttl_seconds=90)
        other_request = SyntheticTransportRequest(another, "other-trusted-peer")
        self.assertEqual(self.bridge.recall_history(
            other_request, "tungsten atlas",
            privacy_scopes=frozenset({"private"}),
        ), ())
        self.assertEqual(self.bridge.recall_history(
            self.request, "tungsten atlas",
            privacy_scopes=frozenset({"private"}),
        )[0].memory_id, record.turn_id)

    def test_signed_archive_historical_recall_and_service_cleanup_after_expiry(self) -> None:
        record = self.bridge.archive_turn(
            self.request, "synthetic nebula station original",
        )
        self.assertIsNotNone(record.expires_at)
        before = self.bridge.recall_history(
            self.request, "nebula station", privacy_scopes=frozenset({"private"}),
        )
        self.assertEqual(len(before), 1)
        self.assertEqual(before[0].result_semantics, HISTORICAL_ONLY)
        self.assertEqual(before[0].source_ids[1], "vera-local-conversation:signed-chat")

        # Permission checking and retention are deliberately independent.
        # The host cleanup principal cannot read or append personal content.
        with self.assertRaises(PermissionError):
            self.archive.search(self.host_cleanup_principal, self.scope, "nebula",
                                privacy_scopes=frozenset({"private"}))
        with self.assertRaises(PermissionError):
            self.archive.append_turn(
                self.host_cleanup_principal, self.scope,
                conversation_id="forged", role="user", content="cannot insert",
            )

        # Simulate a restart/offline interval longer than user credentials.
        self.archive.close()
        self.archive = ConversationArchive(
            self.path, authorize=lambda principal, operation, scope: (
                principal is self.host_cleanup_principal and scope == self.scope
                and operation in {"expire", "audit_legacy", "write_privacy:private"}
            ) or self.broker.authorize_archive(principal, operation, scope),
        )
        self.now += timedelta(minutes=2)
        self.runner = RetentionSweepRunner(
            self.create_retained(),
            targets=lambda: (SweepTarget(
                self.host_cleanup_principal, self.scope, frozenset({"private"}),
            ),),
        )
        with self.assertRaises(PermissionError):
            self.bridge.recall_history(self.request, "nebula",
                                       privacy_scopes=frozenset({"private"}))
        report = self.runner.run_once()
        self.assertEqual(report.deleted, 1)
        self.assertTrue(report.complete)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT count(*) FROM turns").fetchone()[0], 0)
            db.execute("INSERT INTO turns_fts(turns_fts, rank) VALUES ('integrity-check', 1)")

    def test_signed_revocation_blocks_new_queries_before_expiry(self) -> None:
        self.bridge.remember(self.request, "synthetic chrome compass")
        self.revoked = True
        with self.assertRaises(PermissionError):
            self.bridge.working_context(self.request, "chrome", token_budget=256)
        with self.assertRaises(PermissionError):
            self.bridge.archive_turn(self.request, "revoked archival marker")



if __name__ == "__main__":
    unittest.main()
