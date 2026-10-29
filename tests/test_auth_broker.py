"""Cryptographic broker and maintenance authorization boundary regressions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import tempfile
import unittest

from stm.archive import ArchiveScope, ConversationArchive
from stm.auth_broker import (
    ConversationCredentialSpec, HmacCredentialIssuer,
    HmacConversationBroker, ScopedCleanupAuthority,
)
from stm.models import SessionKey
from stm.vera_bridge import VerifiedConversation


SCOPE = SessionKey("vera-local", "owner-1", "vera", "chat-7")
OTHER = SessionKey("vera-local", "owner-2", "vera", "chat-7")
ARCHIVE_SCOPE = ArchiveScope("vera-local", "owner-1", "vera")
ARCHIVE_OTHER = ArchiveScope("vera-local", "owner-2", "vera")


@dataclass(frozen=True)
class SyntheticAuthenticatedRequest:
    """Test host transport; no claim of actual OS peer verification."""
    bearer: str
    trusted_transport_binding: str


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = secrets.token_bytes(32)
        self.revoked: set[str] = set()
        self.consumed: set[str] = set()
        self.issuer = HmacCredentialIssuer(
            self.key, issuer="vera-local-host", audience="stm-conversation-v1",
            clock=lambda: self.now,
        )
        self.spec = ConversationCredentialSpec(
            subject="subject-from-trusted-identity-provider",
            session=SCOPE,
            conversation_id="chat-7",
            privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({
                "working_write:user", "archive_write:user", "archive_read",
                "archive_store", "archive_delete",
            }),
            channel_binding="os-peer-verified-credential:session-channel-35",
            max_working_ttl_seconds=60,
            archive_consent=True,
            archive_retention_seconds=3600,
        )
        self.broker = self.make_broker()

    def make_broker(self, *, key=None, issuer="vera-local-host",
                    audience="stm-conversation-v1", single_use=False,
                    max_active_grants=2048, revoked=None):
        def claim_jti(_issuer, _subject, token_id, _expiry):
            # Simulates an atomic shared ledger across broker instances; a
            # production caller MUST supply a truly durable version.
            if token_id in self.consumed:
                return False
            self.consumed.add(token_id)
            return True

        return HmacConversationBroker(
            key or self.key, issuer=issuer, audience=audience,
            token_from_request=lambda request: request.bearer,
            channel_binding_from_request=lambda request: request.trusted_transport_binding,
            is_revoked=lambda iss, sub, jti: (jti in self.revoked if revoked is None else revoked),
            clock=lambda: self.now,
            single_use=single_use,
            consume_jti=claim_jti if single_use else None,
            max_active_grants=max_active_grants,
        )

    def request(self, spec=None, *, ttl=60, binding=None):
        candidate = self.spec if spec is None else spec
        return SyntheticAuthenticatedRequest(
            self.issuer.issue(candidate, ttl_seconds=ttl),
            candidate.channel_binding if binding is None else binding,
        )

    def test_valid_mac_issues_one_opaque_scope_bound_principal(self):
        grant = self.broker.resolve(self.request())
        self.assertIsInstance(grant, VerifiedConversation)
        self.assertEqual(grant.session, SCOPE)
        self.assertEqual(grant.privacy_scopes, frozenset({"private"}))
        self.assertNotEqual(grant.principal, self.spec.subject)
        self.assertTrue(self.broker.authorize(grant, "working_write:user", "private"))
        self.assertFalse(self.broker.authorize(grant, "working_write:assistant", "private"))
        self.assertFalse(self.broker.authorize(grant, "archive_read", "shared"))
        self.assertFalse(self.broker.authorize(replace(grant), "archive_read", "private"))
        self.assertTrue(self.broker.authorize_archive(grant.principal, "search", ARCHIVE_SCOPE))
        self.assertFalse(self.broker.authorize_archive(grant.principal, "search", ARCHIVE_OTHER))
        self.assertFalse(self.broker.authorize_archive(grant.principal, "read_privacy:shared", ARCHIVE_SCOPE))

    def test_unknown_claimed_identity_cannot_authenticate(self):
        for request in (None, object(), "owner-1", SCOPE, self.spec):
            with self.subTest(request=repr(request)), self.assertRaises(PermissionError):
                self.broker.resolve(request)
        self.assertFalse(self.broker.authorize_archive(object(), "search", ARCHIVE_SCOPE))

    def test_tamper_wrong_audience_issuer_key_and_binding_fail(self):
        valid = self.request()
        altered = valid.bearer.split(".", 1)
        altered[0] = ("A" if altered[0][0] != "A" else "B") + altered[0][1:]
        with self.assertRaises(PermissionError):
            self.broker.resolve(replace(valid, bearer=".".join(altered)))
        for broker in (
            self.make_broker(key=secrets.token_bytes(32)),
            self.make_broker(issuer="impostor"),
            self.make_broker(audience="different-service"),
        ):
            with self.subTest(broker=broker), self.assertRaises(PermissionError):
                broker.resolve(valid)
        with self.assertRaises(PermissionError):
            self.broker.resolve(replace(valid, trusted_transport_binding="attacker-supplied"))

    def test_replay_and_expiration(self):
        single = self.make_broker(single_use=True)
        request = self.request(ttl=5)
        grant = single.resolve(request)
        self.assertTrue(single.authorize(grant, "archive_read", "private"))
        with self.assertRaisesRegex(PermissionError, "replay"):
            single.resolve(request)
        after_restart = self.make_broker(single_use=True)
        with self.assertRaisesRegex(PermissionError, "replay"):
            after_restart.resolve(request)
        self.now += timedelta(seconds=6)
        self.assertFalse(single.authorize(grant, "archive_read", "private"))
        self.assertFalse(single.authorize_archive(grant.principal, "search", ARCHIVE_SCOPE))
        with self.assertRaises(PermissionError):
            self.broker.resolve(request)

    def test_revocation_and_unknown_revocation_fail_closed(self):
        request = self.request()
        grant = self.broker.resolve(request)
        import json, base64
        payload = json.loads(base64.urlsafe_b64decode(request.bearer.split(".")[0] + "=="))
        self.revoked.add(payload["jti"])
        self.assertFalse(self.broker.authorize(grant, "archive_read", "private"))
        self.assertFalse(self.broker.authorize_archive(grant.principal, "search", ARCHIVE_SCOPE))
        with self.assertRaises(PermissionError):
            self.broker.resolve(request)
        unknown = self.make_broker(revoked=None)
        unknown._is_revoked = lambda *_: (_ for _ in ()).throw(RuntimeError("store unavailable"))
        with self.assertRaises(PermissionError):
            unknown.resolve(self.request())

    def test_issuer_requires_strong_key_lifetime_and_explicit_limits(self):
        with self.assertRaises(ValueError):
            HmacCredentialIssuer(b"short", issuer="vera", audience="stm")
        with self.assertRaisesRegex(ValueError, "durable atomic replay ledger"):
            HmacConversationBroker(
                self.key, issuer="vera-local-host", audience="stm-conversation-v1",
                token_from_request=lambda r: r.bearer,
                channel_binding_from_request=lambda r: r.trusted_transport_binding,
                is_revoked=lambda *_: False, single_use=True,
            )
        for lifetime in (0, 301, -3, True):
            with self.subTest(lifetime=lifetime), self.assertRaises(ValueError):
                self.issuer.issue(self.spec, ttl_seconds=lifetime)
        for invalid_field in (
            {"capabilities": frozenset({"*"})},
            {"archive_retention_seconds": 91 * 86400},
            {"privacy_scopes": frozenset({"all"})},
        ):
            with self.subTest(invalid=invalid_field), self.assertRaises(ValueError):
                replace(self.spec, **invalid_field)

    def test_single_use_registry_capacity_fails_closed(self):
        broker = self.make_broker(single_use=True, max_active_grants=1)
        seen = []
        for _ in range(8):
            request = self.request()
            seen.append(request)
            broker.resolve(request)
        with self.assertRaisesRegex(PermissionError, "registry full"):
            broker.resolve(self.request())
        with self.assertRaisesRegex(PermissionError, "replay"):
            broker.resolve(seen[-1])

    def test_archive_authorizer_requires_distinct_raw_capability(self):
        minimal = replace(self.spec,
                          capabilities=frozenset({"archive_write:user"}))
        grant = self.broker.resolve(self.request(minimal))
        self.assertTrue(self.broker.authorize(grant, "archive_write:user", "private"))
        self.assertFalse(self.broker.authorize_archive(grant.principal, "append", ARCHIVE_SCOPE))
        self.assertFalse(self.broker.authorize_archive(grant.principal, "search", ARCHIVE_SCOPE))

    def test_correction_requires_current_archival_consent(self):
        no_consent = replace(self.spec, archive_consent=False,
                             archive_retention_seconds=None,
                             capabilities=frozenset({"archive_correct", "archive_delete"}))
        revoked = self.broker.resolve(self.request(no_consent))
        self.assertFalse(self.broker.authorize_archive(revoked.principal, "correct", ARCHIVE_SCOPE))
        # Label authorization must also independently deny this write path.
        write_only = self.broker.resolve(self.request(replace(
            no_consent, capabilities=frozenset({"archive_correct"}),
        )))
        self.assertFalse(self.broker.authorize_archive(
            write_only.principal, "write_privacy:private", ARCHIVE_SCOPE,
        ))
        # A user may revoke consent without losing the right to erase data.
        self.assertTrue(self.broker.authorize_archive(revoked.principal, "delete", ARCHIVE_SCOPE))
        consented = self.broker.resolve(self.request(replace(
            self.spec, capabilities=frozenset({"archive_correct"}),
        )))
        self.assertTrue(self.broker.authorize_archive(consented.principal, "correct", ARCHIVE_SCOPE))


class CleanupAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = secrets.token_bytes(32)
        self.scope = ArchiveScope("tenant", "owner", "vera")
        self.service = ScopedCleanupAuthority(
            self.key, scope=self.scope, privacy_scopes=frozenset({"private"}),
            clock=lambda: self.now, lease_seconds=5,
        )

    def test_service_principal_is_unforgeable_scoped_and_delete_only(self):
        with self.assertRaises(PermissionError):
            self.service.acquire(secrets.token_bytes(32))
        principal = self.service.acquire(self.key)
        self.assertTrue(self.service.authorize_archive(principal, "expire", self.scope))
        self.assertTrue(self.service.authorize_archive(principal, "audit_legacy", self.scope))
        self.assertTrue(self.service.authorize_archive(principal, "write_privacy:private", self.scope))
        for action in ("append", "search", "correct", "delete", "read_privacy:private",
                       "write_privacy:shared"):
            with self.subTest(action=action):
                self.assertFalse(self.service.authorize_archive(principal, action, self.scope))
        self.assertFalse(self.service.authorize_archive(principal, "expire",
                                                        ArchiveScope("tenant", "other", "vera")))
        self.assertFalse(self.service.authorize_archive(object(), "expire", self.scope))
        self.now += timedelta(seconds=6)
        self.assertFalse(self.service.authorize_archive(principal, "expire", self.scope))

    def test_service_can_sweep_expired_after_user_grant_expired(self):
        user_key = secrets.token_bytes(32)
        revoked = set()
        issuer = HmacCredentialIssuer(user_key, issuer="test-host", audience="stm",
                                      clock=lambda: self.now)
        broker = HmacConversationBroker(
            user_key, issuer="test-host", audience="stm",
            token_from_request=lambda request: request.bearer,
            channel_binding_from_request=lambda request: request.trusted_transport_binding,
            is_revoked=lambda _i, _s, jti: jti in revoked,
            clock=lambda: self.now,
        )
        spec = ConversationCredentialSpec(
            subject="verified-owner", session=SessionKey("tenant", "owner", "vera", "chat"),
            conversation_id="chat", privacy_scopes=frozenset({"private"}),
            capabilities=frozenset({"archive_store", "archive_read"}),
            channel_binding="trusted-connection-44", max_working_ttl_seconds=30,
            archive_consent=True, archive_retention_seconds=30,
        )
        request = SyntheticAuthenticatedRequest(issuer.issue(spec, ttl_seconds=5),
                                                spec.channel_binding)
        grant = broker.resolve(request)

        def composed_authorizer(principal, action, scope):
            return (broker.authorize_archive(principal, action, scope)
                    or self.service.authorize_archive(principal, action, scope))

        with tempfile.TemporaryDirectory() as temp:
            with ConversationArchive(str(Path(temp) / "scoped.sqlite"),
                                     authorize=composed_authorizer) as archive:
                row = archive.append_turn(
                    grant.principal, self.scope, conversation_id="chat", role="user",
                    content="synthetic short-held private text", privacy="private",
                    expires_at=self.now + timedelta(seconds=4),
                )
                future = archive.append_turn(
                    grant.principal, self.scope, conversation_id="chat", role="user",
                    content="synthetic future private text", privacy="private",
                    expires_at=self.now + timedelta(days=1),
                )
                self.now += timedelta(seconds=6)
                self.assertFalse(broker.authorize_archive(grant.principal, "delete", self.scope))
                cleanup = self.service.acquire(self.key)
                self.assertEqual(archive.expire_due(
                    cleanup, self.scope, now=self.now,
                    privacy_scopes=frozenset({"private"}),
                ), 1)
                with self.assertRaises(PermissionError):
                    archive.delete(cleanup, self.scope, future.turn_id)
                with self.assertRaises(PermissionError):
                    archive.delete(cleanup, self.scope, row.turn_id)
                with self.assertRaises(PermissionError):
                    archive.search(cleanup, self.scope, "private",
                                   privacy_scopes=frozenset({"private"}))


if __name__ == "__main__":
    unittest.main()
