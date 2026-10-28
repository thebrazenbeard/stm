"""Android UID/installed-package binding negative and working-memory tests.

The app identity provider is synthetic here. No Android PackageManager, APK,
SELinux policy or Vera Android runtime is installed or qualified by this suite.
"""

from __future__ import annotations

from dataclasses import replace
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import struct
from tempfile import TemporaryDirectory
import unittest

from stm import STM, SessionKey, VerifiedConversation
from stm.android_local_auth import (
    AndroidAppIdentity, AndroidAppRegistration, AndroidAppPeerGateway,
    verify_android_binding,
)


UID = 10_123
GOOD_DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


class SyntheticPeerSocket:
    """Minimal transport double: tests policy after synthetic kernel identity."""

    family = socket.AF_UNIX

    def __init__(self, uid=UID):
        self.uid = uid

    def getsockopt(self, level, option, length):
        assert level == socket.SOL_SOCKET and option == socket.SO_PEERCRED
        return struct.pack("3i", 123, self.uid, self.uid)


@unittest.skipUnless(os.name == "posix" and hasattr(socket, "SO_PEERCRED"),
                     "Linux SO_PEERCRED required")
class AndroidAppAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stm = STM()
        self.identity = AndroidAppIdentity(
            uid=UID, android_user_id=0,
            packages=("org.vera.conversation",),
            signing_cert_sha256=GOOD_DIGEST,
        )
        self.session = SessionKey("local", "owner", "vera", "chat")
        self.grant = VerifiedConversation(
            principal=object(), session=self.session, conversation_id="conversation",
            privacy_scopes=frozenset({"private"}),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120,
            archive_consent=False,
        )
        self.registration = AndroidAppRegistration(self.identity, self.grant)
        self.current = self.identity
        self.gateway = self.make_gateway()

    def make_gateway(self, registrations=None, resolver=None):
        return AndroidAppPeerGateway(
            str(Path(self.temp.name) / "memory.sock"), stm=self.stm,
            app_registrations=registrations if registrations is not None
            else {UID: self.registration},
            resolve_installed_app=resolver if resolver is not None
            else lambda uid: self.current,
        )

    def call(self, operation):
        return self.gateway._dispatch(SyntheticPeerSocket(), json.dumps(operation).encode())

    def test_authorized_app_can_write_working_memory_and_get_private_context(self):
        saved = self.call({"operation": "remember", "text": "Synthetic amber light"})
        self.assertEqual(saved["status"], "STORED_WORKING_ONLY")
        retrieved = self.call({"operation": "context", "query": "amber", "token_budget": 256})
        self.assertEqual(retrieved["status"], "WORKING_CONTEXT")
        self.assertIn("amber", retrieved["text"])
        self.assertLessEqual(retrieved["token_count"], 256)

    def test_caller_cannot_claim_another_uid_identity_role_or_archive_grant(self):
        for payload in (
            {"operation": "remember", "text": "x", "uid": UID},
            {"operation": "remember", "text": "x", "package": "org.vera.conversation"},
            {"operation": "remember", "text": "x", "role": "assistant"},
            {"operation": "remember", "text": "x", "owner_id": "other"},
            {"operation": "remember", "text": "x", "archive_consent": True},
            {"operation": "archive", "text": "x"},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.call(payload)["status"], "DENIED_OR_HELD")

    def test_package_reassignment_signature_change_and_profile_change_fail_closed(self):
        for changed in (
            None,
            replace(self.identity, signing_cert_sha256=OTHER_DIGEST),
            replace(self.identity, packages=("org.attacker.fake",)),
            replace(self.identity, packages=("org.vera.conversation", "org.shared.app")),
            replace(self.identity, android_user_id=10),
            replace(self.identity, uid=UID + 1),
        ):
            with self.subTest(changed=changed):
                self.current = changed
                self.assertEqual(
                    self.call({"operation": "remember", "text": "denied"})["status"],
                    "DENIED_OR_HELD",
                )
        self.assertEqual(self.stm.store.list(self.session, datetime.now(timezone.utc)), [])

    def test_unregistered_kernel_uid_is_denied_even_with_matching_request_fields(self):
        raw = json.dumps({"operation": "remember", "text": "no access", "uid": UID}).encode()
        self.assertEqual(self.gateway._dispatch(SyntheticPeerSocket(UID + 1), raw)["status"],
                         "DENIED_OR_HELD")

    def test_provider_failure_and_revocation_block_new_writes(self):
        broken = self.make_gateway(resolver=lambda uid: (_ for _ in ()).throw(RuntimeError()))
        self.assertEqual(broken._dispatch(SyntheticPeerSocket(), b'{"operation":"remember","text":"x"}')
                         ["status"], "DENIED_OR_HELD")
        self.assertTrue(self.gateway.revoke_app(UID))
        self.assertFalse(self.gateway.revoke_app(UID))
        self.assertEqual(self.call({"operation": "remember", "text": "x"})["status"],
                         "DENIED_OR_HELD")

    def test_expired_grant_denied(self):
        expired = replace(self.grant,
                          expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.gateway = self.make_gateway(registrations={
            UID: AndroidAppRegistration(self.identity, expired),
        })
        self.assertEqual(self.call({"operation": "remember", "text": "x"})["status"],
                         "DENIED_OR_HELD")

    def test_reject_bad_registration_and_archive_grant(self):
        invalid = (
            replace(self.identity, uid=9999),
            replace(self.identity, packages=()),
            replace(self.identity, packages=("org.vera.conversation", "org.vera.other")),
            replace(self.identity, signing_cert_sha256="not-a-digest"),
            replace(self.identity, android_user_id=-1),
        )
        for item in invalid:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    self.make_gateway(registrations={item.uid: AndroidAppRegistration(
                        item, self.grant)})
        with self.assertRaises(PermissionError):
            self.make_gateway(registrations={UID: AndroidAppRegistration(
                self.identity, replace(self.grant, archive_consent=True,
                                       archive_retention_seconds=3600))})
        with self.assertRaises(ValueError):
            self.make_gateway(resolver=object())

    def test_policy_match_is_strict(self):
        self.assertTrue(verify_android_binding(UID, self.registration, self.identity))
        self.assertFalse(verify_android_binding(True, self.registration, self.identity))
        self.assertFalse(verify_android_binding(UID, self.registration, None))
        self.assertFalse(verify_android_binding(UID, self.registration,
                                                replace(self.identity, signing_cert_sha256="A" * 64)))

    def test_actual_linux_socket_kernel_credential_rejected_without_android_binding(self):
        # Not Android runtime qualification: the host's real kernel UID is
        # deliberately not registered as the synthetic UID.
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with closing(client), closing(server):
            identity = self.gateway._dispatch(
                server, b'{"operation":"remember","text":"x"}'
            )
        if os.getuid() != UID:
            self.assertEqual(identity["status"], "DENIED_OR_HELD")


if __name__ == "__main__":
    unittest.main()
