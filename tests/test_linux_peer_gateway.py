"""Actual AF_UNIX/SO_PEERCRED roundtrips, no live Vera endpoint."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import errno
import os
from pathlib import Path
import socket
import stat
import threading
from tempfile import TemporaryDirectory
import unittest

from stm import STM, SessionKey, VerifiedConversation

from stm.linux_peer_gateway import PeerMemoryGateway, authenticated_linux_peer


@unittest.skipUnless(os.name == "posix" and hasattr(socket, "SO_PEERCRED"),
                     "Linux kernel peer credentials required")
class PeerGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.socket_path = Path(self.temp.name) / "memory.sock"
        self.uid = os.getuid()
        self.stm = STM()
        self.principal = object()
        self.key = SessionKey("local", "verified-owner", "vera", "host-session")
        self.grant = VerifiedConversation(
            principal=self.principal, session=self.key,
            conversation_id="host-conversation",
            privacy_scopes=frozenset({"private"}),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120,
            archive_consent=False,
        )
        self.gateway = PeerMemoryGateway(
            self.socket_path, stm=self.stm, uid_grants={self.uid: self.grant},
        )
        try:
            self.server = self.gateway.create_server()
        except PermissionError as error:
            # The managed workspace sandbox denies AF_UNIX bind even for
            # owner-only scratch sockets. CI explicitly REQUIRES the socket
            # checks, and the integration run is separately executed outside
            # that sandbox. Do not hide EPERM on a qualifying host.
            if (error.errno == errno.EPERM
                    and os.environ.get("STM_REQUIRE_PEER_SOCKET_TESTS") != "1"):
                self.skipTest("AF_UNIX bind prohibited by execution sandbox")
            raise
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.gateway.close()
        self.temp.cleanup()

    def call(self, payload: dict):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket_path))
            conn.sendall(json.dumps(payload).encode() + b"\n")
            with conn.makefile("rb") as response:
                return json.loads(response.readline())

    def test_kernel_credential_and_socket_privacy(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket_path))
            # This exercises the kernel credential primitive with a real socket.
            self.assertEqual(authenticated_linux_peer(conn).uid, self.uid)
        mode = stat.S_IMODE(os.lstat(self.socket_path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_authenticated_working_memory_and_context_not_archive(self):
        saved = self.call({"operation": "remember", "text": "Synthetic copper lantern on stairs"})
        self.assertEqual(saved["status"], "STORED_WORKING_ONLY")
        context = self.call({"operation": "context", "query": "copper lantern",
                             "token_budget": 1024})
        self.assertEqual(context["status"], "WORKING_CONTEXT")
        self.assertIn("copper lantern", context["text"])
        self.assertLessEqual(context["token_count"], 1024)
        # The working session contains the synthetic observation; this
        # transport does not attach or create an archive.
        session = self.stm.open_session(
            tenant_id=self.key.tenant_id, owner_id=self.key.owner_id,
            agent_id=self.key.agent_id, session_id=self.key.session_id,
        )
        self.assertEqual(len(session.retrieve("copper lantern")), 1)

    def test_request_cannot_claim_identity_or_role(self):
        for payload in (
            {"operation": "remember", "text": "hello", "owner_id": "someone-else"},
            {"operation": "remember", "text": "hello", "uid": self.uid},
            {"operation": "remember", "text": "hello", "role": "assistant"},
            {"operation": "remember", "text": "hello", "archive": True},
            {"operation": "archive", "text": "hello"},
            {"operation": "context", "query": "hello", "token_budget": 400,
             "conversation_id": "other-person"},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.call(payload)["status"], "DENIED_OR_HELD")
        self.assertEqual(self.stm.store.list(self.key, datetime.now(timezone.utc)), [])

    def test_non_authorized_kernel_uid_denied(self):
        self.gateway._uid_grants.clear()
        self.assertEqual(self.call({"operation": "remember", "text": "should deny"})["status"],
                         "DENIED_OR_HELD")

    def test_expired_grant_denied(self):
        self.gateway._uid_grants[self.uid] = replace(
            self.grant, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        self.assertEqual(self.call({"operation": "remember", "text": "expired"})["status"],
                         "DENIED_OR_HELD")

    def test_existing_socket_or_bad_parent_denied(self):
        with self.assertRaises(FileExistsError):
            PeerMemoryGateway(self.socket_path, stm=self.stm,
                              uid_grants={self.uid: self.grant})
        directory = Path(self.temp.name) / "unsafe"
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o777)
        try:
            with self.assertRaises(PermissionError):
                PeerMemoryGateway(directory / "s.sock", stm=self.stm,
                                  uid_grants={self.uid: self.grant})
        finally:
            os.chmod(directory, 0o700)

    def test_archive_policy_cannot_be_smuggled_via_host_grant(self):
        with self.assertRaises(PermissionError):
            PeerMemoryGateway(Path(self.temp.name) / "other.sock", stm=self.stm,
                              uid_grants={self.uid: replace(self.grant,
                                  archive_consent=True, archive_retention_seconds=3600)})


if __name__ == "__main__":
    unittest.main()
