"""Windows identity policy tests (live Win32 pipe/SID still host-qualified)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ctypes
from ctypes import wintypes
import json
import os
import secrets
import threading
import time
import unittest

from stm import STM, SessionKey, VerifiedConversation
from stm.windows_host_auth import (
    PIPE_PREFIX, WindowsPeerMemoryGateway, authenticated_windows_sid,
)


class WindowsGatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.stm = STM()
        self.sid_a = "S-1-5-21-111-222-333-1001"
        self.sid_b = "S-1-5-21-111-222-333-1002"
        self.session_a = SessionKey("tenant", "owner-a", "vera", "session-a")
        self.session_b = SessionKey("tenant", "owner-b", "vera", "session-b")
        self.grant_a = self.grant(self.session_a)
        self.grant_b = self.grant(self.session_b)
        self.gateway = WindowsPeerMemoryGateway("unit-test", stm=self.stm,
                                               sid_grants={self.sid_a: self.grant_a,
                                                           self.sid_b: self.grant_b})

    @staticmethod
    def grant(session):
        return VerifiedConversation(
            principal=object(), session=session, conversation_id="host-conversation",
            privacy_scopes=frozenset({"private"}),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            max_working_ttl_seconds=120, archive_consent=False,
        )

    def call(self, sid, payload):
        # Simulates a result AFTER Win32 SID extraction; this private policy
        # method is not proof of actual Windows kernel authentication.
        return self.gateway._authenticated_dispatch(
            sid, json.dumps(payload).encode("utf-8"),
        )

    def test_source_stage_no_server_started(self):
        self.assertEqual(self.gateway.pipe_name, PIPE_PREFIX + "unit-test")
        if os.name != "nt":
            with self.assertRaises(RuntimeError):
                self.gateway.serve_once()
            with self.assertRaises(PermissionError):
                authenticated_windows_sid(23)

    def test_authenticated_sid_bound_working_roundtrip(self):
        result = self.call(self.sid_a, {"operation": "remember", "text": "cerulean fox"})
        self.assertEqual(result["status"], "STORED_WORKING_ONLY")
        context = self.call(self.sid_a, {"operation": "context", "query": "cerulean",
                                         "token_budget": 512})
        self.assertEqual(context["status"], "WORKING_CONTEXT")
        self.assertIn("cerulean fox", context["text"])
        self.assertLessEqual(context["token_count"], 512)

    def test_two_windows_accounts_are_strictly_isolated(self):
        self.call(self.sid_a, {"operation": "remember", "text": "scarlet pear secret"})
        self.call(self.sid_b, {"operation": "remember", "text": "cobalt banana secret"})
        result_a = self.call(self.sid_a, {"operation": "context", "query": "secret",
                                           "token_budget": 512})
        result_b = self.call(self.sid_b, {"operation": "context", "query": "secret",
                                           "token_budget": 512})
        self.assertIn("scarlet pear", result_a["text"])
        self.assertNotIn("cobalt banana", result_a["text"])
        self.assertIn("cobalt banana", result_b["text"])
        self.assertNotIn("scarlet pear", result_b["text"])

    def test_client_cannot_claim_sid_role_owner_or_archive(self):
        for request in (
            {"operation": "remember", "text": "injected", "sid": self.sid_b},
            {"operation": "remember", "text": "injected", "role": "assistant"},
            {"operation": "remember", "text": "injected", "owner": "owner-b"},
            {"operation": "remember", "text": "injected", "archive": True},
            {"operation": "archive", "text": "injected"},
            {"operation": "context", "query": "secret", "token_budget": 100,
             "owner": "owner-b"},
        ):
            with self.subTest(request=request):
                self.assertEqual(self.call(self.sid_a, request)["status"], "DENIED_OR_HELD")
        self.assertEqual(self.stm.store.list(self.session_a,
                         datetime.now(timezone.utc)), [])

    def test_unknown_sid_and_expired_grant_denied(self):
        request = {"operation": "remember", "text": "cannot store"}
        self.assertEqual(self.call("S-1-5-21-111-222-333-1999", request)["status"],
                         "DENIED_OR_HELD")
        self.gateway._sid_grants[self.sid_a] = replace(
            self.grant_a, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        self.assertEqual(self.call(self.sid_a, request)["status"], "DENIED_OR_HELD")
        self.assertEqual(self.stm.store.list(self.session_a,
                         datetime.now(timezone.utc)), [])

    def test_session_escapes_invalid_frames_budget_and_input_types(self):
        for raw in (b"", b"not JSON", b"[]", b"{" + b"z" * 4096, b"{\"operation\":\"context\"}"):
            self.assertEqual(self.gateway._authenticated_dispatch(self.sid_a, raw)["status"],
                             "DENIED_OR_HELD")
        for budget in (0, -1, 4097, 1.0, True, "200"):
            self.assertEqual(self.call(self.sid_a, {"operation": "context", "query": "hello",
                                                   "token_budget": budget})["status"],
                             "DENIED_OR_HELD")

    def test_invalid_pipe_suffix_sid_and_archive_policy_denied(self):
        for suffix in ("", "bad/path", "../../other", "a" * 81, "pipe\\hack"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                WindowsPeerMemoryGateway(suffix, stm=self.stm,
                                         sid_grants={self.sid_a: self.grant_a})
        for sid in ("BUILTIN\\Administrators", "Everyone", "s-1-5-21-1-2-3-1001", "S-1-5"):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                WindowsPeerMemoryGateway("valid", stm=self.stm,
                                         sid_grants={sid: self.grant_a})
        with self.assertRaises(PermissionError):
            WindowsPeerMemoryGateway("valid", stm=self.stm,
                                     sid_grants={self.sid_a: replace(
                                         self.grant_a, archive_consent=True,
                                         archive_retention_seconds=3600,
                                     )})

    def test_rejects_legacy_broad_session_label(self):
        shared = replace(self.grant_a, privacy_scopes=frozenset({"shared"}))
        bridge = WindowsPeerMemoryGateway("unique", stm=self.stm,
                                          sid_grants={self.sid_a: shared})
        self.assertEqual(bridge._authenticated_dispatch(
            self.sid_a, b'{"operation":"remember","text":"secret"}') ["status"],
            "DENIED_OR_HELD")


@unittest.skipUnless(os.name == "nt", "real Win32 named-pipe/token check requires Windows")
class NativeWindowsPipeTests(unittest.TestCase):
    """OS-backed attestation; Windows CI should execute, not silently skip."""

    @staticmethod
    def current_sid():
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                               ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_void_p)]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        token = wintypes.HANDLE()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                      ctypes.byref(token)):
            raise OSError("cannot read test process token")
        try:
            needed = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, 1, buf, needed,
                                             ctypes.byref(needed)):
                raise OSError("cannot retrieve test process SID")

            class SidAndAttributes(ctypes.Structure):
                _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

            sid_ptr = ctypes.cast(buf, ctypes.POINTER(SidAndAttributes)).contents.sid
            converted = ctypes.c_void_p()
            if not advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(converted)):
                raise OSError("cannot stringify test process SID")
            try:
                return ctypes.wstring_at(converted.value)
            finally:
                kernel.LocalFree(converted)
        finally:
            kernel.CloseHandle(token)

    def test_native_pipe_attests_account_and_roundtrips(self):
        sid = self.current_sid()
        grant = WindowsGatewayPolicyTests.grant(SessionKey(
            "windows-ci", "native-owner", "vera", "native-session"
        ))
        gateway = WindowsPeerMemoryGateway(
            "test-" + secrets.token_hex(8), stm=STM(), sid_grants={sid: grant},
        )
        result = {}

        def run_server():
            try:
                result["response"] = gateway.serve_once()
            except Exception as error:
                result["error"] = repr(error)

        server = threading.Thread(target=run_server, daemon=True)
        server.start()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                     ctypes.c_void_p]
        kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                    ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        pipe = None
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                pipe = kernel.CreateFileW(gateway.pipe_name, 0x00000003, 0,
                                          None, 3, 0, None)
                if pipe and pipe != ctypes.c_void_p(-1).value:
                    break
                time.sleep(0.02)
            else:
                self.fail(f"native pipe not connectable: {result}")
            sent = wintypes.DWORD()
            request = b'{"operation":"remember","text":"native windows test"}'
            message = ctypes.create_string_buffer(request)
            self.assertTrue(kernel.WriteFile(pipe, message, len(request),
                                             ctypes.byref(sent), None))
            self.assertEqual(sent.value, len(request))
            received = ctypes.create_string_buffer(8192)
            count = wintypes.DWORD()
            self.assertTrue(kernel.ReadFile(pipe, received, 8192,
                                            ctypes.byref(count), None))
            wire = json.loads(received.raw[:count.value])
            self.assertEqual(wire["status"], "STORED_WORKING_ONLY")
        finally:
            if pipe and pipe != ctypes.c_void_p(-1).value:
                kernel.CloseHandle(pipe)
        server.join(timeout=5)
        self.assertFalse(server.is_alive(), "Windows pipe server did not complete")
        self.assertNotIn("error", result, result.get("error"))
        self.assertEqual(result["response"]["status"], "STORED_WORKING_ONLY")


if __name__ == "__main__":
    unittest.main()
