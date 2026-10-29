"""Optional Windows named-pipe peer-authenticated working-memory gateway.

This is source-stage Windows integration, not a deployed VeraOS endpoint.
Only a server-owned named-pipe handle, AFTER a message was read from it, may
be passed to :func:`authenticated_windows_sid`. Identity comes from the
Windows client impersonation token, not request JSON, process ID, HTTP Host,
Origin, or a caller-supplied SID. A Windows account SID identifies an OS
account, not an individual human in a shared login.

The gateway is deliberately working-memory only: its host-approved SID map
never delegates archive reads/writes, retention consent or long-term export.
The host must supervise its blocking ``serve_once`` method, rotate session
grants and separately authorize any persistence or deep-memory handoff.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import os
import re
from threading import RLock
import time
from typing import Mapping

from .core import STM
from .vera_bridge import VerifiedConversation, VeraConversationBridge


MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 8192
MAX_CONTEXT_BUDGET = 4096
_SID = re.compile(r"^S-1(?:-[0-9]{1,12}){2,15}$", re.ASCII)
_PIPE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$", re.ASCII)

# Windows names must be local and fixed by the trusted host. No client-provided
# \"pipe name\" is ever used. A prefixed single-instance pipe prevents an
# attacker from pre-creating another instance of the same name.
PIPE_PREFIX = "\\\\.\\pipe\\VeraSTM-"


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


def _api():
    if os.name != "nt":
        raise PermissionError("Windows desktop named-pipe authentication required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    h = wintypes.HANDLE
    d = wintypes.DWORD
    p = ctypes.c_void_p
    functions = (
        (kernel.CreateNamedPipeW, [wintypes.LPCWSTR, d, d, d, d, d, d,
                                   ctypes.POINTER(_SecurityAttributes)], h),
        (kernel.ConnectNamedPipe, [h, p], wintypes.BOOL),
        (kernel.PeekNamedPipe, [h, p, d, p, ctypes.POINTER(d), p], wintypes.BOOL),
        (kernel.ReadFile, [h, p, d, ctypes.POINTER(d), p], wintypes.BOOL),
        (kernel.WriteFile, [h, p, d, ctypes.POINTER(d), p], wintypes.BOOL),
        (kernel.DisconnectNamedPipe, [h], wintypes.BOOL),
        (kernel.CloseHandle, [h], wintypes.BOOL),
        (kernel.GetCurrentThread, [], h),
        (kernel.LocalFree, [p], p),
        (advapi.ImpersonateNamedPipeClient, [h], wintypes.BOOL),
        (advapi.RevertToSelf, [], wintypes.BOOL),
        (advapi.OpenThreadToken, [h, d, wintypes.BOOL, ctypes.POINTER(h)], wintypes.BOOL),
        (advapi.GetTokenInformation, [h, d, p, d, ctypes.POINTER(d)], wintypes.BOOL),
        (advapi.ConvertSidToStringSidW, [p, ctypes.POINTER(p)], wintypes.BOOL),
        (advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW,
         [wintypes.LPCWSTR, d, ctypes.POINTER(p), p], wintypes.BOOL),
    )
    for fn, args, result in functions:
        fn.argtypes = args
        fn.restype = result
    return kernel, advapi


def _error(operation: str) -> OSError:
    return OSError(ctypes.get_last_error(), f"Windows {operation} failed")


def authenticated_windows_sid(server_pipe_handle: int) -> str:
    """Retrieve client TOKEN_USER SID from a *read* server named-pipe handle.

    Call only on the same thread that called ``ReadFile`` on this connected
    instance, before any other read. ``ImpersonateNamedPipeClient`` attaches
    the token of the last message read. On failure no client work is done.
    Reverting is mandatory. If Windows refuses to revert, immediately stop
    the process to prevent subsequent privileged work under another identity.
    """
    if os.name != "nt":
        raise PermissionError("Windows impersonation unavailable")
    if type(server_pipe_handle) is not int or server_pipe_handle <= 0:
        raise PermissionError("server-owned pipe handle required")
    kernel, advapi = _api()
    handle = wintypes.HANDLE(server_pipe_handle)
    if not advapi.ImpersonateNamedPipeClient(handle):
        raise PermissionError("Windows pipe client impersonation denied")
    token = wintypes.HANDLE()
    sid_buffer = ctypes.c_void_p()
    try:
        # OpenAsSelf=TRUE permits querying an identification-level token.
        if not advapi.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True,
                                     ctypes.byref(token)):
            raise PermissionError("Windows client token query denied")
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not 16 <= required.value <= 65536:
            raise PermissionError("invalid Windows token buffer size")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(token, 1, buffer, required,
                                         ctypes.byref(required)):
            raise PermissionError("Windows client token information unavailable")
        sid_address = ctypes.cast(buffer, ctypes.POINTER(_SidAndAttributes)).contents.sid
        if not sid_address or not advapi.ConvertSidToStringSidW(
                sid_address, ctypes.byref(sid_buffer)):
            raise PermissionError("Windows client SID unavailable")
        sid = ctypes.wstring_at(sid_buffer.value)
        if not _SID.fullmatch(sid):
            raise PermissionError("Windows client SID not canonical")
        return sid
    finally:
        if sid_buffer.value:
            kernel.LocalFree(sid_buffer)
        if token.value:
            kernel.CloseHandle(token)
        if not advapi.RevertToSelf():
            # Official Win32 guidance: do not continue execution with a
            # failed revert. It can preserve another account's privileges.
            os._exit(72)


class WindowsPeerMemoryGateway:
    """Single-client-at-a-time, ACLed local Windows named-pipe STM host.

    ``sid_grants`` is **operator-established**: no request may select its own
    SID, scope, agent, role, TTL, or archive consent. Host-approved account
    SIDs must remain unique and unambiguously mapped to scoped sessions.
    This is not suitable for browsers until the VeraOS browser/auth bridge
    has an independently verified user-to-SID binding.
    """

    def __init__(self, pipe_suffix: str, *, stm: STM,
                 sid_grants: Mapping[str, VerifiedConversation]) -> None:
        if not isinstance(pipe_suffix, str) or not _PIPE_NAME.fullmatch(pipe_suffix):
            raise ValueError("host-defined bounded pipe suffix required")
        if not isinstance(stm, STM) or not sid_grants:
            raise ValueError("STM and host-approved account grants required")
        approved = {}
        for sid, grant in sid_grants.items():
            if not isinstance(sid, str) or not _SID.fullmatch(sid):
                raise ValueError("canonical Windows account SID required")
            if not isinstance(grant, VerifiedConversation):
                raise ValueError("verified host conversation grant required")
            if grant.archive_consent or grant.archive_retention_seconds is not None:
                raise PermissionError("working pipe cannot carry archive authority")
            approved[sid] = grant
        self.pipe_name = PIPE_PREFIX + pipe_suffix
        self._sid_grants = approved
        self._handle_grants: dict[object, VerifiedConversation] = {}
        self._lock = RLock()
        self._bridge = VeraConversationBridge(
            stm, resolve=self._resolve, authorize=self._authorize,
            archive=None, retention_gate=None,
        )

    def _resolve(self, handle: object) -> VerifiedConversation:
        with self._lock:
            result = self._handle_grants.get(handle)
        if result is None:
            raise PermissionError("unissued Windows request handle")
        return result

    @staticmethod
    def _authorize(grant: VerifiedConversation, operation: str, label: str) -> bool:
        return (operation in {"working_write:user", "working_context"}
                and label == "private" and label in grant.privacy_scopes)

    def _authenticated_dispatch(self, sid: str, raw: bytes) -> dict[str, object]:
        """For connected *native-authenticated* SID only. Not a network API."""
        try:
            grant = self._sid_grants.get(sid)
            if grant is None or datetime.now(timezone.utc) >= grant.expires_at:
                raise PermissionError("OS identity not currently authorized")
            if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
                raise ValueError("bounded JSON frame required")
            request = json.loads(raw)
            if type(request) is not dict:
                raise ValueError("JSON object required")
            handle = object()
            with self._lock:
                self._handle_grants[handle] = grant
            try:
                if set(request) == {"operation", "text"} and request["operation"] == "remember":
                    content = request["text"]
                    if type(content) is not str or not 0 < len(content) <= 2048:
                        raise ValueError("invalid bounded text")
                    record = self._bridge.remember(handle, content, role="user", privacy="private")
                    return {"status": "STORED_WORKING_ONLY", "record_id": record.id}
                if (set(request) == {"operation", "query", "token_budget"}
                        and request["operation"] == "context"):
                    query, budget = request["query"], request["token_budget"]
                    if type(query) is not str or not query.strip() or len(query) > 2048:
                        raise ValueError("invalid query")
                    if type(budget) is not int or not 1 <= budget <= MAX_CONTEXT_BUDGET:
                        raise ValueError("invalid token budget")
                    context = self._bridge.working_context(
                        handle, query, privacy="private", token_budget=budget,
                    )
                    return {"status": "WORKING_CONTEXT", "text": context.text,
                            "token_count": context.token_count,
                            "budget": context.token_budget}
                raise PermissionError("operation not allowed")
            finally:
                with self._lock:
                    self._handle_grants.pop(handle, None)
        except (PermissionError, ValueError, TypeError, KeyError, RuntimeError):
            return {"status": "DENIED_OR_HELD"}
        except Exception:
            return {"status": "UNKNOWN"}

    def serve_once(self, *, frame_timeout_seconds: float = 3.0) -> dict[str, object]:
        """Serve one verified Windows pipe message; blocks awaiting a client.

        The 3-second frame bound begins *after* the client connects. The
        caller owns cancellation and process supervision while waiting for a
        connection. No implicit daemon or network listener starts on import.
        """
        if os.name != "nt":
            raise RuntimeError("Windows named-pipe server required")
        if (type(frame_timeout_seconds) not in (int, float)
                or not 0.1 <= frame_timeout_seconds <= 10):
            raise ValueError("frame timeout must be 0.1..10 seconds")
        kernel, advapi = _api()
        # Full-control rights only for SYSTEM. Authorized client accounts
        # receive read-data/write-data/attributes/read-control/synchronize,
        # but NOT FILE_CREATE_PIPE_INSTANCE (0x0004).
        acl = "D:P(A;;GA;;;SY)" + "".join(
            f"(A;;0x00120083;;;{sid})" for sid in sorted(self._sid_grants)
        )
        descriptor = ctypes.c_void_p()
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                acl, 1, ctypes.byref(descriptor), None):
            raise _error("security descriptor creation")
        attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        pipe = None
        try:
            # PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
            # PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
            # PIPE_REJECT_REMOTE_CLIENTS, one instance max.
            created = kernel.CreateNamedPipeW(
                self.pipe_name, 0x00080003, 0x0000000E, 1,
                MAX_RESPONSE_BYTES, MAX_REQUEST_BYTES, 3000, ctypes.byref(attrs),
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if not created or created == invalid_handle:
                raise _error("pipe creation")
            pipe = created
            if not kernel.ConnectNamedPipe(pipe, None) and ctypes.get_last_error() != 535:
                raise _error("pipe connection")
            until = time.monotonic() + frame_timeout_seconds
            raw = b""
            while time.monotonic() < until:
                ready = wintypes.DWORD()
                if not kernel.PeekNamedPipe(pipe, None, 0, None,
                                            ctypes.byref(ready), None):
                    raise PermissionError("pipe disconnected before message")
                if ready.value:
                    if ready.value > MAX_REQUEST_BYTES:
                        raise PermissionError("request exceeds frame ceiling")
                    buffer = ctypes.create_string_buffer(MAX_REQUEST_BYTES + 1)
                    got = wintypes.DWORD()
                    if not kernel.ReadFile(pipe, buffer, MAX_REQUEST_BYTES + 1,
                                           ctypes.byref(got), None):
                        raise PermissionError("incomplete pipe message")
                    raw = buffer.raw[:got.value]
                    break
                time.sleep(0.01)
            if not raw:
                raise PermissionError("no complete message before timeout")
            # The SID is read from the last pipe message's OS token, never
            # from JSON fields, and no client work precedes this check.
            sid = authenticated_windows_sid(int(pipe))
            result = self._authenticated_dispatch(sid, raw)
        except (PermissionError, ValueError, TypeError, RuntimeError, OSError):
            result = {"status": "DENIED_OR_HELD"}
        finally:
            if descriptor.value:
                kernel.LocalFree(descriptor)
        if pipe is not None:
            response = json.dumps(result, separators=(",", ":")).encode("utf-8")
            if len(response) <= MAX_RESPONSE_BYTES:
                try:
                    buffer = ctypes.create_string_buffer(response)
                    sent = wintypes.DWORD()
                    kernel.WriteFile(pipe, buffer, len(response), ctypes.byref(sent), None)
                finally:
                    kernel.DisconnectNamedPipe(pipe)
                    kernel.CloseHandle(pipe)
            else:
                kernel.DisconnectNamedPipe(pipe)
                kernel.CloseHandle(pipe)
        return result


__all__ = ["authenticated_windows_sid", "WindowsPeerMemoryGateway"]
