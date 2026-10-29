"""Linux AF_UNIX peer-authenticated STM gateway prototype.

This is an isolated, non-deployed source prototype. The existing VeraOS HTTP
endpoint is NOT authenticated and is not used. No server process starts on
import. The embedding operator must map approved Linux UIDs to actual owners,
choose per-owner scopes and a private filesystem location, and separately
provide any persisted conversation-retention consent policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
from threading import Lock
from typing import Mapping

from stm import STM, VeraConversationBridge, VerifiedConversation


MAX_REQUEST_BYTES = 4096
MAX_CONTEXT_BUDGET = 4096
PEER_CRED_FORMAT = "3i"


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int


def authenticated_linux_peer(conn: socket.socket) -> PeerIdentity:
    """Read kernel-issued UNIX socket credentials, not protocol metadata.

    The kernel's SO_PEERCRED identifies the connecting process at connect
    time; it does not authenticate a human nor distinguish processes sharing
    one Linux UID. Unsupported platforms deliberately fail closed.
    """
    if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
        raise PermissionError("Linux SO_PEERCRED is required")
    if conn.family != socket.AF_UNIX:
        raise PermissionError("authenticated peer must use AF_UNIX")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                          struct.calcsize(PEER_CRED_FORMAT))
    pid, uid, gid = struct.unpack(PEER_CRED_FORMAT, raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PermissionError("invalid kernel peer identity")
    return PeerIdentity(pid, uid, gid)


class PeerMemoryGateway:
    """A bound, fail-closed UNIX transport; no bearer or browser auth claim.

    ``uid_grants`` is an operator-authorized mapping of *kernel UIDs* to
    immutable, expiring STM scopes. A process may never submit its own owner,
    agent, session, privacy grant, message role, or archiving consent.
    Only working-memory writes and context assembly are exposed here.
    """

    def __init__(self, socket_path: str | Path, *, stm: STM,
                 uid_grants: Mapping[int, VerifiedConversation]) -> None:
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("this gateway needs Linux peer credentials")
        if not isinstance(stm, STM) or not uid_grants:
            raise ValueError("STM and explicitly authorized UID mapping required")
        grants: dict[int, VerifiedConversation] = {}
        for uid, grant in uid_grants.items():
            if type(uid) is not int or uid < 0 or not isinstance(grant, VerifiedConversation):
                raise ValueError("invalid authorized UID grant")
            if grant.archive_consent or grant.archive_retention_seconds is not None:
                raise PermissionError("this working-memory transport has no archive grant")
            grants[uid] = grant
        self._uid_grants = grants
        self._handles: dict[object, VerifiedConversation] = {}
        self._lock = Lock()
        self._socket_path = Path(socket_path)
        self._validate_socket_parent()
        self._bridge = VeraConversationBridge(
            stm, resolve=self._resolve, authorize=self._authorize,
            archive=None, retention_gate=None,
        )
        self._server: socketserver.UnixStreamServer | None = None
        self._created_inode: tuple[int, int] | None = None

    def _validate_socket_parent(self) -> None:
        path = self._socket_path
        if not path.is_absolute():
            raise ValueError("socket must have an absolute path")
        parent = os.lstat(path.parent)
        if (not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o077):
            raise PermissionError("socket directory must be owned and private (0700)")
        if os.path.lexists(path):
            raise FileExistsError("refusing to replace an existing socket/path")

    def _resolve(self, handle: object) -> VerifiedConversation:
        with self._lock:
            grant = self._handles.get(handle)
        if grant is None:
            raise PermissionError("unissued broker handle")
        return grant

    @staticmethod
    def _authorize(grant: VerifiedConversation, operation: str, label: str) -> bool:
        # The trust boundary is fixed: this transport only writes as 'user'.
        # Working context now filters privacy labels before packing, so a
        # private-only UID grant never requires broader label authority.
        return (operation in {"working_write:user", "working_context"}
                and label in grant.privacy_scopes)

    def _dispatch(self, conn: socket.socket, raw: bytes) -> dict[str, object]:
        try:
            peer = authenticated_linux_peer(conn)
            grant = self._uid_grants.get(peer.uid)
            if grant is None:
                raise PermissionError("UID not authorized")
            now = datetime.now(timezone.utc)
            if now >= grant.expires_at:
                raise PermissionError("UID capability expired")
            request = json.loads(raw)
            if type(request) is not dict:
                raise ValueError("JSON object required")
            handle = object()
            with self._lock:
                self._handles[handle] = grant
            try:
                if set(request) == {"operation", "text"} and request["operation"] == "remember":
                    text = request["text"]
                    if type(text) is not str or not 0 < len(text) <= 2048:
                        raise ValueError("invalid text")
                    record = self._bridge.remember(handle, text, role="user", privacy="private")
                    return {"status": "STORED_WORKING_ONLY", "record_id": record.id}
                if (set(request) == {"operation", "query", "token_budget"}
                        and request["operation"] == "context"):
                    query = request["query"]
                    budget = request["token_budget"]
                    if type(query) is not str or not query.strip() or len(query) > 2048:
                        raise ValueError("invalid query")
                    if type(budget) is not int or not 1 <= budget <= MAX_CONTEXT_BUDGET:
                        raise ValueError("invalid budget")
                    packed = self._bridge.working_context(
                        handle, query, privacy="private", token_budget=budget,
                    )
                    return {"status": "WORKING_CONTEXT", "text": packed.text,
                            "budget": packed.token_budget, "token_count": packed.token_count}
                raise PermissionError("operation not allowed")
            finally:
                with self._lock:
                    self._handles.pop(handle, None)
        except (ValueError, PermissionError, RuntimeError, TypeError, KeyError):
            return {"status": "DENIED_OR_HELD"}
        except Exception:
            return {"status": "UNKNOWN"}

    def create_server(self) -> socketserver.UnixStreamServer:
        if self._server is not None:
            raise RuntimeError("gateway already bound")
        self._validate_socket_parent()
        gateway = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(3.0)
                raw = self.rfile.readline(MAX_REQUEST_BYTES + 2)
                if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                    result: dict[str, object] = {"status": "DENIED_OR_HELD"}
                else:
                    result = gateway._dispatch(self.request, raw)
                self.wfile.write(json.dumps(result, sort_keys=True).encode() + b"\n")

            def finish(self) -> None:
                try:
                    super().finish()
                except OSError:
                    pass

        # Deliberately serialized transport: bounded one-request processing,
        # no attacker-controlled unbounded thread fan-out or connection cache.
        class BoundedServer(socketserver.UnixStreamServer):
            request_queue_size = 8

        server = BoundedServer(str(self._socket_path), Handler)
        os.chmod(self._socket_path, 0o600)
        info = os.lstat(self._socket_path)
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            server.server_close()
            raise PermissionError("socket mode unsafe")
        self._created_inode = (info.st_dev, info.st_ino)
        self._server = server
        return server

    def close(self) -> None:
        server = self._server
        if server is not None:
            server.server_close()
            self._server = None
        if self._created_inode is not None:
            try:
                info = os.lstat(self._socket_path)
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self._created_inode:
                    os.unlink(self._socket_path)
            self._created_inode = None


__all__ = ["PeerIdentity", "authenticated_linux_peer", "PeerMemoryGateway"]
