"""Opt-in Android app UID binding for STM's Linux AF_UNIX peer gateway.

This is a source-level adapter, *not* an Android application or a claim that
Vera's Android interface is authenticated. The trusted host supplies a fresh
PackageManager-backed resolver; STM independently reads the peer UID from the
kernel via SO_PEERCRED. A payload cannot name an app, owner, or permission.

Android UID ownership may change on reinstall, and a UID can belong to more
than one package. The resolver must inspect the installed package set, signing
certificate(s), and Android user profile through the platform's privileged
PackageManager APIs. No generic Python library can attest that information
without a host bridge. Missing, stale, or ambiguous evidence fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import socket
from typing import Callable, Mapping

from . import STM, VerifiedConversation
from .linux_peer_gateway import PeerMemoryGateway, authenticated_linux_peer


_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class AndroidAppIdentity:
    """Current installed-app evidence supplied by a privileged host bridge.

    It is *not* itself cryptographic attestation. A caller-provided resolver is
    trusted only when wired to Android PackageManager, not to request JSON.
    ``packages`` is the full PackageManager.getPackagesForUid result, not an
    arbitrary selected package. Shared UIDs are intentionally unsupported.
    """

    uid: int
    android_user_id: int
    packages: tuple[str, ...]
    signing_cert_sha256: str


@dataclass(frozen=True, slots=True)
class AndroidAppRegistration:
    """Operator-approved app identity tied to an existing STM conversation.

    Registrations are device-specific because Android app UIDs are not global.
    A user-profile and signing certificate digest are mandatory. Revoking the
    host registration prevents subsequent requests from being authorized.
    """

    identity: AndroidAppIdentity
    conversation: VerifiedConversation


def _valid_app_identity(identity: AndroidAppIdentity) -> bool:
    return (
        isinstance(identity, AndroidAppIdentity)
        and type(identity.uid) is int and identity.uid >= 10_000
        and type(identity.android_user_id) is int and identity.android_user_id >= 0
        and type(identity.packages) is tuple and len(identity.packages) == 1
        and type(identity.packages[0]) is str
        and _PACKAGE.fullmatch(identity.packages[0]) is not None
        and type(identity.signing_cert_sha256) is str
        and _DIGEST.fullmatch(identity.signing_cert_sha256) is not None
    )


def verify_android_binding(
    kernel_uid: int,
    registration: AndroidAppRegistration,
    live_identity: AndroidAppIdentity | None,
) -> bool:
    """Match kernel UID to current package, cert and Android user profile.

    ``kernel_uid`` must originate from SO_PEERCRED. This function does not
    authenticate the provider used to obtain ``live_identity``.
    """
    if (type(kernel_uid) is not int
            or not isinstance(registration, AndroidAppRegistration)
            or not _valid_app_identity(registration.identity)
            or not _valid_app_identity(live_identity)):
        return False
    return registration.identity.uid == kernel_uid and live_identity == registration.identity


class AndroidAppPeerGateway(PeerMemoryGateway):
    """Working-memory only, owner-bound Unix socket for Android app processes.

    The operator must provide a trusted ``resolve_installed_app(uid)`` that
    reads *fresh* Android PackageManager state, including the complete package
    set and current signing certificate. No cached or client-supplied identity
    may be used; the callable is invoked for every accepted socket request.

    Host config must give the serving process permission to create a private
    AF_UNIX socket. Android SELinux policy, app permissions, and actual Vera
    application wiring are separately required and are not tested here.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        stm: STM,
        app_registrations: Mapping[int, AndroidAppRegistration],
        resolve_installed_app: Callable[[int], AndroidAppIdentity | None],
    ) -> None:
        if not callable(resolve_installed_app):
            raise ValueError("trusted Android PackageManager resolver required")
        if not app_registrations:
            raise ValueError("explicit app registrations required")
        registrations: dict[int, AndroidAppRegistration] = {}
        for uid, registration in app_registrations.items():
            if (type(uid) is not int
                    or not isinstance(registration, AndroidAppRegistration)
                    or not isinstance(registration.conversation, VerifiedConversation)
                    or not _valid_app_identity(registration.identity)
                    or uid != registration.identity.uid):
                raise ValueError("invalid Android app registration")
            registrations[uid] = registration
        super().__init__(
            socket_path, stm=stm,
            uid_grants={uid: reg.conversation for uid, reg in registrations.items()},
        )
        self._android_registrations = registrations
        self._resolve_installed_app = resolve_installed_app

    def revoke_app(self, uid: int) -> bool:
        """Revoke future access; host must also retire stale authorization."""
        with self._lock:
            removed = self._android_registrations.pop(uid, None)
            self._uid_grants.pop(uid, None)
        return removed is not None

    def _dispatch(self, conn: socket.socket, raw: bytes) -> dict[str, object]:
        try:
            # Never trust request JSON for these values. SO_PEERCRED returns a
            # kernel-side process identity for the connected Unix socket.
            peer = authenticated_linux_peer(conn)
            with self._lock:
                registration = self._android_registrations.get(peer.uid)
            if registration is None:
                raise PermissionError("app UID is not registered")
            live_identity = self._resolve_installed_app(peer.uid)
            if not verify_android_binding(peer.uid, registration, live_identity):
                raise PermissionError("installed app identity changed or is ambiguous")
            return super()._dispatch(conn, raw)
        except Exception:
            # Coarse denial avoids exposing UID, package, cert or host state.
            return {"status": "DENIED_OR_HELD"}


__all__ = [
    "AndroidAppIdentity", "AndroidAppRegistration", "AndroidAppPeerGateway",
    "verify_android_binding",
]
