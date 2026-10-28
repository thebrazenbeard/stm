"""Offline signed-host composition demonstration with purely synthetic data.

Shows real HMAC verification and STM retention behavior; the credential
issuer and synthetic channel binding here stand in for a REAL host that must
authenticate an OS user / peer before minting tokens. There is NO VeraOS
endpoint, installed scheduler, actual user consent, key store, backup erasure,
or production authentication in this example. Never reuse its test key.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from stm import STM, SessionKey
from stm.archive import ArchiveScope, ConversationArchive
from stm.auth_broker import (
    ConversationCredentialSpec, HmacConversationBroker, HmacCredentialIssuer,
)
from stm.retention import RetainedConversationArchive, RetentionPolicy
from stm.retention_runner import RetentionSweepRunner, SweepTarget
from stm.vera_bridge import VeraConversationBridge


@dataclass(frozen=True)
class SyntheticHostRequest:
    token: str
    # A true host MUST independently derive this from verified transport/OS
    # credentials; copying a client-provided header would defeat the binding.
    transport_binding: str


def main() -> None:
    current = datetime.now(timezone.utc)
    key = b"SYNTHETIC-EXAMPLE-ONLY-NEVER-USE-THIS-KEY"
    identity_scope = SessionKey("synthetic", "demo-owner", "vera", "new-chat")
    archive_scope = ArchiveScope("synthetic", "demo-owner", "vera")
    host_cleanup_principal = object()
    host_binding = "synthetic-local-peer-credential"
    revoked = False

    issuer = HmacCredentialIssuer(
        key, issuer="synthetic-local", audience="stm-demo", clock=lambda: current,
    )
    verifier = HmacConversationBroker(
        key, issuer="synthetic-local", audience="stm-demo",
        token_from_request=lambda req: req.token,
        channel_binding_from_request=lambda req: req.transport_binding,
        is_revoked=lambda issuer, subject, jti: revoked,
        clock=lambda: current,
    )
    token = issuer.issue(ConversationCredentialSpec(
        subject="synthetic-person", session=identity_scope,
        conversation_id="synthetic-conversation", privacy_scopes=frozenset({"private"}),
        capabilities=frozenset({
            "working_write:user", "working_context", "archive_write:user",
            "archive_store", "archive_read",
        }),
        channel_binding=host_binding, max_working_ttl_seconds=30,
        archive_consent=True, archive_retention_seconds=15,
    ), ttl_seconds=90)
    request = SyntheticHostRequest(token, host_binding)

    def archive_authorizer(principal: object, action: str,
                           scope: ArchiveScope) -> bool:
        # Service expiry is separate from user-credential source authority;
        # it cannot hard-delete an unexpired turn by ID.
        if principal is host_cleanup_principal:
            return (scope == archive_scope and action in
                    {"expire", "audit_legacy", "write_privacy:private"})
        return verifier.authorize_archive(principal, action, scope)

    with TemporaryDirectory() as temporary:
        with ConversationArchive(str(Path(temporary) / "history.sqlite3"),
                                 authorize=archive_authorizer) as archive:
            policy = RetentionPolicy(timedelta(seconds=15), frozenset({"private"}))
            retained = RetainedConversationArchive(
                archive, policy=policy, consent_check=lambda *_: False,
                clock=lambda: current,
            )
            runner = RetentionSweepRunner(
                retained, targets=lambda: (SweepTarget(
                    host_cleanup_principal, archive_scope, frozenset({"private"}),
                ),),
            )

            class OnWriteGate:
                def verify(self, grant, store):
                    return (store is archive and grant.archive_retention_seconds <=
                            policy.maximum_age.total_seconds() and runner.run_once().complete)

            bridge = VeraConversationBridge(
                STM(clock=lambda: current), resolve=verifier.resolve,
                authorize=verifier.authorize, archive=archive,
                retention_gate=OnWriteGate(), clock=lambda: current,
            )
            bridge.remember(request, "Synthetic violet beacon is stable")
            archived = bridge.archive_turn(
                request, "Synthetic cedar pin is on the imaginary board",
            )
            cited = bridge.recall_history(
                request, "cedar pin", privacy_scopes=frozenset({"private"}),
            )
            assert len(cited) == 1 and cited[0].memory_id == archived.turn_id
            print("Signed synthetic request: permitted, citation preserved")

            try:
                bridge.remember(SyntheticHostRequest(token, "forged-peer"),
                                "This should be rejected")
            except PermissionError:
                print("Wrong transport binding: denied")
            else:
                raise AssertionError("invalid host binding was accepted")

            current += timedelta(seconds=16)
            result = runner.run_once()
            assert result.deleted == 1 and result.complete
            assert bridge.recall_history(
                request, "cedar pin", privacy_scopes=frozenset({"private"}),
            ) == ()
            print("Explicit host retention catch-up: 1 expired row deleted")


if __name__ == "__main__":
    main()
