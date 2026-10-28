"""Synthetic day-30 review and private sink receipt; NO real DMS connection.

Run after ``pip install -e .``. This example intentionally sends no data to
the public DeepMemoryStorage GitHub repository or Vera host.
"""

from datetime import datetime, timedelta, timezone

from stm import (
    ArchiveScope, ArchiveTurn, DeepMemoryHandoff, HandoffPolicy,
    TargetGovernance,
)


now = datetime.now(timezone.utc)
scope = ArchiveScope("demo-tenant", "demo-owner", "demo-vera")
turn = ArchiveTurn(
    turn_id="synthetic-turn-1", conversation_id="synthetic-chat-1",
    role="user", content="A synthetic note about a blue paperclip.",
    source="example:synthetic-chat-1:turn-1", privacy="private",
    event_time=(now - timedelta(days=31)).isoformat(),
    recorded_at=(now - timedelta(days=31)).isoformat(),
    supersedes_id=None,
    expires_at=(now + timedelta(days=5)).isoformat(),
)
policy = HandoffPolicy(review_age=timedelta(days=30))
decision = policy.evaluate(
    turn, now=now, current_consent=True, current_authority=True,
)
assert decision.ready_for_review

target = TargetGovernance(
    destination_id="SYNTHETIC-PRIVATE-SINK-ONLY",
    retention_until=now + timedelta(days=60),
    supports_deletion=True, supports_correction=True,
    supports_consent_revocation=True, private_destination=True,
    supports_scope_isolation=True,
)


class MockPrivateSink:
    def __init__(self):
        self.entries = {}

    def submit(self, record, *, target, idempotency_key):
        assert target.destination_id == "SYNTHETIC-PRIVATE-SINK-ONLY"
        self.entries.setdefault(idempotency_key, record)
        return {"external_record_id": "synthetic-private:turn-1",
                "idempotency_key": idempotency_key}


sink = MockPrivateSink()
handoff = DeepMemoryHandoff(
    policy=policy,
    resolve_live_turn=lambda principal, check_scope, turn_id: (
        turn if principal == "demo-authorized" and check_scope == scope
        and turn_id == turn.turn_id else None
    ),
    authorize=lambda principal, action, check_scope, label: (
        principal == "demo-authorized" and action == "long_term_export"
        and check_scope == scope and label in (None, "private")
    ),
    consent=lambda principal, check_scope, turn_id, label, check_target: (
        principal == "demo-authorized" and check_scope == scope
        and turn_id == turn.turn_id and label == "private"
        and check_target == target
    ),
    verify_target=lambda check_target, check_scope, label: (
        check_target == target and check_scope == scope and label == "private"
    ),
    sink=sink,
    verify_receipt=lambda receipt, record, key: (
        receipt.get("idempotency_key") == key
        and sink.entries.get(key) == record
    ),
)
receipt = handoff.submit("demo-authorized", scope, turn.turn_id, target=target)
assert receipt.external_record_id == "synthetic-private:turn-1"
assert len(sink.entries) == 1
print("REVIEW_READY, SYNTHETIC_IN_PROCESS_RECEIPT_ONLY, SOURCE_UNCHANGED")
