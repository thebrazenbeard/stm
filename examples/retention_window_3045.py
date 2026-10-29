"""Synthetic day-30 eligibility / day-45 local expiry, no Vera or DMS access.

The simulated time advancement below uses the archive's authorized test-time
sweep. Production needs a separately supervised authenticated sweeper.
"""

from datetime import datetime, timedelta, timezone

from stm import ArchiveScope, ConversationArchive
from stm.retention_window_3045 import (
    LOCAL_EXPIRE_AFTER, REVIEW_AFTER, ThirtyFortyFiveWindow,
)


scope = ArchiveScope("synthetic-tenant", "synthetic-owner", "synthetic-agent")
principal = "synthetic-host-authorized"


def authorize(identity, action, requested_scope):
    return identity == principal and requested_scope == scope and action in {
        "append", "expire", "audit_legacy", "search",
        "write_privacy:private", "read_privacy:private",
    }


window = ThirtyFortyFiveWindow()
with ConversationArchive(":memory:", authorize=authorize) as archive:
    retained = window.retained_archive(
        archive,
        consent_check=lambda identity, requested_scope, operation, privacy: (
            identity == principal and requested_scope == scope
            and operation == "archive_write" and privacy == "private"
        ),
    )
    turn = retained.append_turn(
        principal, scope, conversation_id="example-chat", role="user",
        content="A synthetic reminder about a teal notebook.",
        source="synthetic-example:turn-1", privacy="private",
    )
    recorded_at = datetime.fromisoformat(turn.recorded_at)
    expires_at = datetime.fromisoformat(turn.expires_at)
    assert timedelta(0) < expires_at - recorded_at <= LOCAL_EXPIRE_AFTER

    early = window.review_policy.evaluate(
        turn, now=recorded_at + REVIEW_AFTER - timedelta(seconds=1),
        current_consent=True, current_authority=True,
    )
    assert not early.ready_for_review

    review = window.review_policy.evaluate(
        turn, now=recorded_at + REVIEW_AFTER + timedelta(seconds=1),
        current_consent=True, current_authority=True,
    )
    assert review.ready_for_review  # Does not export anything.

    # Simulate an authorized host sweep *after* the selected hard deadline.
    simulated_after_expiry = expires_at + timedelta(seconds=1)
    assert not archive.search(
        principal, scope, "teal", privacy_scopes=frozenset({"private"}),
        require_expiration=True, now=simulated_after_expiry,
    )
    assert archive.expire_due(
        principal, scope, now=simulated_after_expiry,
        privacy_scopes=frozenset({"private"}),
    ) == 1

print("DAY_30_REVIEW_ONLY, DAY_45_SOURCE_EXPIRY, SYNTHETIC_NO_DMS_EXPORT")
