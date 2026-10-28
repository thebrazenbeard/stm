"""Deterministic synthetic conversational-history fixtures.

No user conversations, third-party benchmark datasets, or remote services are
used.  The intentionally tiny gold set detects correctness regressions; it is
not a representative estimate of conversational recall accuracy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class SyntheticScope:
    tenant_id: str
    owner_id: str
    agent_id: str


@dataclass(frozen=True)
class SyntheticTurn:
    fixture_id: str
    scope: SyntheticScope
    conversation_id: str
    role: str
    content: str
    event_time: datetime
    replaces: str | None = None


@dataclass(frozen=True)
class SyntheticQuestion:
    question_id: str
    scope: SyntheticScope
    current_conversation_id: str
    query: str
    gold_ids: tuple[str, ...]
    category: str


@dataclass(frozen=True)
class SyntheticDataset:
    turns: tuple[SyntheticTurn, ...]
    questions: tuple[SyntheticQuestion, ...]


SCOPES = (
    SyntheticScope("local", "alice", "vera"),
    SyntheticScope("local", "bob", "vera"),
    SyntheticScope("local", "alice", "other-agent"),
    SyntheticScope("other-tenant", "alice", "vera"),
)


def build_dataset(*, turns_per_conversation: int = 25) -> SyntheticDataset:
    """Create six chats per scope with older, corrected and current evidence.

    The four scopes intentionally share the keyword ``zinnia``.  This tests
    scope predicates without leaking personal data into the fixture.
    """
    if turns_per_conversation < 25:
        raise ValueError("turns_per_conversation must be >= 25")
    anchor = datetime(2025, 1, 1, tzinfo=timezone.utc)
    turns: list[SyntheticTurn] = []
    questions: list[SyntheticQuestion] = []
    position = 0
    for scope_no, scope in enumerate(SCOPES):
        tag = ("alice", "bob", "other-agent", "other-tenant")[scope_no]
        for conversation_no in range(6):
            chat = f"{tag}-chat-{conversation_no}"
            for turn_no in range(turns_per_conversation):
                fixture_id = f"{tag}-f-{conversation_no}-{turn_no}"
                content = (
                    f"Synthetic sensor record {tag} conversation {conversation_no} "
                    f"turn {turn_no}: the apparatus checked the gray compass "
                    "and ultraviolet marker during a routine calibration."
                )
                if conversation_no == 1 and turn_no == 3:
                    fixture_id = f"{tag}-zinnia"
                    content = (
                        f"For the {tag} profile, the greenhouse lookup phrase is "
                        f"zinnia code {tag}."
                    )
                if scope_no == 0 and conversation_no == 2 and turn_no == 10:
                    fixture_id = "alice-windchime"
                    content = "The old music-room bench is called windchime."
                if scope_no == 0 and conversation_no == 3 and turn_no == 4:
                    fixture_id = "alice-old-passphrase"
                    content = "The current project passphrase is saffron."
                if scope_no == 0 and conversation_no == 5 and turn_no == 23:
                    fixture_id = "alice-maple"
                    content = "The active field notebook uses the maple reference."
                turns.append(SyntheticTurn(
                    fixture_id=fixture_id,
                    scope=scope,
                    conversation_id=chat,
                    role="user" if turn_no % 2 == 0 else "assistant",
                    content=content,
                    event_time=anchor + timedelta(minutes=position),
                ))
                position += 1
        if scope_no == 0:
            # Correction is a new chronological event, not a rewrite of the
            # historical source. Only the successor is current for retrieval.
            turns.append(SyntheticTurn(
                fixture_id="alice-new-passphrase",
                scope=scope,
                conversation_id="alice-chat-3",
                role="user",
                content="The corrected project passphrase is marigold.",
                event_time=anchor + timedelta(minutes=position),
                replaces="alice-old-passphrase",
            ))
            position += 1

        current = f"{tag}-chat-5"
        questions.append(SyntheticQuestion(
            question_id=f"{tag}-cross-chat-zinnia", scope=scope,
            current_conversation_id=current, query="zinnia",
            gold_ids=(f"{tag}-zinnia",), category="cross_conversation",
        ))
        if scope_no == 0:
            questions.extend((
                SyntheticQuestion("alice-older-fact", scope, current,
                                  "windchime", ("alice-windchime",), "cross_conversation"),
                SyntheticQuestion("alice-updated-fact", scope, current,
                                  "marigold", ("alice-new-passphrase",), "correction"),
                SyntheticQuestion("alice-current-chat", scope, current,
                                  "maple", ("alice-maple",), "current_conversation"),
                SyntheticQuestion("alice-lexical-gap", scope, current,
                                  "journal", ("alice-maple",),
                                  "paraphrase_challenge"),
                SyntheticQuestion("alice-obsolete-keyword", scope, current,
                                  "saffron", (), "negative_superseded"),
                SyntheticQuestion("alice-unsupported", scope, current,
                                  "pineapple", (), "negative_absent"),
            ))
    return SyntheticDataset(tuple(turns), tuple(questions))


if __name__ == "__main__":
    sample = build_dataset()
    print(f"synthetic turns={len(sample.turns)} questions={len(sample.questions)}")
