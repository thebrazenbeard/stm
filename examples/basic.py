"""Small offline demonstration of STM's working-session lifecycle."""

from pathlib import Path
from tempfile import TemporaryDirectory

from stm import STM


def main() -> None:
    memory = STM()
    chat = memory.open_session(tenant_id="demo", owner_id="alice", agent_id="local-llm", session_id="demo-1")
    old = chat.append("Our project codename is Lantern", source="chat:1", pinned=True)
    chat.append("Bring the compiler benchmark to tomorrow's meeting", source="chat:2")
    print("Retrieved:", [r.content for r in chat.retrieve("compiler benchmark")])
    packed = chat.assemble_context("What is the project codename?", token_budget=1024)
    print("Context:\n" + packed.text)
    print("Budget units:", packed.token_count, "/", packed.token_budget)
    chat.correct(old.id, "Our project codename is STM", expected_version=1)

    with TemporaryDirectory() as directory:
        checkpoint = Path(directory) / "session.json"
        chat.checkpoint(str(checkpoint))
        reopened = STM().open_session(tenant_id="demo", owner_id="alice", agent_id="local-llm", session_id="demo-1")
        reopened.restore(str(checkpoint))
        print("Recovered:", [r.content for r in reopened.retrieve("codename")])


if __name__ == "__main__":
    main()
