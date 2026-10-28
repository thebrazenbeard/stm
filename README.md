# STM — Short-Term Memory

STM is a small, dependency-free Python library for **bounded, session-scoped working context** in AI agents and local language models. It stores attributed observations and messages, selects relevant evidence, and constructs a bounded context block. It is not a long-term autobiographical memory, a neural-learning mechanism, a model-runtime KV cache, or an identity authority.

**Status:** v0.1 source candidate for review. Tests of source code do not establish installation in an agent, model-runtime acceleration, or production readiness.

## Install

Requires Python 3.10 or newer. No cloud API, model server, external database, or embedding service is required.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Quick start

```python
from stm import STM

memory = STM()
session = memory.open_session(
    tenant_id="local", owner_id="person-1", agent_id="assistant-1", session_id="chat-1"
)

item = session.append(
    "The next build review is on Friday",
    role="user", source="conversation:turn-7", kind="observation",
)
print([record.content for record in session.retrieve("build review")])

context = session.assemble_context("When is the build review?", token_budget=1024)
print(context.text)
print(context.token_count, context.token_budget)

session.correct(item.id, "The next build review is on Thursday", expected_version=1)
session.delete(item.id)
print(session.stats())
```

`session.build_context(...)` is an alias for `assemble_context(...)`. The context is **quoted, attributed, untrusted data** for an application to use in its own policy-controlled prompt. STM does not execute or elevate stored instructions.

The default `Utf8ByteCounter` measures **UTF-8 bytes**, not actual model tokens. This enforces an application byte budget, not an exact per-model context-window guarantee. Supply a model-specific `TokenCounter` and account for chat-template/system overhead when model-token accuracy matters. Pinned records cannot silently disappear: STM either packs them or raises `BudgetOverflow`.

## What the first release includes

- Exact tenant/owner/agent/session isolation within in-process storage.
- Bounded record and active-session capacities; deterministic oldest-unpinned eviction.
- TTL expiration, correction with optimistic version checks, deletion, and explicit pruning.
- Deterministic lexical + recency retrieval; optional injectable local semantic embedder.
- Bounded relevance-first context packing with chronological presentation and source attribution.
- Optional atomic, checksummed JSON checkpoints and recovery.
- Application-level prompt-prefix cache with explicit hits, misses and invalidations. It **does not** store or prove reuse of inference-engine KV tensors.
- Conservative admission and privacy controls, historical-only classification, and narrow in-memory consent grants.
- Standalone tests and reproducible synthetic benchmark harnesses.

See [architecture](docs/architecture.md), [source research and license boundaries](docs/research.md), [limitations](docs/limitations.md), and [examples](examples/basic.py).

## Checkpoint and restore

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from stm import STM

memory = STM()
session = memory.open_session(owner_id="owner", agent_id="agent", session_id="s")
session.append("An attributed short-lived note", source="chat:1")

with TemporaryDirectory() as temp:
    path = Path(temp) / "session.json"
    session.checkpoint(str(path))
    restored = STM().open_session(owner_id="owner", agent_id="agent", session_id="s")
    restored.restore(str(path))
    assert len(restored.retrieve("note")) == 1
```

Checkpoints are plaintext, contain potentially sensitive data, and are not authenticated. Use private, trusted filesystem paths; SHA-256 detects accidental damage, not deliberate modification. Deleting live memory does not erase older checkpoint copies.

## Boundaries

The calling host must authenticate identities before supplying owner, agent, session, or tenant IDs; mere matching strings are not proof of identity. `privacy="shared"` does not authorize global retrieval. Historical evidence from DeepMemoryStorage remains an external, read-only candidate and must not be silently promoted into current working memory. STM does not make psychological judgments or overwrite self/empathy governance.

Reference implementations were researched for mechanisms and tradeoffs. STM's code is original; no source or private historical data from those repositories was copied. The repository owner has not yet selected a redistribution license for STM itself.

## Development

```bash
python -m unittest discover -s tests -v
python benchmarks/bench_stm.py
python examples/basic.py
```

These commands verify the source candidate locally. No external service is installed or modified by them.
