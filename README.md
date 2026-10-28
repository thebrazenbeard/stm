# STM — Short-Term Memory

STM is a small, dependency-free Python library for **bounded, session-scoped working context** in AI agents and local language models. It stores attributed observations and messages, selects relevant evidence, and constructs a bounded context block. The opt-in conversation archive provides separately authorized retrieval of original conversations across sessions. STM is not a long-term autobiographical memory, a neural-learning mechanism, a model-runtime KV cache, or an identity authority.

**Status:** v0.4 authenticated-host and retention **source candidate** based on v0.3. It is not connected to Vera's live interface: current VeraOS localhost HTTP endpoints do not authenticate callers. Source tests do not establish production installation, real signed-in identity mapping, or complete data erasure.

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

## Opt-in conversation archive (v0.2 candidate)

`ConversationArchive` stores exact, attributed turns from multiple conversations of one authorized tenant/owner/agent in a local SQLite database and retrieves historical **evidence**, never current authority. The caller's trusted host must authenticate the principal and pass a policy callback; matching owner ID strings alone never constitute authorization. Archive writes, reads, corrections and deletions require scoped access, including privacy-label grants. No archive is created by ordinary `STM()` usage.

The archive and the existing `HistoricalEvidenceBridge` are separate from active-session `STM.retrieve()` calls. History is not automatically admitted to current memory, interpreted as identity, or promoted to DeepMemoryStorage. SQLite data is plaintext unless the host supplies disk/database encryption; FTS, WAL, checkpoint and backup deletion require a retention policy.

See [conversation archive usage and boundaries](docs/conversation_archive.md), [v0.2 archive contract](docs/archive_v02_contract.md), [source qualification and remaining gaps](docs/v02_qualification.md), and [local example](examples/conversation_archive.py).

## Authenticated Vera host and finite-retention integration (v0.3 candidate)

The new `VeraConversationBridge` accepts only a **trusted broker-resolved, expiring** `VerifiedConversation` scope. It never treats a caller's `conversation_id`, localhost, browser `Origin`, or `Host` as authentication. Working records are TTL-bounded; archiving is **disabled unless** explicit consent, a finite policy limit, archive permissions and a host-provided retention-enforcement gate are all supplied. Historical recall requires current consent and retrieves only nonexpired, explicitly governed evidence. There is no automatic promotion into live memory.

The SQLite schema now stores `expires_at`, migrates from v0.2, hides expired rows at query time, and exposes scope-authorized bounded `expire_due()` sweeps (with dry-run counts). `RetainedConversationArchive` wraps this with current consent checks and an explicit configurable maximum age (library ceiling: 90 days; **not Vera's adopted policy**). Host-side recurring scheduling, managed backups/logs, OS permissions, actual authentication and deletion across source journals are still required before any personal data is enabled.

See [Vera integration and source findings](docs/vera_local_integration.md) and [privacy/retention qualification](docs/privacy_retention_v03.md). This library does **not** attach itself to VeraOS's unauthenticated `/api/conversation` or `/api/conversation/history` endpoints.

## Unblocking authenticated local operation (v0.4 candidate)

- `HmacCredentialIssuer` and `HmacConversationBroker` support short-lived signed conversation grants with issuer, audience, scope, capability, consent and trusted transport binding. Host identity verification, key protection, revocation and single-use replay storage remain mandatory host responsibilities, not assumptions about browser headers.
- `ScopedCleanupAuthority` issues a **different**, narrowly scoped host-maintenance principal. It can authorize `expire` and `audit_legacy`, **not** arbitrary `delete(turn_id)`, retrieval or archival writes. Old user tokens cannot be reused for offline cleanup.
- `RetentionSweepRunner` supports explicitly invoked startup catch-up and supervised periodic expiry. Its reports cover registered scopes/labels only, identify incomplete backlogs and refuse to certify completion if policyless legacy records remain in scope. Old rows may be explicitly audited and purged only with separate `delete_legacy` authority.
- `ManagedArchiveBackupVault` is an optional **whole-database** POSIX-private backup manager requiring separate archive-wide administrator rights. It refuses known policyless/expired content, cannot extend the earliest record deadline, and reports partial retirement and unmanaged copies. It is **not encrypted or forensically erased** and is not qualified for Windows ACLs.
- `stm.linux_peer_gateway.PeerMemoryGateway` is an opt-in Linux-only working-memory prototype using actual `AF_UNIX`/`SO_PEERCRED` process identity. It is **not a VeraOS desktop/browser integration**, cannot distinguish processes sharing a UID and exposes no archive writes.
- The working-context packer now filters explicitly granted privacy labels before retrieval/pinning, so a private-only grant does not need blanket shared/session access.

See [v0.4 privacy/retention matrix](docs/privacy_retention_v04.md), [VeraOS host integration blockers](docs/vera_os_auth_status_v04.md), and [source verification record](docs/v04_qualification.md). The executable [authenticated-host example](examples/authenticated_host_demo.py) uses synthetic credentials; nothing is installed automatically.

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
python benchmarks/bench_archive.py --iterations 30
python examples/basic.py
python examples/conversation_archive.py
python examples/vera_bridge_mock.py
python examples/authenticated_host_demo.py
```

These commands verify the source candidate locally. No external service is installed or modified by them.
