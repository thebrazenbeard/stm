# STM — Short-Term Memory

STM is a small, dependency-free Python library for **bounded, session-scoped working context** in AI agents and local language models. It stores attributed observations and messages, selects relevant evidence, and constructs a bounded context block. The opt-in conversation archive provides separately authorized retrieval of original conversations across sessions. STM is not a long-term autobiographical memory, a neural-learning mechanism, a model-runtime KV cache, or an identity authority.

**Status:** v0.7 **source candidate** (v0.1-v0.7 review stack). The library implements working-memory APIs, opt-in SQLite conversation evidence, consent/retention boundaries, prototype Windows and Android/Linux local-process authentication, and a durable clock-fence for supervised retention. It is **not connected** to a verified signed-in VeraOS/VeraAPK conversation producer, does not operate a host scheduler or a private DeepMemoryStorage writer, and has never qualified complete deletion of all journals/backups. A successful source test is not evidence of live host integration.

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

## Windows, Android/Linux and governed history handoff (v0.5 candidate)

Patrick proposed **30 days before conversational history becomes eligible for DeepMemoryStorage review**, on Windows and Android/Linux. STM deliberately treats this as *review eligibility*, not an automatic transfer, retention extension, deletion, current identity update or permission to train a model.

- `WindowsPeerMemoryGateway` is an opt-in local Windows named-pipe gateway with explicit account-SID ACLs and client-token impersonation. It permits working-memory operations only; the calling host must map the Windows account to an actual Vera principal. Its simulated policy tests are portable; an OS-backed native test is provided for Windows CI.
- `AndroidAppPeerGateway` uses Linux `SO_PEERCRED` plus host-provided fresh Android PackageManager identity (package, signing certificate, UID and user profile). The package resolver is an interface, **not implemented Android platform attestation**. Both gateways refuse archive/export operations. Neither authenticates a phone talking over a network to a PC.
- `HandoffPolicy` calculates 30-day review eligibility separately from source expiration. `HandoffReviewQueue` holds bounded, **in-memory, content-free** tickets and checks live versions/consent; it is not a durable scheduler or migration. A source record expiring **at** day 30 is ineligible: an approved longer deadline or an earlier review window would have to be selected before source expiry.
- `DeepMemoryHandoff` is an optional *injected-sink contract* that requires current per-turn long-term export consent, archive scope authority, exact provenance, a verified private destination capable of deletion/correction/revocation and finite retention, plus an independently verified receipt. It never deletes source records, connects to a live DMS writer, or silently retries uncertain sends.

**Critical destination boundary:** `thebrazenbeard/deepmemorystorage` is currently a **public** append-only GitHub evidence repository with read/query tooling, not a qualified private conversation-ingestion service. Never export private conversation payloads to that GitHub repo. The new sink is intentionally host-supplied and disabled without independent destination governance.

See [Windows/Android platform and proposed 30-day policy](docs/windows_android_deepmemory_handoff_v05.md). Actual host endpoints, target retention/deletion guarantees, user consent and activation all require separate verification. The in-memory review queue has a capacity ceiling but no durable tombstone or cross-restart retry ledger; it is unsuitable as a production transfer scheduler.

## Selected 30/45-day local archive policy (v0.6 candidate)

Patrick selected **review eligibility on day 30 and hard local source expiry on day 45**. A 15-day window is available for separately consented private historical export, but **no export is automatic and a failed/pending export never extends local retention**. Source records become unreadable at expiration; a trusted running host must supervise physical expiry sweeps and all backup/original-journal cleanup. Without an authorized destination, local history still expires at day 45. A later correction inherits the original expiry and may not mature to its own 30-day review threshold before day 45.

See [selected policy and effect limitations](docs/retention_30_45_v06.md). This applies to newly admitted opt-in archive turns through the configured host policy; it does not silently rewrite old history, grant long-term-memory permission, or activate a Windows/Android Vera service.

## v0.7 durable retention clock fence (source candidate)

`DurableClockFence` holds a transactional high-water mark for a host-provided UTC clock. It refuses backward observations across restarts and refuses to silently recreate an absent clock database. `SupervisedRetention` requires a real `RetentionSweepRunner` whose retained archive uses the exact same `DurableClockFence.now` callback; it checks that binding on construction and immediately before each sweep. A fake runner or independent/unfenced archive clock is rejected. It does not start a service or supervise its own scheduler.

The host must provide and secure the real user/session authenticator, current consent store, complete retention scope registry, a protected clock DB, supervised day-45 deletion, journal/backup retirement, and an independently qualified private DMS destination and specific export consent. The same clock fence must govern retention writes, reads, and sweeps; direct raw-archive access bypasses the wrapper and is not an approved deployment interface. This cannot detect every offline clock rollback or prove forensic erasure.

See [v0.7 durable clock-fence qualification](docs/retention_clock_fence_v07.md) and [the selected 30/45 policy](docs/retention_30_45_v06.md). Day 30 means **review eligibility only**; day 45 remains the local source deadline even when a handoff fails.
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
python examples/handoff_review_mock.py
python examples/retention_window_3045.py
```

These commands verify the source candidate locally. No external service is installed or modified by them.
