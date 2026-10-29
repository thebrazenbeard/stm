# MemoryLedger / STM / DeepMemoryStorage — account-export integration contract

**Status:** source-based integration proposal for `chat_history_ingestion_live_coordination`. No private transcript transfer, model training, runtime installation, or memory-admission effect is established here.

**Scope:** the owner-provided ChatGPT entire-account export on Lappy and the next *optional*, private evidence/recall path. This document is not an instruction to publish that archive to GitHub or to move it into DeepMemoryStorage.

## Freshly inspected source anchors (2026-10-29)

| Repository | Exact observed source | What is actually available |
| --- | --- | --- |
| [MemoryLedger](https://github.com/thebrazenbeard/MemoryLedger) | `main@55b431b5257880f7b6636e5c6b3b7b9d3ec46792`; [Draft PR #1](https://github.com/thebrazenbeard/MemoryLedger/pull/1) `e1b62d0552d32262e37d127e7e9c386f541c2e4a` | Main is an initialized laboratory (only `.gitignore`); draft PR contains source-only `ConversationEvent`, `HostAuthorization`, `LifecyclePolicy`, `CandidateIndex`, `LifecyclePlanner.propose`, and synthetic tests. There is no store, device authenticator, or effect executor. |
| [STM](https://github.com/thebrazenbeard/stm) | `main@c40431c77e00a9b6b817641d07768d95bdd9c238`; [account-export Draft PR #3](https://github.com/thebrazenbeard/stm/pull/3) original head `49fbbba17813b305d950417d4711c6f5495bf27f` | Main implements bounded working context and optional consented historical archive, prototype host-auth/retention/handoff contracts, and **no qualified VeraOS / Android deployment**. PR #3 adds a separate encrypted entire-account source archive; this local worktree adds candidate source tests/derivation but does not make a network service. |
| [DeepMemoryStorage](https://github.com/thebrazenbeard/deepmemorystorage) | `main@47681d52923d05a66060e60a88c5e020e540f8c1` | An append-only historical-evidence repository with schema, provenance overlays and bounded query/catalog tools; **public GitHub repository**, not a private ingestion service. |

Primary inspected contracts: MemoryLedger [lifecycle contract (draft)](https://github.com/thebrazenbeard/MemoryLedger/blob/work/memory-lifecycle-contracts-v0-20261029/docs/MEMORY_LIFECYCLE_CONTRACT_V0.md); STM [retention 30/45](https://github.com/thebrazenbeard/stm/blob/main/docs/retention_30_45_v06.md) and [Windows/Android handoff](https://github.com/thebrazenbeard/stm/blob/main/docs/windows_android_deepmemory_handoff_v05.md); DMS [integration contract](https://github.com/thebrazenbeard/deepmemorystorage/blob/main/architecture/DEEP_MEMORY_INTEGRATION_CONTRACT_V1.md) and [record semantics](https://github.com/thebrazenbeard/deepmemorystorage/blob/main/schema/DEEP_MEMORY_RECORD_V1.md).

## One pipeline, distinct owners

| Plane / component | Responsibility | Explicit non-responsibility |
| --- | --- | --- |
| Private account-export source archive (STM PR #3) | Preserve the exact original ZIP and full encrypted conversation records under the owner-controlled local vault. Index by authenticated source/version and opaque conversation identity; independently recount the source when qualifying completeness. | Not current working memory; not truth/admission, training, or inferred consent. The ZIP's retention must have its **own** authorized source policy. |
| Graph and read-only evidence derivation (current STM draft work) | Preserve every parent/child/alternate branch; distinguish reported author, event time, record/version time, and opaque source/node locator. Label all historical text untrusted. | Does not rewrite the original, choose a truth-winning branch, or grant a tool action. Unsupported/malformed graphs are quarantined, not reconstructed by guessing. |
| STM working context / optional opt-in conversation archive | Hold bounded owner/tenant/session-scoped working context and newly admitted turns, with explicit privacy, consent, correction, TTL and 30/45 source deadlines. | The entire-account export is not retroactively day-45 STM material. SQLite conversation archive is **not encrypted by default**; do not insert private export text there without a separately qualified private deployment. |
| MemoryLedger lifecycle planner (Draft PR #1 only) | Given a complete authorized, versioned snapshot, propose `HOLD`, `REJECT`, `WORKING_ONLY`, `REVIEW_CURRENT`, `REVIEW_HISTORICAL`, `REVIEW_CORRECTION`, or `EXPIRE`. | A proposal is not storage, revocation, deletion, admission, memory export, current truth, or training. Its injected authorizer callback and speech-act label are not intrinsically trustworthy. |
| Private historical destination conforming to DMS semantics | *Future, separately approved deployment only:* store attributed historical evidence with privacy inheritance, source IDs, corrections, effective time and auditable deletion/retention. | The public `deepmemorystorage` GitHub ledger is **never** a transcript dump or private handoff target. Existing DMS repo query code does not prove a private destination writer. |
| Vera Mono governed-current memory | Separate authenticated admission and CAS/supersession for current mutable beliefs, state, and continuity; preserve source links and currentness checks. | Historical source, semantic similarity, or MemoryLedger recommendation never writes this plane automatically. |

The interface boundary is **asymmetric**: the source can supply evidence to a reviewer, but an advisory MemoryLedger proposal cannot write upstream to an encrypted archive or downstream to STM, DMS, or Vera Mono.

## Candidate mapping (not a deployed adapter)

1. A trusted local source reader verifies the encrypted original + indexed records **and**, separately, source-to-index coverage against the original ZIP using the opt-in source recount. A repaired/indexed state must have a versioned receipt; any scan of the 8.93 GB file is a private-host operation, not a task for many remote agents.
2. Each historical candidate retains `export_version`, `conversation_id`, `node_id`, `parent_id`, children/branch status, original author role, content type, original event time (or **unknown**), source-record/import time, and privacy classification. Record a correction/supersession edge without erasing the earlier source.
3. If a future MemoryLedger adapter is evaluated, derive its `ConversationEvent` from **trusted host-classified** evidence, not self-asserted data: `event_id` = private opaque stable source-node reference; `content_sha256` = private canonical content digest; `tenant_id/project_id/identity_id/conversation_id` and `privacy_scope` = authenticated host context; `occurred_at` only after timestamp validation. Unknown dates or pragmatics require a HOLD/quarantine path, **not invented time or a model assertion**. Keep identifiers/digests private; public correlation of predictable content hashes is a disclosure risk.
4. `HostAuthorization` is the output of an independently verified, current principal/consent boundary. It cannot be derived from a ChatGPT message, a `Host`/`Origin` header, an unverified app package name, or a caller-supplied boolean. The current MemoryLedger draft planner accepts a callback; that callback is **not an authenticator**.
5. A proposal may enter an **owner-visible, privacy-scoped review queue**. It cannot itself run `DeepMemoryHandoff`, grant `RECALL`, select current self-beliefs, or train a model. A separate effect owner checks fresh consent, source eligibility, exact destination identity, idempotency and a verified receipt.
6. Any future private-DMS retrieval must produce a DMS-compatible evidence envelope: `memory_id`, `source_ids`, `privacy_scope`, `provenance_ceiling`, `currentness_rule`, event/record/effective/retrieval times separately, correction overlay lineage, and `HISTORICAL_EVIDENCE_ONLY_NOT_CURRENT_MEMORY_OR_AUTHORITY`. The public repository's ledger union/query contract is a design reference, not the private data store.

## 30/45-day and original-export retention are different policies

- Patrick's selected STM rule for **newly consented local conversation records**: day 30 = *eligible for review*; day 45 = hard local visibility/expiry; pending or failed long-term transfer cannot extend that deadline.
- A correction inherits its source expiry. Review eligibility cannot fabricate another 30 days or resurrect an expired source.
- An entire-account ChatGPT export is a separate historical archive, not a newly admitted STM turn. A day-45 wipe of the 8.93 GB source is **not implied** by the STM rule, and indefinite preservation is **not automatically authorized** by implementation convenience. Establish its distinct retention/backup/deletion choice before relying on it as the sole source.
- Approval to keep short-term working context is not approval to export it to long-term storage, train weights, expose it to other devices, or publish it. Third-party content and secrets require separate screening/authority.
- Physical deletion must cover indexes, WAL/FTS, caches, checkpoints, logs, backups and private destination derivatives. A MemoryLedger `EXPIRE` proposal does not fulfill this obligation.

## Acceptance / falsification matrix

| Gate | Synthetic/source requirement | Further real evidence needed |
| --- | --- | --- |
| Source integrity | Reject malformed/missing numbered shards, traversal, unsafe ZIP metadata, duplicates with conflicting IDs; authenticate original bytes + every indexed row; **independently reparse source** to catch deleted index rows plus falsified counters. | Exact Lappy source, storage ACL, versioned tool/command exit, verified private readback; no transcript or key in public issue/CI. |
| Provenance | Reconstructed active path follows `current_node` parents while retaining inactive branches; author/time/metadata remain historical and corrections append provenance. | Bounded private compatibility check on actual graph variants; malformed records quarantined with counts only. |
| Scope and consent | Wrong owner, no host authorization, expired/revoked consent, third-party material, assistant/tool-authored claims and historical prompt injection all fail closed. | Windows owner-bound host principal and signed scoped grant `memory.historical.recall.review`; Android V2 independently paired and revocable; V1 service remains undisturbed. |
| Lifecycle | Unknown/hypothetical/quoted content yields at most working/review recommendation; cross-identity/cyclic/stale correction held; no auto promotion. | Host-authenticated MemoryLedger candidate evaluation against current STM/Vera Mono baseline with independently labeled held-out cases; no privacy/identity regressions. |
| Retention and recovery | Selected new STM day 30/45 clocks, crash/replay/idempotence, source archive vs STM separation, correction/tombstone propagation, deletion-all-copies test. | Supervised clock-fenced host scheduler, recoverable private backup, owner consent, auditable effect receipts and private sink deletion/readback. |
| Real consumption | Locally bounded owner-review excerpts are attributed quotations, not instructions; deny cross-owner and unreviewed privacy. | Actual authenticated selected-model readback on Lappy, distinct Android V2 enrollment/readback, no source-only claim of neural weight update or autobiography. |

> **Hostile challenge:** A model-generated label that says “this is my memory” is not a user admission receipt. MemoryLedger cannot elevate it simply because the source was successfully imported or repeated.

> **Hostile challenge:** A source repository containing DMS query tools is not a private storage service. Sending the owner's entire chat export to the public append-only ledger would irreversibly break confidentiality and revocation semantics.

## Current verified limits

- The [coordination issue](https://github.com/thebrazenbeard/chat-communication-bus/issues/403) records a real Lappy import and cryptographic indexed readback; its original status reports are not a current host memory-readback qualification. The draft local derivation/recount modules and their synthetic tests need exact-head integration and independent review.
- MemoryLedger `main` has no deployed planner and the interesting implementation remains Draft PR #1. Its recorded 38/38 tests on Lappy are **synthetic**, not a private-memory integration or an improvement against a frozen STM/Vera Mono baseline.
- The current STM `main` host bridges and handoff contracts are **source candidates**; the import feature branch is distinct. Reconcile the branches additively before claiming an installed unified runtime.
- DeepMemoryStorage `main` is public, historical and append-only. No private STM-to-DMS writer, authentication/retention/delete propagation, or selected-model recall has passed a live probe.

**Consequence:** Keep source preservation, lifecycle proposal, owner review, private archival write and current governed-memory admission as separate operations with independent authorization and evidence receipts. The next useful implementation is an authenticated *private* memory broker, not an automatic “import everything into DMS” command.
