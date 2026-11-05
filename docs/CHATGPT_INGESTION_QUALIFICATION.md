# ChatGPT account-history ingestion — qualification gates

**Status:** evidence ledger and gate specification; this document does **not**
authorize automatic import, promotion, inference, deployment or merge.

Event: [`chat_history_ingestion_live_coordination`](https://github.com/thebrazenbeard/chat-communication-bus/issues/403).
Source implementation: STM Draft [PR #3](https://github.com/thebrazenbeard/stm/pull/3),
initial exact head `49fbbba17813b305d950417d4711c6f5495bf27f`.

## What is currently evidenced

| Evidence class | Scope | Recorded observation | Remaining gap |
| --- | --- | --- | --- |
| SOURCE / local preflight | Lappy export | CCB issue records 8,929,236,891-byte ZIP, 9,264 entries, 20 numbered JSON shards | This document did not independently inspect the raw ZIP; verify stable source/version before future imports |
| REAL SYSTEM PROBE / local import | STM PR #3's Lappy import | Sanitized [event checkpoint](https://github.com/thebrazenbeard/chat-communication-bus/issues/403#issuecomment-6509189531) records exit 0; 1,960 unique conversations, 336,690 message nodes, 20/20 shards | These are event-reported results, not evidence of semantic memory or inference |
| REAL SYSTEM PROBE / encrypted readback | Same export and account vault | Event records AES-GCM archive verification and all 1,960 encrypted conversation records authenticated, exit 0 | Restore from independent recovery copy not demonstrated; independent shard recount not inherent to `verify()` |
| TEST / synthetic | STM draft importer at cited head | 13 focused synthetic tests recorded passing | Extend adversarial tests for hostile ZIPs, message graphs, wrong owners, deletion and retrieval |
| SOURCE INSPECTION | `chatgpt_archive.py` | Encrypts full ZIP; stores sealed complete conversation JSON keyed by HMAC of conversation ID | No per-node provenance/search index; no authenticated broker; no model hook |
| MODEL REVIEW / hostile | Cross-repository architecture assessment | Risks identified around role spoofing, stale claims, secrets, PII, prompt injection and plaintext index leakage | A model review alone cannot elevate runtime status |
| REAL SYSTEM PROBE / selected-model inference | Lappy VERA Interface and Android V2 | **Not demonstrated** | Require authenticated principal, bounded attributable retrieval and observed selected-model response |
| FORMAL VERIFY / neural weights | Vera model training | **Not demonstrated** | Requires actual weight change, frozen comparison, held-out evaluation and provenance |

Do not interpret an issue comment, a local script's exit code, a passing test,
a successful decryption, or agreement among subagents as the same evidence
class. A fresh independent observer must reproduce each asserted runtime gate.

## Gate sequence

### G1 — Source integrity and complete preservation

- Record the exact source version privately. Validate stable ZIP length/hash,
  archive paths and entry types, part naming and completeness, duplicate IDs,
  source rows and original assets. Avoid blind extraction and decompression
  bombs; reject unsupported content instead of certifying partial coverage.
- All original bytes remain encrypted in the owner-private source vault;
  every indexed object authenticates and maps back to its source export.
- Reimport the same source idempotently. Contradictory duplicate IDs fail.
  Demonstrate recovery after a deliberate interrupted synthetic import.
- An independent check should reparse and recount source records. Current
  `verify()` authenticates indexed conversations and archive bytes but does not
  independently reparse all numbered JSON shards in the original ZIP.

### G2 — Graph and provenance derivation (currently **OPEN**)

- Test a null-message root, edited/regenerated siblings, `current_node`
  selection, missing timestamps, multimodal/tool nodes, invalid parent links,
  cycles and duplicate node IDs with synthetic fixtures.
- Every accepted node is traceable to the source export version,
  conversation, node, reported author, branch and timestamp quality.
- The derivation is read-only against immutable source, with plaintext kept
  out of files, logs, public repositories, CCB and Blotter. Refuse unsupported
  graphs explicitly; record failure counts without content.
- Separate imported quote from interpreted claim, proposed summary and
  actually admitted memory. Dedup old Drive/other-export copies without
  silently collapsing source versions or conflicting corrections.

### G3 — Privacy, admission and retention (currently **OPEN**)

- Present an explicit owner-approved purpose and scope before promoting
  historical evidence to a live personal-memory record. Deny by default.
- Block third-party/private-secret disclosure; test revoked consent,
  currentness, corrections, cross-owner access, re-identification risk and
  prompt injections contained in the historical text.
- Keep derived records private and encrypted; ensure secure indexes/caches,
  precise purge of derived copies and deletion receipts.
- Test day-30 review and day-45 expiry **only for newly consented STM
  admissions**. Preserve archival source independently until separately
  authorized deletion; no automatic public-repo DeepMemoryStorage writes.

### G4 — Owner-authenticated retrieval and selected-model response (**OPEN**)

- Prove the local service's principal binding; `Host`/`Origin` checks are not
  a substitute. Failed/missing/forged/replayed credentials must return no
  private content. Scope requested output by owner, purpose, size and count.
- Show a known synthetic quote can be retrieved with its source citation,
  corrected with an explicit supersession reference, refused for another
  owner, and not executed as a tool instruction.
- Observe actual selected-model response using the quote as historical
  evidence, with proper attribution. Distinguish response text from training
  or autobiographical continuity.
- Prove Lappy VERA Interface independently of Android V2. For V2, require
  owner-device pairing and revocation. Check V1 connectivity before and after
  any separately authorized V2 rollout.

### G5 — Recovery and hostile verification (**OPEN**)

- Create a restricted backup that is recoverable after disk loss **without**
  exposing archive/key together unnecessarily. Restore to an isolated owner
  account, verify AES-GCM, counts, graph derivation and revoked-policy state.
- Falsify successful retrieval with secret-like canaries, malicious retrieved
  instructions, identical titles for different owners, stale corrections,
  malformed timestamps, conflicting source versions and missing metadata.
- Preserve independently verified test output, code commit, provider/runtime,
  exact artifact identity and material reviewer disagreements. Do not declare
  the event fully complete until G1–G5 runtime evidence is recorded.

## Next bounded implementation

Keep source preservation immutable. Build a synthetic-tested, local-only
graph/evidence derivation layer and a deny-by-default memory admission policy.
Only then add a *verified owner-authenticated* retrieval broker, staging
Android V2 without touching V1. No actual conversation content or keys should
be attached to pull requests or issue comments.
