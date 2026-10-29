# STM v0.1 architecture and integration contract

STM keeps a deliberately small **current working set**. It is not a semantic archive, a personal identity store, a learned model parameter update, or a claim that old observations are presently true.

## Components and responsibilities

| Component | Source | Boundary |
| --- | --- | --- |
| Session coordination | `core.py`, `models.py` | `STM.open_session`, `MemorySession`; exact tenant/owner/agent/session key |
| Working storage | `storage.py` | Bounded, thread-safe in-process records; TTL, version checks, checkpoint/restore |
| Retrieval | `retrieval.py` | Deterministic lexical/recency ranking with optional injected embeddings; scoped before ranking |
| Context packing | `context.py` | Byte-budget baseline, pluggable token counter, protected/pinned hard-fail on overflow |
| Cache | `cache.py` | Exact application prompt-prefix matches keyed by tenant/owner/agent/session/model/tokenizer/template |
| Governance | `governance.py` | Admission, privacy, provenance, consent receipts, quarantine indicators; no authority promotion |
| Historical boundary | `history.py` | Read-only external historical-evidence protocol, no automatic import or promotion |
| Evaluation | `tests/`, `benchmarks/` | Offline regressions, adversarial checks, reproducible synthetic comparisons |

`MemoryRecord` is immutable and includes ID, scope, content, role, source, kind (`observation|interpretation|hypothesis`), origin (`direct|external|historical`), privacy, pin, creation and update times, optional expiry and revision number. The event's `source` is an attribution label, not an authorization token.

## Lifecycle

1. A host supplies an *authenticated* actor scope. STM does not verify the identity proof itself.
2. Admission checks nonempty content/source, evidence category, privacy, historical origin and common instruction-spoofing signatures. Flagged text is quarantined (rejected by the facade).
3. The scoped store admits the immutable record. Expired records are rejected; bounded storage evicts only unpinned records, oldest first, or explicitly fails.
4. Retrieval filters a fully scoped current set, ranks optional items, and retains provenance across exact duplicate grouping. Scores represent relevance, **never truth or permission**.
5. Pinned current records bypass relevance top-k and dedup, then the packer includes them or raises. Selected context is presented chronologically with escaped source labels and untrusted-data annotation.
6. Correction creates a new version with unchanged ownership/provenance/privacy and optimistic concurrency checks. Deletion and TTL remove current working entries; optional cache entries for that session are invalidated.
7. Checkpoint saves one scope atomically to a bounded checksummed JSON file. Restore validates schema, digest, scope, timestamp and capacity before modifying live records.

## Public entrypoints

```python
from stm import STM
from stm.storage import InMemoryStore
from stm.retrieval import ContextRetriever
from stm.context import ContextPacker, TokenBudget, Utf8ByteCounter
from stm.governance import GovernancePolicy
from stm.cache import BoundedPromptPrefixCache, CacheIdentity

memory = STM(
    store=InMemoryStore(max_items_per_session=128, max_sessions=32),
    retriever=ContextRetriever(),
    packer=ContextPacker(counter=Utf8ByteCounter()),
    policy=GovernancePolicy(),
    cache=BoundedPromptPrefixCache(max_bytes=1_048_576),
)
session = memory.open_session(owner_id="user-1", agent_id="assistant-1", session_id="conversation-1")
```

Alternative retrieval backends should accept the fully scoped `SessionKey` and return ranked records without determining permissions. Alternative token counters must count the entire rendered prompt, not just raw contents. Alternative stores must preserve exact scope, immutable attribution, pinned-eviction semantics, and version checks.

## External integration

`HistoricalEvidenceBridge` only validates read-only candidates from an injected provider. It neither connects to a live DeepMemoryStorage instance by default nor authorizes the content as current. A deliberate host policy and explicit provenance are required for any separate current-memory admission.

`CacheIdentity` must use trustworthy model-revision, tokenizer, and template fingerprints; changing them causes a cache miss. Cache hits only mean this Python process saw the exact same prefix. Only a local inference backend's own verified telemetry could establish its KV reuse. Ollama-compatible metrics are parsed but no inference API is called in the default library.

The governance layer can issue narrow ephemeral cross-agent read grants within a shared owner/tenant/session trust domain. This does **not** make `STM.retrieve()` a cross-session search API: the standard session facade remains exact-scope only.
