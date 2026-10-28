# Local conversation archive (experimental STM v0.2)

STM v0.1 keeps a small, bounded working context for **one** tenant/owner/agent/session. The optional `ConversationArchive` is a separate, local SQLite evidence ledger for recalling exact messages from **other conversations belonging to the same authorized tenant/owner/agent**. It does not change `STM.open_session()` or silently add historical records to working memory.

Status: v0.2 source candidate. No claim of installation in Vera, production authorization, secure physical deletion, real-model recall quality, or KV-cache reuse follows from passing local source tests.

## Start locally

From the repository checkout (Python 3.10+):

```bash
python -m pip install -e .
python examples/conversation_archive.py
python -m unittest discover -s tests -v
```

The example generates synthetic conversation text in a temporary SQLite database and uses an intentionally simple **demonstration-only** authorizer. An embedding application must replace it with an authorization callback that receives an authenticated host principal. A raw `owner_id`, `session_id`, or `DemoPrincipal` object is **not** proof of identity; untrusted users must not be allowed to create arbitrary principals or authorizer callbacks.

## Separate authority and storage planes

```python
from stm.archive import ArchiveScope, ConversationArchive

scope = ArchiveScope(tenant_id="local", owner_id="alice", agent_id="vera")

def trusted_host_authorize(principal, action, target_scope):
    # This is a required integration point, NOT a complete authentication design.
    # The host must already have authenticated principal and bound its permissions.
    return host_policy.can_access(principal, action, target_scope)

archive = ConversationArchive("private-history.sqlite3", authorize=trusted_host_authorize)
```

The `host_policy` variable represents an application-specific policy service; the snippet is intentionally illustrative and will not run without the host's implementation. For a working, standalone synthetic demonstration use `examples/conversation_archive.py`.

`ConversationArchive` exposes:

- `append_turn(principal, scope, *, conversation_id, role, content, source, privacy, event_time)` to write source-attributed text.
- `search(principal, scope, query, *, privacy_scopes, limit)` to return ranked `ArchiveHit` values; each hit carries an original turn and a **scope-local lexical term-coverage score**, not a global FTS5 BM25 score or factual confidence score.
- `correct(principal, scope, turn_id, content)` to create a successor with a stable link to the superseded turn, hiding the old version from normal search.
- `delete(principal, scope, turn_id)` to remove a turn from normal archive retrieval and indexing.
- `close()` followed by reopening the same file to restore durable archive state.

Every archive call requires its own authorization decision for `append`, `search`, `correct`, or `delete`, **plus** explicit `write_privacy:<label>` grants for stored labels and `read_privacy:<label>` grants for requested labels (including label permission on correction/deletion). The backend additionally filters by exact tenant/owner/agent values in SQLite. The conversation ID is an evidence locator, **not** an authorization boundary. A caller may search across its own past conversations only after the trusted host authorizes the operation.

For session integration, instantiate `ArchiveHistoryReader(archive, authenticated_principal)` from `stm.archive_adapter` and pass its results through the existing `HistoricalEvidenceBridge`. Its results have `HISTORICAL_EVIDENCE_ONLY_NOT_CURRENT_MEMORY_OR_AUTHORITY` semantics. They retain source turn IDs and event timestamps. The host decides whether an excerpt may enter a prompt as **quoted untrusted data**, subject to separate privacy and token-budget checks. The archive never grants permission, changes self identity, makes psychological judgments, retrains a model, or auto-promotes information to DeepMemoryStorage.

## Data lifecycle and correction

Each turn records a stable ID, conversation ID, role, exact source text, source locator, privacy label, event time and database recording time. A correction creates a new attributable turn while marking the predecessor superseded for normal current retrieval. The old content may remain in raw historical storage as evidence unless explicitly erased. A historical recollection is therefore not automatically a *current* fact; applications must respect timestamps, supersession and user corrections.

Deleting an indexed turn and obtaining no FTS matches demonstrates **logical non-retrievability** in that query path. It does **not** prove irreversible erasure. SQLite pages, WAL files, filesystem snapshots, backups, application logs, model prompts and separately derived embeddings may preserve prior contents. A personal-memory deployment needs a written retention and erasure policy, key/storage policy, secure backup workflow, and tests that traverse every derivative. `PRAGMA secure_delete` and FTS5's separate `secure-delete` setting have version-specific requirements and are not a substitute for deleting backups.

## Privacy and operational boundaries

- SQLite is **plaintext by default**. Use a private filesystem with explicitly verified protection, or a separately reviewed encrypted storage option such as SQLCipher. Do not place this database in an unprotected sync folder or telemetry stream.
- On POSIX, the archive checks that the immediate database directory is owned by the current process user and not group/world-writable. It creates new database files with `0600` permissions *before* enabling WAL and refuses insecure existing files or symbolic links. Database, WAL and shared-memory file modes are checked after operations; this does not defend against malicious processes running under the same OS user or every filesystem race. The Windows host must enforce its own ACLs.
- WAL permits readers and a writer to coexist, but only one writer commits at a time, long readers can delay checkpoints, and shared network filesystems are not a supported WAL deployment. SQLite itself must be pinned and regression-tested on the actual host.
- A broad callback such as `lambda *args: True` disables application authorization. It is appropriate only for isolated synthetic tests, never a shared or externally callable Vera process.
- Contents of imported transcripts, retrieved passages, and generated summaries remain *data*. Do not feed a retrieved statement into system/developer instructions, tool authorization, identity governance, or active user consent.
- Keyword/FTS retrieval can miss paraphrases. Semantic embeddings are optional future adapters and similarity never proves truth, speaker identity or authority.
- Scoped lexical ranking scans matching authorized records instead of using shared-corpus BM25 statistics (which can leak other scopes' term prevalence through scores/order). This avoids a silent recency cap but means latency and memory cost can grow for common terms over very large archives; measure on the target host before deployment. Timing-side-channel resistance is not established.
- No built-in retention daemon or automatic TTL expiration is implied by this v0.2 slice. Application retention and secure deletion must be specified and verified before ingesting real private conversation history.
- Neither `ConversationArchive` nor `ArchiveHistoryReader` provides an inference-engine KV cache. App prompt-prefix hits are not evidence of llama.cpp, Ollama or vLLM prefix reuse.

## Verification and evaluation

Use `tests/test_archive.py`, `tests/test_archive_adapter.py`, and `tests/test_archive_security.py` to check basic persistence, correction, privacy filtering, cross-scope denial, and negative behavior. In particular, external-content FTS5 consistency requires `integrity-check` with `rank=1`. The reproducible synthetic evaluation (`python benchmarks/bench_archive.py`) compares FTS5 selection with a sliding window and uncached recency retrieval on equal fixtures; its output represents that test only, not a LongMemEval score or demonstrated Vera performance. Real deployment also requires authenticated-host tests, SQLite version checks, encrypted backup/deletion review, multi-writer/restart stress tests and local-model context/latency qualification.

Reference design and source constraints: `docs/archive_v02_contract.md`; official [SQLite FTS5](https://www.sqlite.org/fts5.html) and [WAL](https://www.sqlite.org/wal.html) documentation. No third-party library source was copied into this implementation.
