# STM v0.2 local conversation archive — integration contract

Status: implementation contract for the v0.2 feature branch; not a production authorization.

The current `STM.open_session` API, exact four-ID working-session isolation and existing historical bridge remain intact. The archive is an **opt-in**, separately governed cross-conversation *evidence* store, not active memory or long-term self/identity state. No model, network service, vector extension, or additional mandatory Python dependency.

## Public archive API (owned by `src/stm/archive.py`)

```python
@dataclass(frozen=True)
class ArchiveScope:
    tenant_id: str
    owner_id: str
    agent_id: str

@dataclass(frozen=True)
class ArchiveTurn:
    turn_id: str
    conversation_id: str
    role: str
    content: str
    source: str
    privacy: str
    event_time: str  # timezone-aware ISO-8601 UTC
    recorded_at: str
    supersedes_id: str | None

@dataclass(frozen=True)
class ArchiveHit:
    turn: ArchiveTurn
    score: float  # scoped lexical term-coverage signal, not confidence or truth

class ConversationArchive:
    def __init__(self, path: str, *, authorize: Callable[[object, str, ArchiveScope], bool],
                 require_fts_secure_delete: bool = False) -> None: ...
    def append_turn(self, principal: object, scope: ArchiveScope, *, conversation_id: str,
                    role: str, content: str, source: str = 'conversation',
                    privacy: str = 'private', event_time: datetime | None = None) -> ArchiveTurn: ...
    def search(self, principal: object, scope: ArchiveScope, query: str, *,
               privacy_scopes: frozenset[str], limit: int = 8) -> tuple[ArchiveHit, ...]: ...
    def correct(self, principal: object, scope: ArchiveScope, turn_id: str,
                content: str) -> ArchiveTurn: ...
    def delete(self, principal: object, scope: ArchiveScope, turn_id: str) -> bool: ...
    def close(self) -> None: ...
```

Calls must check `authorize(principal, action, scope)` for actions `append`, `search`, `correct`, `delete`; fail closed on `False` or error. **Privacy labels are also authenticated by callback:** require `write_privacy:<label>` on append, `read_privacy:<label>` for *every* label requested during search, and the appropriate source-label permission during correction/deletion. The embedding host authenticates `principal` and provides a trusted callback. This Python library **cannot authenticate a principal merely from IDs**; a callback returning `True` for everything is suitable only for trusted single-process demos/tests, and must be labeled as such. All SQL queries must enforce exact tenant/owner/agent filters *again*, regardless of callback behavior. Searching across conversation IDs within the same scope is intentional; searching across owner/agent/tenant is not.

Records carry role, source, privacy, event and recording time and stable turn IDs. Correction creates a new turn referring to the predecessor via `supersedes_id`, marks prior turn inactive for search, and never presents the predecessor as current. Delete removes the target's content from canonical search and FTS5 index and invalidates descendants as necessary; note that logical deletion cannot guarantee forensic erasure from preexisting backups/WAL. Never insert historical text automatically into active STM. User-provided content is always data, never instructions/permission.

Use SQLite `sqlite3` WAL, foreign keys, FTS5 external-content triggers or equivalent atomic indexing, `PRAGMA user_version` schema checks, and parameterized owner predicates. Escape user search terms into a safe phrase/token query; never concatenate raw user query as FTS SQL grammar. For index integrity tests use external-content `integrity-check` **with `rank=1`**. Include recovery/reopen, concurrent writers, cross-scope, TTL/retention policy limitations in documentation; default plaintext must be disclosed.

SQLite FTS5 secure-delete version handling is strict opt-in for real retention: the constructor's `require_fts_secure_delete=True` rejects unqualified builds. SQLite 3.45.1 accepted the FTS5 setting but failed the external-content deletion/integrity regression; SQLite 3.53.1 passed. Until older-version behavior is fixed and independently qualified, the non-strict prototype intentionally leaves FTS5 secure-delete disabled below 3.53.1 and reports `fts_secure_delete_enabled=False`. Do not interpret successful normal deletion on that path as physical erasure.

## Historical adapter (owned by `src/stm/archive_adapter.py`)

`ArchiveHistoryReader(archive: ConversationArchive, principal: object)` exposes the already defined `HistoricalEvidenceReader.search(query, *, scope: SessionKey, authorized_privacy_scopes: frozenset[str], limit=8)` protocol. It maps archive hits to `HistoricalEvidence` with `result_semantics=HISTORICAL_ONLY`, exact citation turn IDs, event timestamps, and a local archive locator; use `ArchiveScope(scope.tenant_id, scope.owner_id, scope.agent_id)`. The original `HistoricalEvidenceBridge` still validates results. Do not modify `src/stm/history.py`.

## Worker file ownership

- Archive owner: `src/stm/archive.py`, `tests/test_archive.py`.
- Historical adapter owner: `src/stm/archive_adapter.py`, `tests/test_archive_adapter.py`.
- Security test owner: `tests/test_archive_security.py` only.
- Evaluation owner: `benchmarks/bench_archive.py`, `benchmarks/archive_fixtures.py` only.
- Documentation owner: `docs/conversation_archive.md`, `examples/conversation_archive.py` only.
- Token budgeting owner: `src/stm/tokenizer_adapter.py`, `tests/test_tokenizer_adapter.py` only; must be optional and not alter existing `context.py` or claim runtime KV reuse.
- One owns packaging exports, cross-component integration, review, bug fixes after worker handoff, test environment, and publication decisions. No worker commits, pushes, PRs, source-repo edits, or modifies another ownership domain.

Acceptance: installable Python 3.10+, no cloud mandatory, 89 v0.1 regressions remain green, archive round-trip/reopen/correction/deletion/scope and adapter tests pass, explicit host-auth interface, deterministic baseline results and limitations recorded. No activation/deployment or confidential user data ingestion.
