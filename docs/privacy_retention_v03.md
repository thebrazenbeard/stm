# STM v0.3 privacy and retention verification matrix

Status: **library enforcement verified on synthetic SQLite stores**; actual
Vera host policy and runtime behavior **not verified**. Date: 2026-10-28.

## Source policy versus newly proposed mechanisms

- [Vera Memory and Privacy V2](https://github.com/thebrazenbeard/vera-control-plane/blob/6306f7009e933ed8a965146f9abf34a46caae490/project-instructions/native-v2/VERA_MEMORY_AND_PRIVACY_V2.md)
  defaults sensitive/autobiographical material to private and restricts
  memory admission, identity/currentness and training promotion. Historical
  retrieval alone does not grant present authority.
- VeraOS [security source](https://github.com/thebrazenbeard/vera-os/blob/11cb2bb81b80841fb6c03901088225b78ab9391a/docs/04-security-and-authority-model.md)
  does not select an authenticated local UI mechanism or logging privacy
  design. The inspected sources specify **no numeric conversation TTL**.
- `RetentionPolicy(maximum_age=...)` requires an explicit positive duration
  at or below **90 days**. This upper bound is a new conservative library
  ceiling, **not an adopted Vera runtime retention policy**. With no policy,
  no consent callback or no authorized identity, `RetainedConversationArchive`
  refuses use. Existing raw `ConversationArchive` callers can bypass the
  wrapper; the trusted host must confine direct archive access.

## Implemented, testable controls

| Requirement | Mechanism | Verification boundary |
| --- | --- | --- |
| Authenticated ownership | Broker-resolved, expiring grant plus independent `ConversationArchive` authorizer; IDs are never credentials | Mock broker adversarial cases, not real Vera credentials |
| Consent, privacy | Current per-operation consent and per-label permissions; revoked archival consent blocks bridge reads | In-process synthetic tests |
| Bounded retention | `expires_at` persisted in SQLite schema v2; correction inherits ancestor deadline; bridge rejects >90-day TTL | SQLite append/correct/reopen tests |
| Immediate expiry exclusion | SQL excludes expired rows **before ranking/limit**, floors supplied clock at system wall time; policy-aware reads exclude policyless rows | Long high-ranked expired-hit regression, clock rollback test |
| Authorized deletion | Scope+label-checked `expire_due()` in bounded transactions, dry-run count only; `delete()` for correction lineage | SQLite FTS integrity, scope, denial, dry-run and restart tests |
| Capacity and safety | Batch max 1000; content-size caps and safe quoted FTS syntax | Unit/negative tests |
| Source evidence | Historical-only, source-linked archive reader; no automatic working/long-term promotion | Bridge/adversarial tests |

## Explicitly **not** verified

- A real authenticated Vera conversation host or broker, installed process,
  selected policy version, live consent, or scheduled expiration execution.
- End-to-end deletion from Vera's original `pre_active` and task journals,
  logging, OpenViking/SemanticAtlas/DeepMemory, caches or training stores.
- Forensic removal from SQLite WAL, FTS shadow structures on older SQLite,
  backup archives, SSD snapshots, swap or prior file copies. A copied SQLite
  backup can still reveal a subsequently deleted turn (adversarial test).
- Encryption at rest, Windows ACLs, same-OS-user process isolation, secure
  backup rotation, remote/distributed erasure receipts or production audit.
- Conversion of legacy schema-v1 rows with null expiration: they remain in
  raw archive storage and must be expressly handled by host migration policy.

SQLite documentation: [FTS5 secure-delete](https://www.sqlite.org/fts5.html),
[secure_delete pragma](https://www.sqlite.org/pragma.html#pragma_secure_delete),
and [WAL behavior](https://www.sqlite.org/wal.html). STM only enables FTS5
secure-delete on the locally tested SQLite 3.53.1+ range; older builds need a
strict fail-closed policy when forensic index erasure is mandatory.

**Acceptance rule:** A passing library suite qualifies source behavior only.
Do not label Vera's memory privacy/retention **runtime verified** until the
host integration checklist, explicit policy authority, real scheduler,
backup/log/source-journal lifecycle and independent device tests all pass.

