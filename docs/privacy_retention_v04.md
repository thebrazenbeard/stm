# STM v0.4 privacy and retention — verification boundaries

Date: 2026-10-28. **Status:** code candidate for review, not an installed
Vera memory policy or whole-conversation deletion system.

## Authority and configuration

The [Vera Memory and Privacy V2 source](https://github.com/thebrazenbeard/vera-control-plane/blob/6306f7009e933ed8a965146f9abf34a46caae490/project-instructions/native-v2/VERA_MEMORY_AND_PRIVACY_V2.md)
defaults sensitive/autobiographical material to private, separates historical
evidence from current identity, and prohibits unauthorized promotion to
training or other repositories. It does **not** provide an approved number of
retention days. The STM 90-day ceiling is only a new library maximum.

Archives remain opt-in. A real host must select a shorter concrete duration,
authenticate the user/issuer, authenticate current read/write consent,
provision signing and cleanup secrets, operate the scheduler and manage every
other transcript copy before enabling private conversations.

## Mechanisms and demonstrated source tests

| Risk | Implemented v0.4 control | Verification limit |
| --- | --- | --- |
| Claimed owner/agent or local `Origin` spoof | HMAC-SHA256 credential validates issuer, audience, subject, exact scope, per-role capability, expiry and trusted channel binding; bridge resolves once per operation | Synthetic issuer/channel; no actual VeraOS auth installed |
| Bearer replay, revoked consent | Fail-closed revocation callback; single-use mode requires a host **durable atomic** replay claim; current archive consent checked on recall/correction | Real revocation service and consent event wiring not installed |
| Role/provenance or mixed-privacy leak | Per-role write capabilities and private-label filtering before packed context, including pinned records | Host must bind role to trusted transport metadata |
| Long-lived stale history | Persisted per-turn expiration, correction deadline inheritance, query/sweep wall-clock floors; SQL excludes expired before ranking | Raw legacy NULL records need explicit migration decision |
| Unattended expiration after restart | `RetentionSweepRunner.run_once()` catch-up and supervised `run_periodically()`; bounded batches; distinct `expire` and `audit_legacy` permissions | Host scheduler/registry/secret not installed or running |
| Destructive maintenance impersonation | Separate cleanup secret and short lease authorizing only scope+label `expire` and legacy audit, never arbitrary hard delete | Operator must secure service process and credential store |
| SQLite backup cross-owner export | Full-database vault requires archive-wide admin authority on **every** operation | Same-user compromise, Windows ACLs and external copies unqualified |
| Snapshot retaining expired/policyless content | Preflight before copy, post-copy validation, earliest-turn deadline cap, bounded registered-copy retirement and backlog receipts | Concurrent write race may create a transient rejected copy; no forensic erase guarantee |
| Consent deletion across copies | `retire_all(reason=...)` can retire known managed backups, with explicit remaining count | Not invoked automatically and never reaches unmanaged backups/snapshots |

`SweepReport.complete` means **complete for the provided trusted scope registry
and specified privacy labels**, including zero legacy rows within them. It
does *not* mean every tenant, label, original Vera journal, checkpoint, backup
or filesystem copy has been erased. A host missing a scope/label from its
registry must not claim store-wide coverage.

`ConversationArchive.purge_legacy_unretained()` defaults to dry-run and needs
explicit `delete_legacy` **and** delete authority. The regular scheduler
cannot silently purge policyless legacy evidence.

## Host and storage gaps

- VeraOS current loopback conversation HTTP still does **not** authenticate
  callers. Linux `SO_PEERCRED` prototype authenticates OS processes in tests,
  but no Windows/browser/session identity mapping or Vera resident hook exists.
- Standard SQLite backups/FTS/WAL are unencrypted plaintext unless the host
  controls the disk/key environment. SQLite `secure_delete` is not a guarantee
  for external FTS/WAL copies or old filesystem blocks. FTS5 secure-delete is
  only enabled on the locally qualified SQLite 3.53.1+ range.
- The managed backup vault is POSIX-only and copies the **whole** database.
  It does not inventory other hosts' snapshots, Vera's canonical task/PreActive
  journals, logs, prompts, embeddings, DeepMemory or training derivatives.
- No numeric policy duration, consent policy revision, live scheduler audit,
  encryption key store, backup retention job or production installation has
  been approved/verified in Vera.

Upstream SQLite documentation: [backup API](https://www.sqlite.org/backup.html),
[WAL](https://www.sqlite.org/wal.html),
[FTS5](https://www.sqlite.org/fts5.html).

