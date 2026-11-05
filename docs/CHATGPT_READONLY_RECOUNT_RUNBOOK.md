# Private ChatGPT export: read-only recount and transport triage

Status: **SOURCE-CANDIDATE / SYNTHETICALLY TESTED, NOT INSTALLED OR RUN ON THE REAL EXPORT**.

## Why this exists

`ChatGPTArchive.__init__` runs SQLite schema initialization, even for its
verification modes. An existing, owner-restricted vault should not need a
write-capable handle just to compare its index to the original export. The
standalone `chatgpt_readonly_recount.py` uses the same record-recount algorithm
but opens the preexisting index in SQLite `mode=ro` and enables `query_only`.
The read-only view also rejects inherited import/encrypted-copy methods rather
than exposing those filesystem-writing operations to an operator by accident.
It refuses a missing vault/index, wrong key, ambiguous multiple verified
exports, changed source ZIP, missing indexed records or mismatched counts.

The operator must still verify trusted source-checkout SHA, key/vault access,
Windows ACLs, and one intended source ZIP before starting. A read-only SQLite
connection is **not** a sandbox against arbitrary Python code or concurrent
writers; this script itself opens no write-capable database connection.

## Synthetic qualification (do first)

From the exact reviewed STM source checkout with pinned dependencies:

```powershell
py -3 -B -m unittest test_chatgpt_readonly_recount -v
py -3 -B -m unittest discover -s . -p 'test_chatgpt*.py' -q
```

The test suite generates fictional conversations in temporary directories;
it checks that an SQL `UPDATE` fails against the read-only handle and that
missing/wrong-key/multiple-source/changed-source gates fail closed. It is not
a test of the actual private export or its owner ACL.

## Operator-controlled invocation (never from public CI)

With local variables set by the authenticated Lappy operator and confirmed
to resolve to the **one intended** archive, key and original ZIP:

```powershell
py -3 -B chatgpt_readonly_recount.py --vault-dir $PrivateVault --key-file $PrivateKey --zip $OriginalExport
```

This conducts a full original-source hash, streams every conversation JSON
shard for keyed record/index comparison, and hashes the original ZIP again.
It prints only sanitized counts, Boolean gate results and an exit status;
it does not print export hashes, conversation IDs, filenames, message text,
asset content or key material. A failed operation returns exit code 2 and
a generic JSON `FAILED` response. It does not repair anything.

The additional optional `--verify-ciphertext` mode also authenticates the
sealed full ZIP and every indexed ciphertext record; this adds significant
I/O and must be scheduled after confirming resource and no-overlap constraints.
Every report must state whether this option was actually used.

**Important precision limitation:** The existing source/index serializer uses
`ijson(use_float=True)`. Two source decimals that differ beyond binary64
precision can create the same indexed canonical JSON. Thus the recount
qualifies *the parser's indexed projection*, not byte-exact per-conversation
number lexemes. The separately sealed original ZIP and its SHA are the
byte-lossless source. A versioned Decimal-preserving migration is pending.

## Transport failure discrimination

Prior native-agent remote calls combining Remote Desktop Commander device
enumeration and WorkBridge operations stalled without a result. A separate,
**sequential** WorkBridge probe reached `LAPPY` and confirmed only presence and
size of the user-selected ZIP. These observations do not prove a source/index
error, network health over time, or a completed recount.

Run one bounded, read-only command at a time. Record the actual transport,
host identity, start/end time, command exit status and remote session ID. If
the tool returns a still-running session, poll **that session** rather than
relaunching the recount. Do not start an additional recount during another
index, backup, import or host maintenance job. If transport hangs, classify
as `TRANSPORT_UNKNOWN`, not `SOURCE_RECONCILIATION_FAIL`; do not guess or
attempt credential/tunnel reconstruction.

## Accepted evidence classes

| Observation | Evidence class | Permitted claim |
| --- | --- | --- |
| CLI tests green on a disposable fixture | TEST | Source contract behaves as tested |
| Lappy ZIP exists and size matches prior receipt | REAL_SYSTEM_PROBE | Presence/size only |
| Read-only recount exits 0 with counts and exact code head | REAL_SYSTEM_PROBE | Original-source/index projection reconciled in that run |
| Optional sealed verification exits 0 | REAL_SYSTEM_PROBE | Ciphertexts authenticated in that run |
| Windows/Android authenticated owner-to-model result | REAL_SYSTEM_PROBE | Separate and still-required recall qualification |
| A native agent critique | INTERNAL_MODEL_REVIEW | Possible defect/falsifier, not independent host proof |

No result automatically admits autobiography, changes identity, grants tool
authority, confirms Android V2 or updates neural weights. The public STM PR,
CCB event and Blotter must never receive raw private content or key paths.
