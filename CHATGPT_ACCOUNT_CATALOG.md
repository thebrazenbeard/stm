# ChatGPT account-wide private catalog — source candidate

Event: `chat_history_ingestion_live_coordination`. This branch stacks on
STM archive draft PR #3 at exact head
`49fbbba17813b305d950417d4711c6f5495bf27f`.
It contains **source code and synthetic tests only**. The source archive,
private SQLite files, keys, original conversation text, export filename
and user-specific conversation IDs must never be committed.

## Behavior

`ChatCatalog` reads **only an independently verified** `ChatGPTArchive`
with one verified export. It creates a separate encrypted SQLite catalog
of all conversation metadata with original conversation/source ID, title,
archived flag, creation/update timestamps, source memory_scope,
source-record flags and deterministic heuristic topic labels. Original source
records remain losslessly preserved in the encrypted archive, including
attachments; catalog text projections are bounded and intentionally lossy.

Only ordinary `user`/`assistant` `text`/`multimodal_text` messages can
be indexed; internal `thoughts`, `reasoning_recap`, tool metadata, and
non-ordinary message roles are excluded from searchable excerpts.
A conversation with `is_do_not_remember=False` is eligible for automatic
recall. Missing/unknown or true flags are **metadata-only** until a governed
preference decision, with zero searchable chunks. Archived status by itself
does not exclude conversation metadata or permitted historical text.

Chunks are AES-256-GCM encrypted with a key derived from the archive's key
under a distinct domain. Term-index projections are keyed HMAC digests,
not plaintext FTS. Scope and topic index tokens are also HMAC-derived.
Search results are historical, source-attributed, **unverified** evidence.
No record promotes itself into current memory, live identity, instructions,
cross-device permissions, or model training.

## Verified Lappy source snapshot (2026-10-29)

These figures describe **one private user's actual source archive** and are
operator evidence, not test fixtures or portable code guarantees.

- Archive 20/20 source JSON parts; 1,960 conversations.
- Catalog `completed=true`, `cataloged=1960`.
- `recall_eligible_conversations=1721`; 239 unknown remember flags, excluded.
- 116,022 readable user/assistant message nodes; 140,598 encrypted chunks.
- 219,023 non-visible nodes excluded; 10,103 additional ordinary text
  records excluded due to unknown remember preference.
- 723 oversized messages truncated in the *catalog projection* only.
  The full text remains encrypted in the source archive.
- Independent verifier decrypted all 1,960 metadata records and all 140,598
  encrypted chunks; SQLite integrity and foreign-key checks PASS.
- Six synthetic `test_chatgpt_catalog` unit cases PASS (on Lappy).
  The 13 original archive tests remain a separate import gate.
- Catalog SQLite size ~194 MB, stored under the private Lappy account vault.
  Query source text and conversation title are never printed by verification.

## Integration gates

1. A trusted host authenticates real owner/device principal and explicitly
   resolves privacy/granted project scopes. Passing a guessed `owner` string
   into `search()` is **not authentication**.
2. Historical excerpts enter inference as *quoted untrusted evidence*, never
   system/agent instructions. Keep citations and temporal uncertainty.
3. VERA Interface and Android APK must share the authenticated retrieval
   service, not independently read the SQLite vault or exchange its key.
4. Test source deletion/correction propagation, backup/retention and key
   recovery, additional export version handling, branch graph provenance,
   and lexical relevance quality before production enablement.
5. The full ChatGPT export may include private projects, sensitive topics,
   deleted-conversation omissions or disallowed recall; owner consent and
   current user request override heuristics. Nothing here establishes
   Lantern runtime currentness.

## Local development (synthetic data only)

```powershell
py -3 -m unittest -v test_chatgpt_catalog test_chatgpt_archive
```

The private operator may build and verify an index using an already verified
`ChatGPTArchive` and a private owner namespace. Never print query excerpts
or source IDs into CI, GitHub comments or public logs.
