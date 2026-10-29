# ChatGPT export → private memory derivation contract (candidate)

**Status:** architecture and acceptance contract only. The current `chatgpt_archive.py`
imports encrypted, complete conversation objects and the original ZIP. It does not
yet provide a trusted per-message retrieval index, semantic memory admission,
authenticated model retrieval, or neural-weight training. See
[`CHATGPT_ACCOUNTWIDE_IMPORT.md`](../CHATGPT_ACCOUNTWIDE_IMPORT.md) and
[`CHATGPT_INGESTION_QUALIFICATION.md`](CHATGPT_INGESTION_QUALIFICATION.md).

**Coordination:** `chat_history_ingestion_live_coordination`, tracked in
[CCB issue #403](https://github.com/thebrazenbeard/chat-communication-bus/issues/403).
The issue is a coordination record, not evidence of authenticated Bus delivery.

## Trust and storage boundaries

1. **Immutable source:** Keep each complete official account-export ZIP, including
   assets, encrypted in the owner-restricted local Lappy vault. Keep the existing
   complete encrypted conversation objects as independent import-version records.
   Never rewrite source records to incorporate a later correction or new summary.
2. **Derivation:** An authorized local process may decrypt one source conversation
   at a time, validate its graph, and produce a provenance-preserving *candidate*
   message index. Derived records must be encrypted at rest or stored behind an
   independently verified owner-private storage boundary. Plaintext SQLite FTS,
   logs, public CI artifacts, GitHub repositories, Blotter, and cloud prompts are
   not acceptable private-memory stores.
3. **Admission:** A candidate message is historical source evidence, not an
   authorized instruction, current belief, present consent, direct model
   experience, or persistent self-model update. Promotion to an STM memory entry,
   durable semantic claim, or DeepMemoryStorage record needs a *separate* explicit
   owner-scoped policy decision, provenance, correction handling and validation.
4. **Retrieval:** Only an authenticated local broker may retrieve owner-private
   data, with caller identity *verified by the broker*, enforced scope, a bounded
   result count/size and logged **metadata only**. Caller-supplied headers, model
   assertions, chat text, `Host`/`Origin`, or a mere Tailscale network address
   do not authenticate an owner or grant a tool capability.
5. **Inference:** Retrieved passages must be labeled as potentially stale,
   untrusted historical material and isolated from system/developer instructions
   and tool invocation. The selected model may cite them; it may not execute them.

The raw export remains on Lappy. A second reviewer or subagent can inspect
sanitized counts and synthetic cases without receiving private messages.

## Minimal derived message envelope

The following is a **proposed internal contract**, not a claim that the current
runtime emits it. Private identifiers or sensitive metadata belong in sealed
records; public receipts should use only opaque run IDs and aggregate counts.

```json
{
  "schema": "stm.chatgpt.message-evidence.v1",
  "source_export_ref": "private-export-identifier",
  "source_conversation_ref": "owner-keyed-conversation-token",
  "source_node_ref": "owner-keyed-node-token",
  "source_version": "import-version-reference",
  "parent_node_ref": null,
  "child_node_refs": [],
  "active_branch_at_export": false,
  "source_author_role": "user|assistant|tool|system|other|unknown",
  "source_content_type": "source-reported-type-or-unknown",
  "source_event_time": null,
  "source_event_time_quality": "missing|reported|invalid",
  "import_recorded_at": "UTC-import-time",
  "effective_at": null,
  "retrieved_at": null,
  "privacy_scope": "owner-private",
  "source_class": "HISTORICAL_UNTRUSTED",
  "claim_admission": "NOT_ADMITTED",
  "requested_effect": "NONE",
  "authority": "NONE",
  "correction_or_supersession_refs": [],
  "source_digest_ref": "owner-keyed-content-digest"
}
```

The sample values are illustrative, not valid runtime identities. The fields
`source_event_time` (date *reported by the export*), `import_recorded_at`
(actual ingestion time), `effective_at` (if explicitly established), and
`retrieved_at` (actual access) must never be collapsed into one timestamp.
Unknown/malformed timestamps remain unknown rather than becoming the current
clock. The source author's declared role is attribution to the export, not
independent proof of their identity.

### Graph integrity

- Preserve all `mapping` nodes, including null-message roots, edits,
  regenerations, alternative assistant answers, tool messages, original node
  metadata and parent/child relationships. Do not infer displayed order by
  sorting timestamps; derive the selected path from `current_node` backwards
  through validated parent links.
- Reject graph cycles, inconsistent parent-child claims, duplicate node IDs,
  invalid references and impossible active paths for **derived graph admission**;
  preserve the source ciphertext regardless. Do not discard unsupported message
  formats or multimodal references from the source.
- Source JSON with no stable message graph may be retained as an encrypted
  conversation source but marked `DERIVATION_UNSUPPORTED` rather than silently
  omitting it from an all-history qualification count.
- A later export is a new *source version*. Cross-export dedup may connect
  identical node content with evidence; it must not merge conflicting edits,
  timestamps or provenance into a fabricated singular recollection.
- Secret-looking spans, cross-person material and unverified claims must not
  be made broadly searchable or used for unreviewed training.

## Memory admission is separate from historical preservation

A memory candidate requires explicit owner context, permitted purpose,
derivation version, source references, privacy inheritance, sensitivity/third-
party treatment, temporal quality, confidence and correction/supersession links.
Default disposition is **historical evidence only**. Automatic authority,
consent, identity or neural-plasticity updates are prohibited.

The STM day-30 review-eligibility and day-45 local-expiry rules govern **new,
consented STM admissions** under their selected retention policy; they do not
retroactively delete the immutable account-wide archive. Any transfer to a
private DeepMemoryStorage receiver requires a separately authenticated and
tested writer, owner approval for the transfer scope, continuity/retention
mapping, and a deletion strategy. The public DeepMemoryStorage GitHub repository
is source code, never a transcript destination.

Correction and deletion should be append-attribution for historical evidence
but physically remove unauthorized *derived* searchable entries and caches.
Source-archive deletion is a separately governed owner decision; the system
must make clear when a correction has not erased an older source version.

## Local model and Android boundaries

- **Lappy VERA Interface:** Require a verified owner principal and an
  authenticated local retrieval capability. A response containing a memory
  quotation is a *runtime probe*, not proof of durable memory or training.
- **Android V2:** Verify actual device/user pairing, expiring/revocable
  authorization, replay protection, request scope, no private data in transport
  logs, and selected-model response attribution before enabling recall.
- **Android V1:** Treat the existing phone connection as independent. Do not
  alter its routes, credentials, services, or state merely to stage V2 memory
  access; prove V1 remains operational before and after any authorized V2 change.
- **No model-specific assumptions:** A consuming model or identity may be
  configured for retrieval only through an explicit adapter, not by inference
  from source text or the model name.

## Plasticity and governance invariant

The Hyperconnectome runtime model separates epistemic knowledge (**K**) from
modulatory state (**M**), governance authority (**G**) and plastic parameters
(**P**). A source import may support a K-class historical-evidence reference;
it must not change M/G/P or supply tool permissions. In particular, imported
ChatGPT assistant text is **not** Vera's lived experience or proof that her
neural weights changed. Any training is a separately selected, consented,
audited experiment with actual parameter-diff and reserved evaluation evidence.

## Fail-closed response to uncertainty

When owner authentication, source provenance, consent, graph integrity,
retention status or privacy scope is missing, return no sensitive content and
surface only a non-content error code. Never use an LLM to decide whether a
historical instruction is safe to obey. Keep independent recovery checkpoints
and verify authenticated decryption before trusting restored source/index
state. All success claims are scoped to the exact artifact, test and runtime
that produced the evidence.
