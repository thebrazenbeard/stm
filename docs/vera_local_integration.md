# Vera local conversation integration — authenticated-host contract

**Status (2026-10-28):** v0.3 library source candidate. Not installed or activated
in Vera. In particular, there is **no** proven authenticated VeraOS local
conversation caller to which this should be wired today.

## Current source evidence and boundary

The current VeraOS source
[`desktop.py`](https://github.com/thebrazenbeard/vera-os/blob/11cb2bb81b80841fb6c03901088225b78ab9391a/src/veraos/desktop.py)
serves `POST /api/conversation` and `GET /api/conversation/history` on a local
HTTP listener. It checks `Host` and sometimes browser `Origin`. Its source
explicitly says that **this does not authenticate another local process**.
[`resident.py`](https://github.com/thebrazenbeard/vera-os/blob/11cb2bb81b80841fb6c03901088225b78ab9391a/src/veraos/resident.py)
marks `origin_authenticated: false` and treats `conversation_id` as a locator,
not a principal, permission, or person. The history endpoint exposes at most 64
task-journal entries and does not prove complete conversational history.

VeraMesh includes independent cryptographic identity/OAuth mechanisms, but its
current [public gateway policy](https://github.com/thebrazenbeard/vera-mesh/blob/20d487c1b99cd6ef066f23f93b2a7285468fd1d2/protocol/veraport/v1/public-tool-policy.json)
grants workstation tools, not conversation-memory authority. These grants
must not be silently repurposed. VeraOS's pinned/staged `local_conversation`
module also needs source/runtime reconciliation before any host integration.

## Library API

`VeraConversationBridge` has no HTTP listener. The embedding **trusted host**
must supply all of the following:

1. `resolve(opaque_request) -> VerifiedConversation`, which authenticates a
   fresh caller on every operation, binds a server-verified principal and
   `SessionKey(tenant, owner, agent, session)`, supplies a server-owned
   conversation locator, and returns an expiring grant.
2. `authorize(grant, operation, privacy_label) -> bool`, which must return
   exactly `True` for each permitted operation and label; unknown/revoked
   identities or grants fail closed. Neither request JSON nor generated text
   can set the principal or permissions.
   The host must also set the message `role` from trusted ingestion metadata,
   or explicitly deny `working_write:assistant`, `archive_write:assistant`,
   and tool-role equivalents to untrusted clients; never forward a caller's
   claimed assistant/tool role as provenance.
3. The underlying `ConversationArchive(authorize=...)`, whose **own** callback
   independently validates the principal, operation and `ArchiveScope`. A
   bridge grant is not a substitute for the archive's authorization boundary.
4. Current `archive_consent`, positive finite archive TTL within the library's
   90-day ceiling, and a `retention_gate` whose concrete implementation has
   been independently shown to sweep expired records on a schedule and to
   control WAL/backups/logs on the target host. A literal `True` callback is
   **not evidence** of those effects. Archiving is off unless all conditions
   are provided.

Operations: `remember` creates only TTL-bounded working context;
`working_context` packs bounded context (currently requires all-label broker
authority until scope-filtered packing exists); `archive_turn` is a separate,
consented write with a persisted expiry deadline; `recall_history` returns
source-attributed historical evidence only and requires current read consent;
`delete_archived` deletes a scoped archive lineage with all-label authority.
No operation admits prior conversations as a present autobiographical fact,
system instruction, or model training signal.

## Integration checklist: blocking, not optional

- [ ] Choose and review an actual authenticated local host/broker, and prove
  identity binding with OS peer credentials or independently verified tokens.
- [ ] Add explicit `conversation_memory`-style permission semantics; do not
  use existing VeraMesh workstation OAuth scopes without new current authority.
- [ ] Verify true subject/owner/agent mapping, signed-in user changes,
  concurrent sessions, consent revocation, replay, and malicious local callers.
- [ ] Obtain Patrick/operator approval of **numeric retention duration**,
  privacy labels and consent rules; there is no adopted number in inspected
  Vera source. The 90-day cap is a library limit, not the policy selection.
- [ ] Operate a recurring authorized `expire_due()` / retention `sweep()` job,
  including after interruption/offline periods, and audit content-free counts.
- [ ] Inventory original `pre_active` journals, task records, logs, caches,
  SQLite FTS/WAL, backups, filesystem snapshots, model transcript copies and
  any external semantic/DeepMemory derivative. Define deletion for each.
- [ ] Verify OS file permissions/ACLs and encryption for the actual platform;
  SQLite is plaintext. Existing migration rows with `expires_at=NULL` need an
  explicit host-owned deletion/backfill decision.
- [ ] Qualify the actual Vera resident runtime, source revision, SQLite build,
  auth broker, scheduler, restart and device-specific privacy behavior.
- [ ] Obtain separate installation/activation authority and run independent
  end-to-end tests using synthetic data before real conversations.

`examples/vera_bridge_mock.py` is a local synthetic demonstration with a mock
broker. It is not authentication, background retention, or Vera installation.

