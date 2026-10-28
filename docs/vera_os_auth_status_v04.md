# VeraOS authenticated conversation seam — remaining integration work

Status: **source exploration and authenticated standalone prototypes; VeraOS
host not modified or installed**. Date: 2026-10-28.

Exact inspected subjects:

- [vera-os@11cb2bb](https://github.com/thebrazenbeard/vera-os/blob/11cb2bb81b80841fb6c03901088225b78ab9391a/src/veraos/desktop.py):
  local HTTP POST/GET conversation handlers check Host/Origin but do not prove
  the caller's identity. `conversation_id` is an untrusted locator.
- [resident.py at same revision](https://github.com/thebrazenbeard/vera-os/blob/11cb2bb81b80841fb6c03901088225b78ab9391a/src/veraos/resident.py):
  `origin_authenticated:false` and direct task-journal readback. No verified
  individual principal or STM admission contract.
- VeraOS imports `vera_core.local_conversation`, absent from the checked
  canonical Vera Mono `main` and cited staged immutable subject. Resident
  source/runtime dependency must be resolved before replacing handlers.
- VeraMesh's [OAuth tool policy](https://github.com/thebrazenbeard/vera-mesh/blob/20d487c1b99cd6ef066f23f93b2a7285468fd1d2/protocol/veraport/v1/public-tool-policy.json)
  has no conversation-memory scope. Its workstation grants are not STM grants.

## Demonstrated alternatives, not automatic VeraOS integration

1. `HmacConversationBroker` verifies signed credentials with per-operation
   authority and authenticated-channel binding. A trusted host still must
   authenticate the person/OS session **before** issuance; client JSON,
   browser Origin/Host and a caller-generated binding are not evidence.
2. `stm.linux_peer_gateway.PeerMemoryGateway` can accept Linux `AF_UNIX`
   connections and ask the **kernel** for `SO_PEERCRED` UID/PID/GID. It binds
   a host-approved UID to working-only STM scopes. Real kernel-socket tests
   ran on Linux. It cannot authenticate browsers, people, distinct processes
   sharing a UID, or Windows VeraOS sessions; archives stay off.
3. `ScopedCleanupAuthority` is separate from interactive credentials. Its
   short-lived scope-bound principal may perform expiry/legacy audit but not
   content retrieval, unrelated delete, or append. A verified host service
   must acquire that principal from a protected independent secret and
   supervise `RetentionSweepRunner` on startup and periodically.

## Actual installation gate

- Determine Vera's **real OS/runtime** and canonical resident dependency.
- Select and implement a trusted browser/desktop authentication design:
  OS peer credential, properly ACLed Windows pipe, or independently verified
  token issuer. Test role/subject/tenant/session binding and local attacker
  paths. Never install a private-memory handler on current unauthenticated
  `/api/conversation/history`.
- Obtain approved numerical TTL and current consent semantics; choose privacy
  labels and a maintained host registry, not guessed values.
- Configure separate private signing, revocation/replay and cleanup-service
  authorities; schedule catch-up and monitor incomplete reports.
- Map deletion across original Vera journals, prompt caches, managed and
  unmanaged backups, WAL, filesystem snapshots and external derivatives.
- Run independent system tests on **the real Vera host** using only synthetic
  transcripts first; review and authorize activation separately.

Until then, claim **STM source and standalone Linux socket runtime tests**,
not authenticated VeraOS connection or retention effect on Patrick's data.

