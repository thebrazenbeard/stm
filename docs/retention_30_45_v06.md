# Vera STM — selected 30/45 conversation-history lifecycle

Selection: Patrick chose **option 1** on 2026-10-28.
**Status:** policy source candidate; not a deployed Vera service or a
retroactive modification of conversation history.

## Selected timing

| Age from original local archive admission | Local action |
| --- | --- |
| Day 0 | Admit an opt-in conversation turn with an explicit local deadline of day 45. Current host consent and scoped archive authority are required. |
| Before day 30 | Short-term and historical retrieval are governed by ordinary privacy and authorization; the turn is not ready for deep-memory review. |
| Day 30 through before day 45 | Review eligibility only, with fresh source authority and consent. A separately verified private destination, exact target-retention consent and receipt are mandatory for any actual export. |
| At and after day 45 | Source is no longer retrievable. The authorized host retention sweeper must delete expired local rows. Pending review or a failed export never pauses or extends this deadline. |

**If no private DeepMemoryStorage destination becomes available, the local
copy still expires.** Review is not a promise of successful transfer. Do not
copy any private transcript into the public append-only
`thebrazenbeard/deepmemorystorage` Git repository.

## Enforced and host-owned boundaries

- An explicitly selected policy must bind **both** `RetentionPolicy` maximum
  source age (45 days) and `HandoffPolicy` review age (30 days). The generic
  library's 90-day ceiling is not the adopted Vera duration.
- A real host must bind the `VeraConversationBridge` archive credential and
  `VerifiedRetentionGate` to the same 45-day maximum. The
  `ThirtyFortyFiveWindow.vera_bridge(...)` factory constructs a guarded
  bridge against the **same** underlying archive used by its
  `retained_archive(...)` wrapper, rejects 46-day grants and invalid clocks,
  rechecks the retained wrapper's current consent before every bridge write
  **and historical read**, revalidates the wrapper's policy on each call,
  and requires an independent `verify_enforcement` callback supplied by a
  trusted host. That callback is an assertion to be audited, **not proof**
  that a Vera scheduler has been installed. The bridge writes through raw
  `ConversationArchive`; never hand untrusted services that raw handle or
  bypass the guarded factory.
  The consent check and raw-archive database write are separate operations;
  atomic revocation enforcement still requires the host archive authorizer
  to check current consent at write time. The strict read gate also requires
  a positive archive-retention duration in read credentials.
- Day 45 is a *logical* visibility cutoff even when cleanup is overdue;
  durable physical deletion requires supervised, regularly run
  `RetentionSweepRunner`, a complete authenticated scope registry, restart
  catch-up, and monitoring. Legacy NULL-expiry records require separate
  explicit migration authority and are not silently assigned 45 days.
- SQL/FTS/WAL, unmanaged copies, backup vault receipts, source Vera task
  journals, checkpoints, swap and future DMS derivatives remain separate
  deletion obligations. Application expiry is **not** forensic erasure.
- Corrections inherit their predecessor's expiry; they cannot reset day 45.
  The existing review policy counts a corrected version's **own** recorded
  admission age. A late correction may therefore be deleted at day 45 before
  it reaches 30 days of review eligibility. This conservative behavior avoids
  silently treating newly corrected text as older evidence. It is a stated
  limitation requiring a separately governed lineage policy if changed.
- The host must use a bounded trusted clock. A future-skewed injected clock
  must not set an expiry beyond 45 days after SQLite's actual recorded time.
  The selected factory rejects a clock more than one second from the observed
  UTC wall clock and clamps admitted future drift; raw archives do not.
  A **system-wide wall-clock rollback** may still reexpose previously expired
  but unswept rows until the clock catches up. Vera must use a trustworthy
  monotonic deadline mechanism or a persisted nondecreasing time watermark
  across restart; the current source factory does not claim that guarantee.
- There is no durable review discovery/enumeration service: the in-memory
  queue cannot reconstruct all day-30 candidates across restart, and the
  public archive API does not enumerate them by due date. A protected host
  candidate registry or a separately authorized scoped enumeration path is
  required for scheduled review.
- No automatic long-term write, durable review queue, model training,
  identity update, or Vera runtime installation is authorized by this choice.

The source implementation and synthetic tests are for the host integrator to
exercise. Activation requires a real user/session authenticator, a consent
store, a secure private historical destination, and a verified running
scheduler. These are not established by a passing local test suite.
