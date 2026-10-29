# STM v0.3 authenticated-host and retention source qualification

Date: 2026-10-28. Source candidate for review only. No actual Vera user
identity, running conversation endpoint, personal conversation, retention
schedule or backup lifecycle was accessed or modified.

## Verification evidence

The final testable implementation includes SQLite schema v2 with a transactional
v1 migration, persisted per-turn deadlines, query-time expiration, scoped
batched expiration, consent-gated retention wrapper, broker-bound STM bridge,
mock demonstration and independent adversarial tests.

- `PYTHONPATH=src python3 -B -m unittest discover -s tests -q`: **176 passed**.
- `PYTHONPATH=src /usr/bin/python3 -B -m unittest discover -s tests -q`:
  **176 passed** on the older system SQLite environment.
- `/tmp/stm_v03_verify_20261028/bin/python -m pip install --no-deps .`:
  v0.3.0 built and installed successfully in a fresh Python 3.12 virtualenv
  after network permission was available for isolated build dependencies.
- `env -u PYTHONPATH /tmp/stm_v03_verify_20261028/bin/python -B -m unittest
  discover -s tests -q`: **176 passed using the installed site-packages copy**.
- `PYTHONPATH=src python3 -B examples/vera_bridge_mock.py`: exited 0;
  synthetic cited recall, expiry deadline and unauthorized-handle rejection.
- `git diff --check`: exited 0.

## Independently discovered and fixed defects

1. Archived turns initially had no expiration timestamp despite a positive
   retention-gate callback. Fixed bridge to persist concrete `expires_at`.
2. Filtering expired results after truncating the top 100 FTS matches hid live
   evidence when 101+ expired high-ranked matches existed. Expiration and
   policy presence now filter in SQL **before** ranking/limit.
3. A rollback/explicitly backdated search time could resurrect unswept
   expired records. Archive SQL cutoff now floors at system wall time.
4. Broker archival consent revoked after write did not initially stop read.
   Current consent is now independently required on recall.
5. Bridge retention TTL initially bypassed the library's 90-day ceiling;
   bound and adversarially tested.
6. Schema-v1 `ALTER` and version bump were initially separately commit-able;
   migration now runs in one explicit SQLite transaction.

These source tests do **not** certify an actual broker, periodic cleanup, or
complete erasure. A copied SQLite backup demonstrably survives subsequent
deletion, and legacy v1 rows with null expiry require explicit host authority.

## Native agent execution

Seven real child workers were dispatched over two waves: six concurrent
specialists for interface research, privacy, retention, bridge, policy engine
and adversarial tests; then an independent reviewer after capacity freed.
All seven returned findings. Each production write surface had one owner
during parallel implementation and integrated changes were freshly tested by
the lead. Worker statuses are task-local evidence, not proof of an installed
Vera deployment.

## Release-state separation

- **Source:** testable STM v0.3 candidate.
- **Build:** installable v0.3.0 package in an isolated test venv.
- **GitHub review:** Draft PR only; revision and CI status recorded separately.
- **Installation:** no source observed in Vera's actual installed conversation
  host; **UNKNOWN / NOT DEMONSTRATED**.
- **Effect:** no personal local history ingested or retrieved; **NOT DEMONSTRATED**.

