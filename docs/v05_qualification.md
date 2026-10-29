# STM v0.5 — Windows/Android and 30-day review qualification

Date: 2026-10-28. **Draft source candidate, not Vera installation or deep-memory export.**

## Scope and tested behavior

New, optional modules:

- `windows_host_auth`: named-pipe Windows account SID/ACL transport; working-only.
- `android_local_auth`: Linux peer UID plus injected Android app identity resolver;
  working-only, PackageManager and APK wiring not installed.
- `handoff_policy`: 30-day review eligibility, separate from expiry; bounded,
  content-free, in-memory review tickets; no durable transfer/retry ledger.
- `deepmemory_handoff`: injected host sink with exact source, long-term consent,
  target retention/deletion/revocation checks, version+target idempotency key,
  independently checked receipt; **not a real DMS writer**.

Independent security review reproduced an actual private-source-text leak in
the original review ticket representation; the ticket no longer stores that
field, and both focused and independent regression tests now pass.

## Direct tests on this source tree

1. `env PYTHONPATH=src python -m unittest discover -s tests -q`:
   **300 run, 0 failures, 8 skipped** (sandbox prevents seven live Linux
   socket binds, and the separate Windows-native test is not runnable here).
2. Fresh Python 3.12 virtual environment in `/tmp/stm_v05_clean_20261028`:
   `pip install --no-cache-dir -e .` built and installed
   **`stm-short-term-memory==0.5.0`**. Initial pip attempt was blocked by
   sandbox network access; an approved unrestricted retry succeeded.
3. Installed package, outside restricted socket sandbox:
   `env -u PYTHONPATH STM_REQUIRE_PEER_SOCKET_TESTS=1 .../bin/python
   -m unittest discover -s tests -q`: **300 run, 0 failures, 1 skipped**.
   Seven actual Linux peer socket tests ran; one Windows-native test remained
   skipped because this test machine runs Linux.
4. Installed-package synthetic example `examples/handoff_review_mock.py`:
   exit 0; emitted `REVIEW_READY, SYNTHETIC_IN_PROCESS_RECEIPT_ONLY,
   SOURCE_UNCHANGED`. It did not contact Vera or DMS.
5. `benchmarks/bench_stm.py` exited 0. Synthetic fixture retained all 16/16
   exact targets against sliding 0/16 and recency 8/16; measured UTF-8 byte
   context savings relative to 50,158-byte full history: **92.01%**. This
   does not measure backend inference latency, model tokens, production chats
   or KV-cache tensors.

## Source/runtime/retention boundaries

- User's **tentative** 30-day transition is coded as review eligibility, not
  adopted max retention, export consent, or automatic promotion. A 30-day
  hard source expiry would make a day-30 read-and-export impossible; a new
  explicit bounded policy choice must reconcile review and expiry.
- The public append-only `thebrazenbeard/deepmemorystorage` Git repository
  cannot be used as a private conversation destination and has no verified
  authenticated write API or deletion guarantee. No live DMS data was changed.
- Windows native named-pipe roundtrip **passed** on the Windows GitHub runner
  during the initial v0.5 CI. The same run uncovered an unrelated test
  resource-lifetime issue (raw SQLite diagnostics were not closed) and an
  Android test import guard bug; those fixes require a full Windows recheck.
  This establishes a narrow native OS test, not real VeraOS identity mapping.
  Android PackageManager
  resolver and APK/runtime are synthetic/unbound, not device-verified.
- No real user sign-in/consent broker, OS key store, cross-device pairing,
  protected file storage for Windows, durable review queue, installed cleanup
  scheduler, original Vera transcript erasure, or complete backup deletion
  has been demonstrated.
- A revoked consent *during* transmission can yield an unverified outcome,
  not retraction of bytes already delivered. A real destination requires a
  separately tested compensating delete/revocation protocol.

The exact tested remote source revision, its tree, and OS matrix results are
recorded in the Draft PR after GitHub publication; source tests are not
production runtime qualification.
