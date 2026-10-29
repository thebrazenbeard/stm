# STM v0.4 source verification / native parallel work

Date: 2026-10-28. Built on the reviewed v0.3 STM source candidate.

## Executed engineering evidence

- `PYTHONPATH=src python3 -B -m unittest discover -s tests -q`:
  **233 tests passed, seven OS-socket cases skipped by the workspace sandbox**.
- `STM_REQUIRE_PEER_SOCKET_TESTS=1 PYTHONPATH=src python3 -B -m unittest
  discover -s tests -q` outside the restricted socket sandbox:
  **233/233 passed including actual Linux `SO_PEERCRED` socket tests**.
- The same **233/233 passed** using `/usr/bin/python3` and its older SQLite
  runtime with the kernel socket test requirement enabled.
- Fresh virtualenv `/tmp/stm_v04_verify_20261028` built and installed
  `stm-short-term-memory==0.4.0` from source without runtime dependencies.
  With `PYTHONPATH` unset, its actual `site-packages` copy passed **233/233**
  tests including socket cases on the qualified Linux test host.
- `PYTHONPATH=src python3 -B examples/authenticated_host_demo.py`: exit 0;
  synthetic signed request, wrong-channel denial and explicit expired cleanup.
- `git diff --check`: exit 0.
- The GitHub Actions matrix and final published commit/tree are recorded
  separately after review publication; source tests must not be attributed
  to a still-unmerged or uninstalled Vera runtime.

Seven native children ran over two waves (six simultaneous maximum): host
authentication source/prototype, signed credential broker, host-run retention
scheduler, backup privacy subsystem, end-to-end contract engineer, security
red-team, and independent integrator review. All returned concrete findings.
Independent reviews reproduced multiple high-impact flaws, including
cross-tenant snapshots, retention extension by backups, unrestricted cleanup
deletion, replay after broker restart, incorrectly complete legacy sweeps,
and insufficient archive-wide administrative controls. Fixes were checked in
the final combined suite; synthetic tests only.

## Separate outcomes

1. **Source engineering:** documented auth, retention, backup and Linux peer
   gateway modules with synthetic/standalone tests.
2. **Independent verification:** current tests and hostile review passed
   within the declared source/runtime test environment.
3. **Source review:** Draft PR link, exact commit/tree and CI separately
   qualify only the published candidate.
4. **Installed VeraOS integration:** NOT DEMONSTRATED. Current HTTP has no
   authenticated caller boundary and canonical resident dependency differs
   from the source tested in its private Windows stage.
5. **Private-memory retention effect:** NOT DEMONSTRATED. No personal dialogue,
   live scheduled cleanup, backup purge, OS key/ACL, or source-journal deletion
   was executed.

