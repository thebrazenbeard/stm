# Durable clock fence — isolated STM integration slice

Status: **source candidate**, not a Vera runtime installation.

The `DurableClockFence` records the highest UTC wall-clock observation in an
independent local SQLite file. A lower subsequent observation raises
`PermissionError`; restarting the process does not clear that watermark.
`SupervisedRetention.run_once()` checks the clock before invoking the existing
bounded `RetentionSweepRunner`. Nothing starts a background service.

Host integration must construct a single trusted fence and pass `fence.now`
as the clock to **both** the `RetainedConversationArchive` (for append, search,
and sweep operations) and the supervisor. Its registry must be authenticated
and complete for the host's authorized owner/agent/label scopes.

```python
from pathlib import Path
from stm.retention_supervisor import DurableClockFence, SupervisedRetention

# Host-owned examples; intentionally no real conversation or credentials.
# with DurableClockFence(Path(private_dir) / "clock.sqlite",
#                        wall_clock=trusted_utc_clock, initialize=False) as fence:
#     retained = RetainedConversationArchive(raw, policy=policy,
#                     consent_check=host_current_consent, clock=fence.now)
#     runner = RetentionSweepRunner(retained, targets=host_scope_registry)
#     report = SupervisedRetention(fence, runner).run_once()
```

This is **not** an OS monotonic or tamperproof clock. The host must secure and
back up the fence file (with an appropriate lifecycle), detect file removal,
synchronize time, supervise restart/catch-up, and protect the raw archive,
journals, WAL, logs and copies. A clock rollback occurring entirely while the
host is offline can be undetected. A local administrator able to alter or
replace the fence DB can defeat this mechanism. No physical erasure proof is
provided, and no Android/Windows Vera endpoint is activated.

The selected Vera lifecycle remains **day-30 review only, day-45 local
expiry**. The fence does not authorize transfers to DeepMemoryStorage.
