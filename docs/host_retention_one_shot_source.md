# Host-operated STM expiry: one-shot source candidate

**Status:** bounded, offline source mechanism only. No installed task,
Windows service, Android producer, current user identity, DMS writer,
personal transcript, or forensic-erasure qualification.

The selected Vera policy is **day-30 review eligibility** and **day-45
local source expiry**. No automatic transfer to DeepMemoryStorage.

A trusted host must supply and independently verify all of:

1. An authenticated current principal and complete tenant/owner/agent and
   privacy-label registry; no caller-supplied string is an identity.
2. A private, protected local SQLite archive, a durable clock fence that
   also governs retained reads and writes, and a retention policy that
   cannot quietly exceed 45 days.
3. An OS-owned scheduler or process supervisor with least-privileged
   service identity, restart/catch-up, failure monitoring and a protected,
   content-free audit-record destination.
4. An independent deletion lifecycle for source chat journals, SQLite
   checkpoints/WAL, historic snapshots, backups and model/runtime copies.

`run_guarded_once(supervisor, record=host_audit_callback)` runs a single
bounded pass. It invokes only a previously constructed `SupervisedRetention`
and records the immutable, **content-free** `SweepReport`. It raises
`IncompleteSweep` after writing that report whenever a bounded backlog or
unretained legacy row remains. An audit write error propagates. Already
deleted rows remain deleted and a retry is safe. An empty registry fails
closed in the underlying `RetentionSweepRunner`.

**Do not report completion** merely because a scheduled process exited
without throwing an unrelated exception. A host should fail/alert when
`IncompleteSweep` is raised, verify registration and principal identity on
every actual task, and retry bounded catch-up until verified.

Synthetic verification only:

```text
PYTHONPATH=src python -m unittest discover -s tests -p test_host_retention_one_shot.py -v
PYTHONPATH=src python examples/host_retention_one_shot.py
```

The example uses only a disposable temporary directory and fictional
message. It does not create a scheduled task or read `D:\\VERA`.

Windows Task Scheduler context: Microsoft documents that tasks run under
their configured principal and may be least-privileged; scheduling by itself
does not authorize access to a user's conversation history:

- https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks
- https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal

**Limit:** logical expiry is not forensic deletion. Production host
installation, backup lifecycle and cross-device consent must be qualified
separately, with live readback before archival is enabled.
