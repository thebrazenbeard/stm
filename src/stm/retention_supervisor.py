"""Durable, local clock rollback fence for host-supervised STM retention.

No service is started. Protect the fence DB from deletion, replacement, and ACL
changes; these are external host responsibilities. A rolled-back wall clock
raises instead of making previously expired conversation turns visible again.
This only detects rollbacks behind the last observed instant, not an arbitrary
clock change that occurred while the host was offline.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3
from threading import RLock
from typing import Callable

from .retention_runner import RetentionSweepRunner
from .retention import RetainedConversationArchive


class DurableClockFence:
    """Transactionally persist the last observed UTC instant across restarts."""

    def __init__(self, path: str | Path, *, wall_clock: Callable[[], datetime],
                 initialize: bool = False):
        if not callable(wall_clock):
            raise TypeError("trusted host wall clock required")
        if type(initialize) is not bool:
            raise TypeError("initialize must be an explicit boolean")
        path = Path(path)
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise PermissionError("clock fence parent must be an existing private directory")
        if initialize:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except FileExistsError as exc:
                raise PermissionError("clock fence already exists; cannot reset") from exc
        elif not path.is_file():
            raise PermissionError("existing durable clock fence is required")
        if path.is_symlink() or not path.is_file():
            raise PermissionError("clock fence path must be a regular private file")
        self._wall_clock = wall_clock
        self._lock = RLock()
        self._db = sqlite3.connect(str(path), timeout=5, isolation_level=None,
                                   check_same_thread=False)
        try:
            self._db.execute("PRAGMA journal_mode=DELETE")
            if not initialize and self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='clock_fence'"
            ).fetchone() is None:
                raise PermissionError("clock fence schema missing")
            self._db.execute("CREATE TABLE IF NOT EXISTS clock_fence "
                             "(id INTEGER PRIMARY KEY CHECK(id=1), "
                             "microseconds INTEGER NOT NULL)")
        except BaseException:
            self._db.close()
            raise

    def now(self) -> datetime:
        instant = self._wall_clock()
        if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("trusted clock must return a timezone-aware datetime")
        instant = instant.astimezone(timezone.utc)
        delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
        value = ((delta.days * 86_400 + delta.seconds) * 1_000_000
                 + delta.microseconds)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT microseconds FROM clock_fence WHERE id=1").fetchone()
                if row is not None and value < row[0]:
                    raise PermissionError("clock rollback behind durable retention watermark")
                self._db.execute("INSERT INTO clock_fence(id, microseconds) VALUES(1, ?) "
                                 "ON CONFLICT(id) DO UPDATE SET microseconds=excluded.microseconds",
                                 (value,))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return instant

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "DurableClockFence":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class SupervisedRetention:
    """One bounded host-triggered sweep, with durable rollback preflight.

    The host MUST also inject `fence.now` into the archive's retention clock,
    and separately schedule, restart and monitor this one-shot runner.
    """

    def __init__(self, fence: DurableClockFence, runner: RetentionSweepRunner):
        if not isinstance(fence, DurableClockFence):
            raise PermissionError("durable retention fence required")
        self._fence = fence
        self._runner = runner
        self._check_clock_binding()

    def _check_clock_binding(self) -> None:
        """Reject an unfenced archive, including changes after construction."""
        runner = self._runner
        if not isinstance(runner, RetentionSweepRunner):
            raise PermissionError("real policy-controlled retention runner required")
        retained = runner._archive
        if not isinstance(retained, RetainedConversationArchive):
            raise PermissionError("policy-controlled archive required")
        clock = retained._clock
        if (getattr(clock, "__self__", None) is not self._fence
                or getattr(clock, "__func__", None) is not DurableClockFence.now):
            raise PermissionError("retention archive must use this durable clock fence")

    def run_once(self) -> object:
        self._check_clock_binding()
        self._fence.now()
        return self._runner.run_once()


__all__ = ["DurableClockFence", "SupervisedRetention"]
