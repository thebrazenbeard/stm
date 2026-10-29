"""Explicit, host-operated expiration sweeps for the local STM archive.

No autonomous service or credential source is created by importing this module.
A trusted host must supply an authenticated scope registry, invoke ``run_once``
after startup and/or ``run_periodically`` in its own managed process, and
collect the content-free reports. This module cannot erase external journals,
backups, filesystem snapshots, or model-runtime copies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from threading import Event
from typing import Callable, Iterable

from .archive import ArchiveScope
from .retention import MAX_SWEEP_BATCH, RetainedConversationArchive


@dataclass(frozen=True, slots=True)
class SweepTarget:
    """Trusted host-owned scope and its independently authorized principal.

    A caller-supplied tenant, owner or conversation identifier is NOT a
    principal. Targets must come from an authenticated, current host registry;
    the archive independently checks deletion and privacy grants on each batch.
    """

    principal: object
    scope: ArchiveScope
    privacy_scopes: frozenset[str]

    def __post_init__(self) -> None:
        if self.principal is None or not isinstance(self.scope, ArchiveScope):
            raise PermissionError("verified retention principal and scope required")
        if not isinstance(self.privacy_scopes, frozenset) or not self.privacy_scopes or any(
            not isinstance(label, str) or not label.strip()
            for label in self.privacy_scopes
        ):
            raise PermissionError("explicit retention privacy scopes required")


@dataclass(frozen=True, slots=True)
class SweepReport:
    """Content-free bounded progress receipt, not proof of forensic deletion."""

    targets: int
    batches: int
    deleted: int
    pending_targets: int
    legacy_targets: int = 0

    @property
    def complete(self) -> bool:
        return self.pending_targets == 0


class RetentionSweepRunner:
    """Run bounded catch-up sweeps using a current trusted scope registry.

    - Construct only with ``RetainedConversationArchive`` and a host registry.
    - Every call refreshes the registry, including after process restart.
    - All targets are checked before any deletion; authorization is then
      rechecked by the archive in each transaction.
    - Batches and target counts have explicit limits to bound one run.
    - If a run is incomplete, call it again; a scheduled host must persist its
      *own* non-sensitive audit receipts and monitor failures/backlog.
    """

    def __init__(
        self,
        archive: RetainedConversationArchive,
        *,
        targets: Callable[[], Iterable[SweepTarget]],
        batch_size: int = 100,
        max_batches_per_target: int = 10,
        max_targets: int = 64,
    ) -> None:
        if not isinstance(archive, RetainedConversationArchive):
            raise PermissionError("policy-controlled archive required")
        if not callable(targets):
            raise PermissionError("trusted current scope registry required")
        for value, name, ceiling in (
            (batch_size, "batch_size", MAX_SWEEP_BATCH),
            (max_batches_per_target, "max_batches_per_target", 1000),
            (max_targets, "max_targets", 10000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be an integer between 1 and {ceiling}")
        self._archive = archive
        self._targets = targets
        self._batch_size = batch_size
        self._max_batches = max_batches_per_target
        self._max_targets = max_targets

    def _current_targets(self) -> tuple[SweepTarget, ...]:
        try:
            source = iter(self._targets())
        except Exception:
            raise PermissionError("trusted retention target registry failed") from None
        rows: list[SweepTarget] = []
        seen: set[tuple[ArchiveScope, frozenset[str]]] = set()
        while True:
            try:
                item = next(source)
            except StopIteration:
                break
            except Exception:
                # A host registry may fail with a sensitive error string.
                # Do not leak that content through the runner's public error.
                raise PermissionError("trusted retention target registry failed") from None
            if len(rows) >= self._max_targets:
                raise PermissionError("trusted retention target registry exceeds limit")
            if not isinstance(item, SweepTarget):
                raise PermissionError("trusted retention target registry contains invalid target")
            key = (item.scope, item.privacy_scopes)
            if key in seen:
                raise PermissionError("trusted retention target registry contains duplicate scope")
            seen.add(key)
            rows.append(item)
        if not rows:
            raise PermissionError("empty retention target registry is not a verified sweep")
        return tuple(rows)

    def run_once(self) -> SweepReport:
        """Perform a bounded authorized catch-up pass; may leave a backlog.

        On a failing scope or operation, the error propagates; previously
        committed batches are durable and will be idempotently skipped when
        the host retries. No personal content is included in the report.
        """
        current = self._current_targets()
        batches = deleted = pending = legacy_targets = 0
        for target in current:
            last_count = 0
            has_backlog = False
            for _ in range(self._max_batches):
                audit = self._archive.sweep(
                    target.principal, target.scope,
                    privacy_scopes=target.privacy_scopes,
                    limit=self._batch_size,
                )
                batches += 1
                deleted += audit.deleted
                last_count = audit.deleted
                if last_count < self._batch_size:
                    break
            if last_count == self._batch_size:
                # A full final batch may have drained the last row. Ask a
                # bounded dry-run question; never label a backlog complete
                # based on an ambiguous full batch.
                preview = self._archive.sweep(
                    target.principal, target.scope,
                    privacy_scopes=target.privacy_scopes,
                    limit=1, dry_run=True,
                )
                if preview.candidates > 0:
                    has_backlog = True
            has_legacy = self._archive.has_legacy_unretained(
                target.principal, target.scope,
                privacy_scopes=target.privacy_scopes,
            )
            if has_legacy:
                legacy_targets += 1
            if has_backlog or has_legacy:
                pending += 1
        return SweepReport(len(current), batches, deleted, pending, legacy_targets)

    def run_periodically(
        self,
        stop: Event,
        *,
        interval: timedelta,
        report: Callable[[SweepReport], None] | None = None,
    ) -> None:
        """Blocking host-managed loop: startup catch-up, then timed sweeps.

        This does not start a daemon, persist a service or install a scheduler.
        The host must supervise it, authorize current scope enumeration,
        restart after interruption and monitor its completion reports.
        """
        if not isinstance(stop, Event):
            raise TypeError("threading.Event stop signal required")
        if not isinstance(interval, timedelta) or not (
            timedelta(seconds=1) <= interval <= timedelta(days=1)
        ):
            raise ValueError("interval must be between one second and one day")
        if report is not None and not callable(report):
            raise TypeError("report callback must be callable")
        while not stop.is_set():
            result = self.run_once()
            if report is not None:
                report(result)
            if stop.wait(interval.total_seconds()):
                break


__all__ = ["SweepTarget", "SweepReport", "RetentionSweepRunner"]
