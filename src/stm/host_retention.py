"""One bounded, supervised host retention pass with explicit completion signal.

This is not a daemon, authenticated registry, service installer, or forensic
erasure tool. Only host-owned approved callbacks may supply audit custody.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .retention_runner import SweepReport
from .retention_supervisor import SupervisedRetention


class IncompleteSweep(RuntimeError):
    """A bounded sweep left backlog or unqualified legacy records."""

    def __init__(self, report: SweepReport):
        self.report = report
        super().__init__("retention catch-up incomplete; host must retry or escalate")


def run_guarded_once(
    supervisor: SupervisedRetention,
    *, record: Callable[[SweepReport], None],
) -> SweepReport:
    """Run one maintenance pass, write a content-free receipt, fail if incomplete.

    The host must independently authenticate the registry and protect the
    clock DB, archive, backups and receipt destination. A failed recorder must
    make the whole invocation fail; the underlying expiry is idempotent.
    """
    if not isinstance(supervisor, SupervisedRetention):
        raise PermissionError("verified supervised retention required")
    if not callable(record):
        raise PermissionError("host-owned audit recorder required")
    result = supervisor.run_once()
    if not isinstance(result, SweepReport):
        raise RuntimeError("unrecognized sweep report")
    if not all(
        type(value) is int and value >= 0
        for value in (result.targets, result.batches, result.deleted,
                      result.pending_targets, result.legacy_targets)
    ):
        raise RuntimeError("invalid sweep report values")
    if result.targets < 1 or result.pending_targets > result.targets:
        raise RuntimeError("inconsistent sweep report")
    record(result)
    if result.pending_targets or result.legacy_targets or not result.complete:
        raise IncompleteSweep(result)
    return result


__all__ = ["IncompleteSweep", "run_guarded_once"]
