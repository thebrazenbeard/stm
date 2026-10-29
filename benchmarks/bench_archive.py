"""Reproducible *synthetic* SQLite STM archive vs two naive baselines.

Usage from repository root::

    PYTHONPATH=src python3 benchmarks/bench_archive.py --iterations 30

Reports exact-evidence Recall@k, reciprocal rank, retrieval latency, selected
raw content bytes, and process memory observations. It does not run a language
model, measure answer quality, or assert a real-world speedup. The benchmark
uses only generated data and a clearly marked trusted-demo authorizer.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
import platform
import sqlite3
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Callable

from archive_fixtures import (
    SyntheticQuestion,
    SyntheticScope,
    build_dataset,
)

from stm.archive import ArchiveScope, ConversationArchive


@dataclass(frozen=True)
class BaselineRow:
    fixture_id: str
    scope: SyntheticScope
    conversation_id: str
    content: str
    turn_id: str


def _rank_metrics(
    selected: tuple[BaselineRow, ...],
    gold: tuple[str, ...],
) -> tuple[float, float]:
    if not gold:
        raise ValueError("negative queries do not have positive recall labels")
    for index, row in enumerate(selected, 1):
        if row.fixture_id in gold:
            return 1.0, 1.0 / index
    return 0.0, 0.0


def _percentile(values: list[int], quantile: float) -> float:
    """Nearest-rank percentile of nanosecond samples, in milliseconds."""
    if not values:
        raise ValueError("no timed samples")
    ascending = sorted(values)
    index = max(0, math.ceil(quantile * len(ascending)) - 1)
    return round(ascending[index] / 1_000_000, 6)


def _source_state() -> dict[str, object]:
    # Only local metadata; never invokes a network operation.
    root = Path(__file__).resolve().parent.parent
    paths = [
        "src/stm/archive.py",
        "benchmarks/bench_archive.py",
        "benchmarks/archive_fixtures.py",
    ]
    fingerprints = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in paths if (root / name).is_file()
    }
    result: dict[str, object] = {
        "base_git_commit": None,
        "worktree_dirty": None,
        "source_sha256": fingerprints,
    }
    git_dir = root / ".git"
    if not git_dir.exists():
        return result
    try:
        import subprocess

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root,
            check=True, capture_output=True, text=True, timeout=3,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root,
            check=True, capture_output=True, text=True, timeout=3,
        )
        result["base_git_commit"] = head.stdout.strip()
        result["worktree_dirty"] = bool(status.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def run(*, turns_per_conversation: int = 25, limit: int = 8,
        iterations: int = 30) -> dict[str, object]:
    """Execute identical, deterministic synthetic questions for all methods."""
    if limit < 1 or iterations < 1:
        raise ValueError("limit and iterations must be positive")

    dataset = build_dataset(turns_per_conversation=turns_per_conversation)
    allowed_scopes = set(dataset.turns[i].scope for i in range(len(dataset.turns)))
    principal = object()
    allowed_actions = {
        "append", "search", "correct", "delete", "read_privacy:private",
        "write_privacy:private",
    }

    def demo_authorize(actor: object, action: str, scope: ArchiveScope) -> bool:
        # A controlled *benchmark-only* callback, not host authentication.
        return (
            actor is principal and action in allowed_actions
            and SyntheticScope(scope.tenant_id, scope.owner_id, scope.agent_id)
            in allowed_scopes
        )

    def db_scope(scope: SyntheticScope) -> ArchiveScope:
        return ArchiveScope(scope.tenant_id, scope.owner_id, scope.agent_id)

    stored_ids: dict[str, str] = {}
    by_turn_id: dict[str, BaselineRow] = {}
    current: dict[str, BaselineRow] = {}
    insertion_order: list[str] = []
    times: dict[str, list[int]] = {
        "sliding_window": [], "uncached_recency": [], "sqlite_fts5": [],
    }
    selected_by_method: dict[str, list[tuple[BaselineRow, ...]]] = {
        name: [] for name in times
    }

    tracemalloc.start()
    try:
        with tempfile.TemporaryDirectory(prefix="stm-archive-bench-") as temp:
            archive = ConversationArchive(
                str(Path(temp) / "conversations.sqlite3"),
                authorize=demo_authorize,
            )
            try:
                for fixture in dataset.turns:
                    scope = db_scope(fixture.scope)
                    if fixture.replaces is None:
                        row = archive.append_turn(
                            principal, scope,
                            conversation_id=fixture.conversation_id,
                            role=fixture.role, content=fixture.content,
                            source="synthetic:archive_benchmark",
                            privacy="private", event_time=fixture.event_time,
                        )
                    else:
                        predecessor = stored_ids[fixture.replaces]
                        row = archive.correct(principal, scope, predecessor, fixture.content)
                        current.pop(fixture.replaces)
                    stored_ids[fixture.fixture_id] = row.turn_id
                    baseline = BaselineRow(
                        fixture.fixture_id, fixture.scope, fixture.conversation_id,
                        fixture.content, row.turn_id,
                    )
                    by_turn_id[row.turn_id] = baseline
                    current[fixture.fixture_id] = baseline
                    insertion_order.append(fixture.fixture_id)

                # Scan the entire in-memory history fresh for both baselines:
                # no index or result cache. A naive sliding window only sees
                # the *current* conversation; recency spans allowed chats.
                def active_rows(question: SyntheticQuestion) -> list[BaselineRow]:
                    return [
                        current[key] for key in insertion_order
                        if key in current and current[key].scope == question.scope
                    ]

                def sliding(question: SyntheticQuestion) -> tuple[BaselineRow, ...]:
                    scoped = active_rows(question)
                    recent_chat = [row for row in scoped
                                   if row.conversation_id == question.current_conversation_id]
                    return tuple(reversed(recent_chat[-limit:]))

                def recency(question: SyntheticQuestion) -> tuple[BaselineRow, ...]:
                    scoped = active_rows(question)
                    return tuple(reversed(scoped[-limit:]))

                def indexed(question: SyntheticQuestion) -> tuple[BaselineRow, ...]:
                    hits = archive.search(
                        principal, db_scope(question.scope), question.query,
                        privacy_scopes=frozenset({"private"}), limit=limit,
                    )
                    rows = tuple(by_turn_id[hit.turn.turn_id] for hit in hits)
                    if any(row.scope != question.scope for row in rows):
                        raise AssertionError("cross-scope archive result")
                    return rows

                methods: dict[str, Callable[[SyntheticQuestion], tuple[BaselineRow, ...]]] = {
                    "sliding_window": sliding,
                    "uncached_recency": recency,
                    "sqlite_fts5": indexed,
                }

                # Warm up all paths once; all reported timings are warmed
                # steady-state retrieval times. Negative-query behavior is
                # measured separately from positive recall.
                for question in dataset.questions:
                    for method in methods.values():
                        method(question)
                for iteration in range(iterations):
                    for question in dataset.questions:
                        for name, method in methods.items():
                            started_ns = time.perf_counter_ns()
                            selected = method(question)
                            times[name].append(time.perf_counter_ns() - started_ns)
                            if iteration == 0:
                                selected_by_method[name].append(selected)
            finally:
                archive.close()
        _, peak_traced = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    results: dict[str, object] = {}
    for name in times:
        # The ordered query sequence repeats each iteration, so the first
        # pass is sufficient for deterministic selection and prompt bytes.
        samples = selected_by_method[name][:len(dataset.questions)]
        positive_scores: list[tuple[float, float]] = []
        by_category: dict[str, list[float]] = {}
        negative_nonempty = 0
        for question, selected in zip(dataset.questions, samples):
            if question.gold_ids:
                score = _rank_metrics(selected, question.gold_ids)
                positive_scores.append(score)
                by_category.setdefault(question.category, []).append(score[0])
            else:
                negative_nonempty += bool(selected)
        results[name] = {
            "recall_at_k": round(statistics.mean(item[0] for item in positive_scores), 6),
            "mrr_at_k": round(statistics.mean(item[1] for item in positive_scores), 6),
            "category_recall": {
                category: round(statistics.mean(values), 6)
                for category, values in sorted(by_category.items())
            },
            "negative_queries_with_nonempty_context": negative_nonempty,
            "mean_selected_raw_content_bytes": round(statistics.mean(
                sum(len(row.content.encode("utf-8")) for row in sample)
                for sample in samples
            ), 2),
            "p50_retrieval_ms": _percentile(times[name], .50),
            "p95_retrieval_ms": _percentile(times[name], .95),
            "timed_query_count": len(times[name]),
        }

    return {
        "classification": "deterministic_synthetic_exploratory_benchmark",
        "qualification": "not representative of Vera conversational accuracy or production latency",
        "source_state": _source_state(),
        "environment": {
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(),
            "process_pid": os.getpid(),
        },
        "fixture": {
            "raw_events": len(dataset.turns),
            "active_turns": len(current),
            "scopes": len(allowed_scopes),
            "questions": len(dataset.questions),
            "positive_questions": sum(bool(q.gold_ids) for q in dataset.questions),
            "negative_questions": sum(not q.gold_ids for q in dataset.questions),
            "turns_per_conversation": turns_per_conversation,
            "top_k": limit,
            "iterations": iterations,
            "random_seed": None,
            "fixture_generation": "fully deterministic enumeration; no random sampling",
        },
        "memory": {
            "peak_python_tracemalloc_bytes": peak_traced,
            "qualification": "whole-process allocation; excludes SQLite native heap/OS pages",
        },
        "methods": results,
        "measurement_notes": [
            "sliding_window selects last K current-chat turns without a query-dependent ranker",
            "uncached_recency scans all allowed conversations and selects last K turns",
            "sqlite_fts5 selects up to K query matches with an actual SQLite index",
            "all retrievals are authorization-scoped; benchmark actor is a trusted synthetic demo only",
            "selected bytes exclude citation labels, model wrappers, and actual tokenization",
            "same synthetic query fixtures and positive gold evidence identities across methods",
            "no model outputs, no LongMemEval data, no neural learning or KV cache involved",
            "one synthetic journal/notebook synonym probes a lexical gap; not a broad semantic benchmark",
            "negative nonempty context is not a false factual answer or a prompt-injection success",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--turns-per-conversation", type=int, default=25)
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    result = run(
        turns_per_conversation=args.turns_per_conversation,
        limit=args.limit,
        iterations=args.iterations,
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
