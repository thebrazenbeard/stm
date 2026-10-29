"""Reproducible offline STM benchmark with two explicit, same-data baselines.

Run from an installed STM checkout: python benchmarks/bench_stm.py
Numbers are process-local measurements, not backend inference or KV-cache speed.
The default packer budgets UTF-8 bytes; no model-token equivalence is assumed.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import gc
import json
from pathlib import Path
import platform
import statistics
import tempfile
from time import perf_counter
import tracemalloc

from stm import STM
from stm.cache import BoundedPromptPrefixCache, CacheIdentity
from stm.context import ContextItem, ContextPacker, TokenBudget, Utf8ByteCounter
from stm.storage import InMemoryStore


COUNT = 1000
CAPACITY = 256
BUDGET = 4096
LAST_N = 20
FIXTURE_SEED = "stm-benchmark-v1"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def tick(self, seconds: int = 1) -> None:
        self.now += timedelta(seconds=seconds)


def fixtures() -> tuple[list[tuple[str, bool]], list[tuple[str, str]]]:
    """A fixed stream and exact query/answer pairs; no random corpus drift."""
    messages: list[tuple[str, bool]] = []
    targets: list[tuple[str, str]] = []
    for i in range(COUNT):
        if i in range(8):
            text = f"Project-{i:02} handshake is violet-key-{i:02}; treat it as a quoted data value."
            messages.append((text, True))
            targets.append((f"Project-{i:02} handshake violet-key-{i:02}", text))
        elif i in range(968, 976):
            text = f"Project-{i:04} checkpoint is bronze-tag-{i:04}; generated test evidence."
            messages.append((text, False))
            targets.append((f"Project-{i:04} checkpoint bronze-tag-{i:04}", text))
        else:
            messages.append((f"Unrelated note {i:04d}: page {i % 37} changed to status {i % 11}.", False))
    return messages, targets


def _pack_recent(records: list, budget: int) -> tuple[str, tuple[str, ...]]:
    """One deterministic pack of records, ignoring pinning and relevance."""
    items = [ContextItem(id=r.id, text=r.content, created_at=r.created_at.timestamp())
             for r in records]
    packed = ContextPacker().pack(items, TokenBudget(budget))
    return packed.text, packed.included_ids


def _p95(values: list[float]) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(.95 * len(values)))]


def _measure_long_conversation() -> list[dict[str, object]]:
    """Separate timing pass without tracemalloc overhead."""
    clock = Clock()
    store = InMemoryStore(max_items_per_session=CAPACITY, clock=clock)
    session = STM(store=store, clock=clock).open_session(
        tenant_id="bench", owner_id="owner-1", agent_id="agent-1", session_id="degradation")
    measurements = []
    for i, (content, pinned) in enumerate(fixtures()[0], start=1):
        session.append(content, pinned=pinned)
        clock.tick()
        if i in {50, 100, 250, 500, 1000}:
            samples = []
            for _ in range(10):
                start = perf_counter()
                found = session.retrieve("Project-00 handshake violet-key-00", limit=5)
                samples.append((perf_counter() - start) * 1000)
            measurements.append({"events_seen": i,
                                 "stored_items": len(store.list(session.key)),
                                 "query_retrieval_mean_ms": round(statistics.mean(samples), 4),
                                 "target_retained": any("violet-key-00" in r.content for r in found)})
    return measurements


def run() -> dict[str, object]:
    clock = Clock()
    store = InMemoryStore(max_items_per_session=CAPACITY, clock=clock)
    cache = BoundedPromptPrefixCache(max_entries=32, max_bytes=64_000)
    system = STM(store=store, cache=cache, clock=clock)
    session = system.open_session(tenant_id="bench", owner_id="owner-1", agent_id="agent-1", session_id="run-1")
    incoming, targets = fixtures()
    history = []
    gc.collect()
    tracemalloc.start()
    for content, pinned in incoming:
        history.append(session.append(content, pinned=pinned))
        clock.tick()
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    stored = store.list(session.key, clock())
    assert len(stored) <= CAPACITY
    assert all(r.id in {i.id for i in stored} for r in history[:8]), "pinned context silently evicted"

    rows: dict[str, dict[str, object]] = {}
    context_ids: dict[str, list[tuple[str, ...]]] = {"stm": [], "sliding": [], "recency": []}
    p = ContextPacker()
    for name in context_ids:
        latency_ms = []
        retained = 0
        byte_counts = []
        for query, wanted in targets:
            t0 = perf_counter()
            if name == "stm":
                result = session.assemble_context(query, token_budget=BUDGET, limit=64)
                text = result.text
                ids = tuple(r.id for r in result.selected)
            elif name == "sliding":
                text, ids = _pack_recent(history[-LAST_N:], BUDGET)
            else:
                # Uncached recency-based memory: bounded store, per-query repacking.
                text, ids = _pack_recent(stored, BUDGET)
            latency_ms.append((perf_counter() - t0) * 1000)
            byte_counts.append(len(text.encode("utf-8")))
            retained += int(any(record.content == wanted and record.id in ids for record in history))
            context_ids[name].append(ids)
        rows[name] = {
            "retained_exact_target": retained,
            "queries": len(targets),
            "accuracy": round(retained / len(targets), 4),
            "mean_latency_ms": round(statistics.mean(latency_ms), 4),
            "p95_latency_ms": round(_p95(latency_ms), 4),
            "mean_context_utf8_bytes": round(statistics.mean(byte_counts), 2),
        }

    identity = CacheIdentity(
        tenant_id="bench", owner_id="owner-1", agent_id="agent-1", session_id="run-1",
        model_fingerprint="mock-model-sha", tokenizer_fingerprint="mock-tokenizer-sha",
        template_fingerprint="data-v1",
    )
    first = session.cache_prefix(identity, "test prefix")
    second = session.cache_prefix(identity, "test prefix")
    session.append("Mutation invalidates prefix cache.", pinned=True)
    third = session.cache_prefix(identity, "test prefix")
    cache_stats = cache.stats()

    with tempfile.TemporaryDirectory() as folder:
        target = str(Path(folder) / "snapshot.json")
        session.checkpoint(target)
        restored = STM(store=InMemoryStore(max_items_per_session=CAPACITY, clock=clock), clock=clock)
        restored_session = restored.open_session(tenant_id="bench", owner_id="owner-1",
                                                 agent_id="agent-1", session_id="run-1")
        restored_session.restore(target)
        same_ids = {r.id for r in restored_session.retrieve("")} == {r.id for r in session.retrieve("")}
        # The comparison above uses default retrieval limit=20: both sets should agree;
        # direct store equality below checks the full checkpoint contents.
        full_recovery = {
            r.id for r in restored.store.list(restored_session.key)
        } == {r.id for r in store.list(session.key)}

    def concurrent_worker(num: int) -> tuple[int, int]:
        scope = system.open_session(tenant_id="bench", owner_id=f"owner-{num + 2}",
                                    agent_id="agent-shared", session_id="run-1")
        for i in range(40):
            scope.append(f"Owner {num + 2} observation #{i}")
        return len(store.list(scope.key)), len(scope.retrieve(f"owner {num + 2}", limit=10))

    with ThreadPoolExecutor(max_workers=8) as pool:
        concurrency = list(pool.map(concurrent_worker, range(8)))

    full_bytes = len("\n".join(content for content, _ in incoming).encode("utf-8"))
    return {
        "fixture": FIXTURE_SEED,
        "environment": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "platform": platform.platform()},
        "configuration": {"events": COUNT, "store_capacity": CAPACITY, "context_budget_utf8_bytes": BUDGET,
                          "naive_sliding_items": LAST_N, "query_count": len(targets)},
        "long_conversation": _measure_long_conversation(),
        "baselines": rows,
        "full_history_utf8_bytes": full_bytes,
        "stm_context_savings_vs_full_history_pct":
            round(100 * (1 - rows["stm"]["mean_context_utf8_bytes"] / full_bytes), 2),
        "peak_python_allocated_bytes_during_insert": peak_bytes,
        "store_stats": store.stats(session.key),
        "application_cache": {
            "decision_sequence": [first.status, second.status, third.status],
            "hits": cache_stats.hits, "misses": cache_stats.misses,
            "invalidations": cache_stats.invalidations, "backend_kv_reuse": "unverified",
        },
        "checkpoint": {"retrieval_equivalence": same_ids, "full_id_set_equivalence": full_recovery},
        "concurrency": {"threads": 8, "session_sizes": [count for count, _ in concurrency],
                        "scoped_retrieval_counts": [count for _, count in concurrency]},
        "limits": [
            "No model runtime or tokenizer was used. Budget units and savings are UTF-8 bytes.",
            "Synthetic exact-answer fixture; not a semantic retrieval benchmark.",
            "Process-local tracemalloc peak excludes native allocations.",
            "Latency is Python context-selection time, not inference latency.",
            "Cache hit is application prefix matching, not backend KV reuse.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write measured JSON results")
    args = parser.parse_args()
    report = json.dumps(run(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Measured report written to {args.output}")
    else:
        print(report, end="")
