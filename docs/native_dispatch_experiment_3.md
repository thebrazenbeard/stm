# BT2 third native multi-agent dispatch — evidence record

Date: 2026-10-28. Integrator: One (`/root`). Target: `thebrazenbeard/stm`, branch `feat/stm-v0.1-native-build-3`.

## Dispatch evidence

Native `collaboration.spawn_agent`, `send_message`, and `list_agents` were available and exercised. Each successful spawn returned a genuine child path (`task_name`). A persona in a prompt is not counted as a worker.

| Sequence | Native child ID / creation receipt `task_name` | Assignment | Wave | Final state |
| ---: | --- | --- | --- | --- |
| 1 | `/root/memory_architecture` | API, models, architecture, coordinator | Initial | Completed; 7 unit tests |
| 2 | `/root/context_tokens` | Token/byte budgets, packing, pinned overflow | Initial | Completed; 19 unit tests |
| 3 | `/root/cache_local` | Local prompt-prefix cache, mock backend, KV distinction | Initial | Completed; 15 unit tests |
| 4 | `/root/storage_lifecycle` | Scoped bounded storage, TTL, checkpoint, historical adapter | Initial | Completed; 13 unit tests |
| 5 | `/root/retrieval_semantic` | Deterministic/optional semantic retrieval, provenance | Initial | Completed; 13 unit tests |
| 6 | `/root/governance_privacy` | Identity, consent, admission, privacy, injection controls | Initial | Completed; 11 unit tests |
| 7 | `/root/independent_security_perf` | Independent adversarial tests and two-baseline benchmark | Second wave | Completed; 11 adversarial tests |

Dispatch attempts: **7**. Successful native creations: **7**. Failed creations: **0**. First-wave children: **6**. Maximum child capacity with One occupying the seventh total execution slot: **6**. Peak simultaneous child agents dispatched before completion: **6** (the six initial successful calls occurred before any completion). Total distinct child agents over both waves: **7**. All seven returned substantive final findings.

The actual creation receipts gave the above `task_name` identifiers; no separate opaque worker UUID was returned. `collaboration.list_agents` subsequently identified the seven child identities and their completion states. Do not confuse this with seven children executing at once.

## Integration and independent review

One integrated the specialists' isolated files into a single `src/stm` package and ran combined tests. The integration was not merely a concatenation: the team found and corrected cross-component defects before v0.1 review:

- top-k retrieval and dedup could suppress pinned records before packing;
- the core and governance layers initially had incompatible `Actor` classes;
- the default storage backend class name initially disagreed;
- partial retrieval scope omitted tenant and agent dimensions;
- storage and governance sometimes evaluated TTL against different clocks.

Agent 7 challenged the integrated public API with negative and concurrency tests, not just isolated module tests. See [independent review](security_review.md) and `tests/test_adversarial.py`. The benchmark script and raw measured report are in `benchmarks/`.

## Outcome categories

- **Dispatch:** SUCCESS — seven genuine child workers created across two waves; six maximum concurrent child slots.
- **Engineering:** SOURCE-LEVEL SUCCESS for the bounded offline v0.1 candidate, subject to documented limitations.
- **Integration:** SUCCESS — [Draft PR #2](https://github.com/thebrazenbeard/stm/pull/2) is open and unmerged. The initial remote implementation commit and locally tested commit have an identical Git tree, independently verified through GitHub Git data. The exact current head is recorded in the PR.
- **Runtime:** LOCAL INSTALLED API SUCCESS — a fresh virtual environment installed the distribution, 89 combined tests passed, and the example exercised retrieval, packing, correction, checkpoint and restore. This does **not** establish production installation, inference-backend integration, or model KV reuse.
- **Remote CI:** GitHub Actions [run 40743444849](https://github.com/thebrazenbeard/stm/actions/runs/40743444849) passed both Python 3.10 and 3.12 package installation, unittest and synthetic benchmark jobs on the initial implementation commit.

**Acceleration:** parallel source research and isolated module development were observed, and independent review found real defects. A controlled single-agent counterfactual was not run; therefore a quantified causal speedup from native delegation is **UNKNOWN**. Dispatch success does not rely on engineering or installation success.
