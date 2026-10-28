# STM v0.2 conversational archive — source qualification record

Date: 2026-10-28. Status: local source candidate for Draft PR, **not** a verified Vera installation or authorized personal-data archive.

Base source: `thebrazenbeard/stm@670f9478df84226d40e975b02cb2c22631c6f850` (the v0.1 feature branch). STM v0.2 source is committed and its exact tested head is reported in the Draft PR / final handoff; never attribute these tests to the untouched `main` branch.

## Confirmed local checks

| Evidence | Command or procedure | Observed result |
| --- | --- | --- |
| Full v0.1 + v0.2 regressions | `PYTHONPATH=src python3 -B -m unittest discover -s tests -q` | Exit 0; **136 tests passed**, Python 3.12.14, SQLite 3.53.1 |
| Public evidence-only path | `PYTHONPATH=src python3 -B examples/conversation_archive.py` | Exit 0; citation-preserving cross-conversation recall, correction, delete, reopen with synthetic text |
| Synthetic evaluation | `PYTHONPATH=src python3 -B benchmarks/bench_archive.py --iterations 30` | Exit 0; 601 events, 600 active, four scopes, 10 queries (8 positive), k=8, 300 timed queries/method |
| Safe source diff | `git diff --check` | Exit 0 |
| Clean Python install | isolated Python 3.12 virtualenv, `pip install --no-deps .` with isolated build deps | Built and installed `stm-short-term-memory==0.2.0`; import resolved to venv `site-packages` |

Measured synthetic Recall@8: naive current-chat sliding window **0.250** (2/8), uncached cross-chat recency **0.375** (3/8), SQLite FTS5 + scope-local lexical ranking **0.875** (7/8). Corresponding MRR@8: 0.125, 0.2083, 0.875. The explicit `journal` versus `notebook` synonym question failed in the lexical archive (expected limitation). Last local illustrative p50 retrieval latencies were approximately **0.27 ms**, **0.26 ms**, **0.22 ms** respectively; environment and short loops make comparative latency claims unreliable. Selected raw bytes exclude citation wrappers, chat templates and exact model tokens. These scores are **synthetic engineering smoke**, not Vera recall accuracy, neural learning, verified token savings, or production speedups.

## Independent adversarial review and remediation

An independently dispatched reviewer reproduced three Important flaws during the implementation and verified repairs:

1. SQLite WAL/SHM temporarily group/world-readable even though main file was chmodded 0600. Fixed by precreating private DB before WAL initialization, validating file and directory ownership/permissions, and regression under `umask 022` (all three files 0600).
2. Global FTS5 BM25 scores and ordering changed with inaccessible tenants' and privacy labels' term frequencies. Removed corpus-global BM25; rank by only authorized content's exact lexical token overlap, with source-local recency tie-breaking.
3. Intermediate newest-512 candidate cutoff silently dropped older exact matches. Removed cutoff and tested 513+ later distractors. Further exact-token tests prevent substring false positives (`cat` versus `caterpillar`).

The final targeted reviewer addendum found no remaining confirmed Critical/Important finding in these areas. Its scope does **not** certify general security or production readiness.

## Remaining qualification gaps

- **Host authentication and consent:** The application integrating STM must provide genuinely authenticated principals and privacy authorization callbacks. The demonstration callback is not that implementation.
- **Confidentiality and erasure:** Standard SQLite database/WAL are plaintext. POSIX permission checks reduce cross-OS-user exposure, not same-user access. FTS5 secure-delete is enabled when supported, but existing WAL, backups, snapshots, and external derived data are not forensically erased. Encryption, backup lifecycle, Windows ACL and attacker-writable ancestor directories need host review.
- **Recovery/security scale:** Multi-process sustained load, power-loss recovery, migration from older SQLite builds, secure restore provenance, massive archives, and side-channel resistance have not been qualified. Ranking scans every authorized FTS hit and CPU cost grows with matched corpus size.
- **Retrieval quality:** No actual LongMemEval/LoCoMo or real Vera conversation/model evaluation. Lexical retrieval misses paraphrases; local semantic search remains optional and unbuilt.
- **Tokenizer/runtime:** A model-independent exact-backend protocol is implemented and mock-tested; no actual Vera engine tokenizer, full rendered prompt, KV-cache reuse, Ollama/llama.cpp process, VRAM or latency measurement was verified.
- **Python versions/licensing:** Tested runtime is Python 3.12.14; Python 3.10/3.11 CI remains to be observed for this branch. STM's distribution license has not been selected by the owner.

No real personal conversation, production memory store, installed model, or self/empathy authority was accessed or changed by this candidate.
