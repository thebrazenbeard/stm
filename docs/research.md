# Source research and provenance — 2026-10-28

These repositories were inspected at the following pinned Git revisions. Current README claims, implemented source behavior, and our own measurements are separate categories of evidence. STM uses original Python source; no external implementation or historical private data was copied.

| Reference | Inspected revision | License/status | Useful mechanism and STM decision |
| --- | --- | --- | --- |
| [mem0](https://github.com/mem0ai/mem0) | `26cdefb46600c0fa5953c4b5ee5003c125539fc4` | Apache-2.0 | Per-user/session/agent memory scopes and retrieval; core STM avoids mandatory model extraction and embeddings |
| [MemPalace](https://github.com/MemPalace/mempalace) | `84582fb055a6429261f9c779da86c0561ec80adc` (`develop`) | MIT | Local-first verbatim collection lifecycle, pluggable storage and importance/recency selection; STM uses bounded volatile working records |
| [OpenViking](https://github.com/volcengine/OpenViking) | `6afd9ba300848cd302cd00bc944b4f1d02e28476` | Main AGPL-3.0, component exceptions | Hierarchical context assembly and budget tiering; STM implements an original deterministic bounded packer without copying AGPL source |
| [DeepMemoryStorage](https://github.com/thebrazenbeard/deepmemorystorage) | `0cb0a483413728d4b6384a2500d56036a28e66ee` | Source-visible proprietary | Read-only historical evidence boundary, exact source/authority separation; no code or personal archive imported |
| [SemanticAtlas](https://github.com/thebrazenbeard/semanticatlas) | `ace4e9bffb23732f2dd4b4d8b7ef634060b1e7af` | Source-visible proprietary | Retrieval evidence lineage, temporal status and distinction between semantics and authority; no source copied |
| [Empathy](https://github.com/thebrazenbeard/empathy) | `4bb1bfd3c91dafd60e33c65738238ca17ce293fa` | Source-visible proprietary | Input evidence is not an independent psychological judgment; STM exposes context, not inferred emotion/consent |
| [self](https://github.com/thebrazenbeard/self) | `b4003a56fe5f0ed845bb29d36bdac6467557638d` | Historical/archived; no root LICENSE observed | Old identity material is historical research evidence, not present identity or permission authority |

## Mechanisms and tradeoffs

- **Storage:** Bounded in-process memory and opt-in JSON checkpoints trade distributed durability and query power for low operational cost and exact session scoping. The checkpoints are not an authenticated evidence ledger.
- **Retrieval:** Keyword overlap and recency ranking work offline; optional injected embeddings may improve paraphrase recall but can cost CPU/memory and require caller review. Semantic similarity never establishes identity, factual truth, or permission.
- **Context:** Whole-record selection plus pinned protection avoids silent truncation. The byte-bound default is deterministic but deliberately not represented as model token counts.
- **Privacy:** Source labels, immutable scope and admission policy are stronger than trusting text itself. They still require a host-authenticated actor and external access controls.
- **Cache:** An application prefix cache can avoid rebuilding or locating identical prefixes; it does not guarantee inference speedups or actual KV-tensor reuse.

Third-party project benchmark and performance statements were considered as project claims, not independently reproduced STM results. The benchmark in this repo uses the **same local synthetic fixture** for STM and the two explicitly defined baselines. It is not a fair cross-system result for the seven reference repositories.

## Redistribution boundary

No third-party code was copied. The source-visible proprietary repositories and AGPL-licensed code were read for high-level ideas only. STM's own public redistribution license is **not yet selected by the repository owner**; do not infer a permission grant from GitHub public visibility.
