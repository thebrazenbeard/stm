# Qualification and known limitations

STM v0.1 is a review candidate, not a deployed long-term memory service.

1. **Identity/authentication:** The embedding application must authenticate `Actor` IDs and protect session identifiers. STM isolates matching scopes but cannot authenticate caller-supplied strings.
2. **Token accounting:** The default budget is UTF-8 bytes. Exact model-token usage additionally depends on a model tokenizer, messages/chat template, and reserved prompt overhead. `Utf8ByteCounter` must not be presented as a certified model-token count.
3. **Recovery:** Checkpoints are opt-in plaintext. SHA-256 detects accidental corruption, not malicious replacement. Restrict restore to trusted files; deleted RAM content can survive in old checkpoint copies.
4. **Concurrency:** Store and cache locks protect threads in one Python process. There is no distributed transaction protocol, multi-process synchronization or durable multi-tenant database.
5. **Eviction and retention:** Unpinned records can be evicted by capacity and are not guaranteed recoverable unless separately checkpointed. Pinned records still expire at their explicit TTL, and full pinned capacity rejects new admission. Context packing raises when pinned evidence exceeds budget.
6. **Retrieval:** Lexical matching misses some paraphrases; optional embeddings are not benchmarked against a real local model yet. Exact duplicate collapse preserves provenance in retrieval results but the standard `MemorySession.retrieve()` returns representative records. Contradiction flags are candidates for review, not factual adjudication.
7. **Memory poisoning:** Lexical prompt-injection quarantine is incomplete and can reject innocent quoted examples. Retrieved text remains untrusted data; the host is responsible for secure prompt composition and tool authorization.
8. **Historical evidence:** The DMS bridge is a protocol/validation boundary, not a verified live connector. There is no automatic long-term promotion, training, self-state rewrite, or psychological inference.
9. **Cache and local inference:** The application prompt-prefix cache does not store GPU/CPU model KV state. No real Ollama execution or KV reuse has been verified in this build. Parser support for backend metrics is not a runtime measurement.
10. **External deployment and license:** No production service was installed, merged or deployed. STM's own redistribution license awaits an explicit owner decision. Reference source pins and license evidence are in `research.md`.

Source tests, package installation tests, benchmark timings, Draft PR publication, merge, real local inference execution, and behavior in an agent are distinct qualification states. None should be inferred from another.
