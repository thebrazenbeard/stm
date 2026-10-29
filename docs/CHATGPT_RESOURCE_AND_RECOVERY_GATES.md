# ChatGPT source archive: storage, I/O and recovery gates

Status: **source and synthetic-test analysis, not a Lappy storage qualification**.
Event: [`chat_history_ingestion_live_coordination`](https://github.com/thebrazenbeard/chat-communication-bus/issues/403).

## Recorded host receipts versus source estimates

The sanitized event records an **8,929,236,891-byte** original ZIP with **20**
numbered conversation shards totaling **677,141,201 uncompressed bytes**.
Those are earlier host receipts; this document does not independently read
the ZIP, its encrypted vault, disk inventory, backup or private index.

Fresh source inspection of `chatgpt_archive.py` shows these I/O phases:

1. Read the original ZIP for its SHA-256.
2. On a new archive version, read it again while creating an encrypted source
   copy of approximately the same size on the *vault volume*.
3. Stream and parse conversation JSON shards, sealing each indexed record in
   SQLite; reread the original ZIP for the precommit stability hash.
4. Authenticate/decrypt the encrypted ZIP and surviving indexed records.
5. An **optional, separate** `verify_source_index` source-reconciliation check
   reads the original ZIP twice more for before/after source hashes and streams
   all numbered JSON shards to compare authenticated index digests.

The optional independent recount is deliberately expensive. With this source
size, it entails at least **17.86 GB of sequential source reads solely for its
two SHA-256 passes**, plus ZIP shard parsing and indexed lookups. That figure
is a source-derived *lower bound on read volume*, not an elapsed-time,
throughput, host-free-space or successful-recount measurement.

## Added fail-early capacity heuristic

The importer previously checked for only the full encrypted-ZIP copy plus
1 MiB of free space. It could succeed at writing that copy and then run out of
space while building the separately sealed SQLite index.

On a **new** source import, the preflight now requests available vault-volume
space for:

`encrypted_source_copy_if_missing + 2 × uncompressed_conversation_shard_bytes + 16 MiB`

For the previously recorded source metadata, the *estimated index reserve* is
**1,371,059,618 bytes**, separate from the encrypted original copy. Existing
sealed-source versions avoid counting a second copy. The input size and shard
sizes come from validated source/ZIP metadata; no raw content is logged.

This is a conservative planning gate, **not** a reservation or assurance.
Other processes can consume the free space; SQLite/page/journal overhead and
future source formats can exceed the estimate. The original ZIP must remain
intact regardless of import outcome. Current source code can remove an
encrypted copy **it just created** if the index transaction never committed;
it does not authorize deleting any preexisting source, vault, backup or
unrelated data. A failed transaction still requires an auditable recovery
decision, not blind cleanup.

## Restore and retention gates still open

- A verified readback of the **existing** encrypted ZIP and rows is not a
  demonstrated restore from a separate backup after loss of the source volume.
- Back up ciphertext and its corresponding recoverable key material using
  separate appropriately restricted custody; exercise restore to an isolated
  owner-controlled environment and revalidate source/index coverage.
- Do not silently create new plaintext archives, search indexes, temporary
  dumps or hosted diagnostics. This repository's other SQLite conversation
  archive is **plaintext unless the host separately encrypts it**.
- Day-30 review eligibility and day-45 expiry govern **new, opted-in STM
  records**, not the separately retained official account-export ZIP. A source
  preservation/retirement decision needs its own explicit authority.
- Any restart, cleanup, or deduplication requires precise selected targets,
  current consent, a rollback/recovery plan and host evidence. No broad
  deletion based solely on a stale space estimate.

Synthetic tests: `test_chatgpt_disk_reserve.py` covers low-space rejection
before copying, a positive new-import case and reuse of an existing sealed
source. They do **not** replace a real Lappy disk, restore or restart probe.
