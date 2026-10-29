# Vera shared private evidence retrieval — source-only integration gate

**Desired behavior:** whichever installed model Vera routes to should receive a small,
source-attributed set of relevant historical excerpts at *inference time*.
This is retrieval-augmented generation (RAG), not LoRA training or neural-weight
modification. A local model has no direct Google Drive credentials.

## Trust topology

1. Authenticated Google Drive reads acquire original documents/archives with
   provider ID, timestamps, revision and SHA-256. Continue using Roots to
   classify primary evidence, conflicts, unknown origins and source status.
2. Ingest preserves source bytes and integrity receipts in an operator-private
   source store. The prior 674-ID/208-lead Drive inventory is **METADATA ONLY**:
   it is not a transcript import or evidence that a local model can recall.
3. Import documented *file text* to a separate encrypted EvidenceMemory
   namespace on Lappy. Do not copy raw text/keys into GitHub, public indexes,
   shared Blotter messages or model training corpora. Source material remains
   marked historical_unverified or source_claim and every revision is retained.
4. A local, authenticated inference router retrieves at most three relevant
   snippets (2,500 characters by default) for a question and appends them as
   **untrusted quoted user context**, with source IDs, timestamps and hashes.
   User content and retrieved documents never become system instructions.
5. Windows VERA Interface (8788) must enforce its existing loopback Host,
   Origin and UI-session checks before retrieval. Android connects through
   the **owner-authenticated V2** gateway, not the legacy shared-bearer V1
   8443/18777 path. The gateway obtains the owner from its device registry,
   never from a client-provided owner_id.
6. Both routes point at the *same encrypted Lappy database* and source
   namespace. Model choice does not determine memory availability; successful
   source recall is a server function. Historical sources must not be mistaken
   for the presently qualified Lantern currentness backend (UNKNOWN).

## Honest present qualification

- A private synthetic EvidenceMemory proof was exercised in an isolated
  container: nine unit tests passed for encryption, provenance, HMAC index,
  owner separation, revision retention, tampering and bounded retrieval.
- Source code and separate synthetic tests exist in STM draft PR #15.
  The exact GitHub commit has **not** yet passed live Lappy testing or CI.
- A V2 gateway source branch contains optional EvidenceMemory loading and
  owner-bound context injection, but has not passed a full gateway regression
  or owner-enrolled Android acceptance. Production V2 is not deployed.
- No actual Drive file bodies have been loaded into the new memory vault.
  The account-wide ChatGPT export is still pending and cannot be inferred
  from older Drive chat files.

## Mandatory readback before saying 'Vera remembers across devices'

- Fully acquire selected Drive files and raw archives privately; compare the
  file SHA-256 to a connector/provider readback; preserve original content and
  revision without semantic promotion.
- Provision the same private vault to both host inference adapters; verify
  Win+Android V2 question retrieves matching source IDs after reboot, including
  a different-model selection. Negative tests: wrong owner, corrupted vault,
  missing key, source instruction injection, model hallucination, key rotation
  and erased/expired sources.
- Device-scoped V2 pairing and encrypted token handoff must be qualified before
  exposing the memory path to the phone. Do not weaken V1, publish a new Serve
  route or restart the shared gateway solely on source success.
- Use a separate owner-confirmed schedule for STM's 30-day review and DMS
  handoff. Do not fabricate an automatic archive/delete policy.

Dependencies: Python 3, cryptography, an operator-private key file with
exactly 32 random bytes, and the trusted gateway's owner namespace.
This first module uses HMAC-protected lexical retrieval, **not embeddings**.
Embedding/semantic reranking is an optional later experiment with independent
accuracy and privacy tests, not a reason to delay correct source citations.
