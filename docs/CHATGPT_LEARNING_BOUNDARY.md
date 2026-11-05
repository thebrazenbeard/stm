# Imported conversation history: learning and memory boundary

Status: **source contract and synthetic tests**, not an installed Vera or neural-training qualification.

An official ChatGPT account export is historical, untrusted source evidence. Importing it into an encrypted vault or deriving a structural catalog does not make the contents current, correct, owner-authored, safe for third-party disclosure, or available as a model-training corpus.

## Separate stages

1. **Source custody:** Verify exact original ZIP bytes, preserve the encrypted copy, and independently reconcile every indexed conversation against the original source. Source count, index count, ciphertext authentication and optional source-to-index recount are different observations.
2. **Historical interpretation:** Preserve exact conversation and message/node references, role, correction links, branch selection, source time vs observed time, uncertainty, privacy label and third-party review state. A model-produced assistant statement is not evidence of the owner's beliefs or autobiographical experience.
3. **Owner review:** Only a genuinely authenticated owner/session may review bounded historical excerpts under a dedicated, currently valid scope. The existing `RECALL_SCOPE` does **not** grant semantic consolidation, identity modification, external disclosure or neural-weight updates. The module's `OwnerContext` is externally supplied policy metadata, not standalone authentication.
4. **Separate curated-data approval:** Any future training or semantic-memory admission needs its own purpose-specific, revocable authorization, provenance/third-party screening, correction handling, licensing or reuse review, and independent quality gates. There is **no automatic transition** from `REVIEW_ELIGIBLE` to any of those effects in this implementation.
5. **Training evaluation:** Distinguish prompt-context demonstrations, curation packages, LoRA updates, quantization and held-out behavioral changes. A GGUF label or output score does not prove new neural weights; a small random-model pilot does not establish useful Vera learning. Require before/after adapter hashes, frozen-model and corrupted-label controls, reserved tasks, reload persistence and an identified runtime/provider for each claim.

## Source-grounded nearby workbenches (checked 2026-10-29)

- [`bt2` main @ `b3d2a0f9`](https://github.com/thebrazenbeard/bt2/blob/b3d2a0f9506af68b923ddf5628858f3b2efb3405/README.md) describes modules and conformance, but explicitly does **not** claim a qualified installed currentness provider.
- [`labyrinth` main @ `39a95ac1`](https://github.com/thebrazenbeard/labyrinth/blob/39a95ac1d12cce372de980b8cad2bc41016e1705/README.md) distinguishes in-context demonstrations, a toy numeric backend and optional HF/PEFT LoRA path; it does not claim generalized reasoning improvement from a random-model adapter smoke test.
- [`model-training` main @ `d1540985`](https://github.com/thebrazenbeard/model-training/blob/d1540985e151fb62d9f78df26c81dfa4a75e4d2c/README.md) describes public-source bootcamp capsules, **not** neural-weight changes, and explicitly forbids private chat transcripts in its public workflow.
- [`vera-model` main @ `a106bd2a`](https://github.com/thebrazenbeard/vera-model/blob/a106bd2aabf8c9a819eea92c862d2609d04d25e7/README.md) describes an optional pinned local model sidecar with **no** default tool/memory write authority or qualified provider cutover.

## Negative controls

`test_chatgpt_learning_boundary.py` exercises synthetic owner-scoped historical review without granting model access/weights/identity/currentness; refuses training-purpose scopes under recall consent; quarantines assistant/tool, third-party and superseded material; and checks that an injection string stays source data in the catalog. These are source tests only, not physical/security proof.

The account source ZIP remains private on Lappy. No source conversations, keys, attachments or actual training corpora are committed with these tests.
