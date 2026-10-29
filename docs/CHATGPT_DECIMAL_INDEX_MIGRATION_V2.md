# ChatGPT secondary index: Decimal-safe V2 candidate, not installed

Status: **SOURCE-ONLY EXPERIMENTAL CODEC** (`STM_CHATGPT_DECIMAL_PROJECTION_V2_CANDIDATE`).

## Problem proved against legacy V1

The V1 importer's `ijson.items(..., use_float=True)` converts arbitrary JSON
fractions to Python binary64. Distinct decimal tokens such as
`0.12345678901234567890` and `0.12345678901234567891` both become
`0.12345678901234568`; V1's canonical indexed JSON and per-row keyed digest
therefore collide. This does **not** corrupt the separately AES-GCM-preserved
original ZIP, whose source SHA remains byte-authenticated. It does mean the
secondary per-conversation index is not byte-exact source JSON, and a recount
over the same lossy projection cannot establish byte-exact per-row fidelity.

## Candidate only

[`chatgpt_decimal_codec_v2.py`](../chatgpt_decimal_codec_v2.py) supplies a
version-marked, opt-in, bounded JSON projection with `Decimal` parsing and a
deterministic number writer. It rejects binary floats, NaN/Infinity, duplicate
object keys, noncanonical V2 input, excessive depth/node/output size and
unknown value types. Its tests prove high-precision decimal coefficient/scale
distinctions survive which legacy V1 loses.

This **does not** reproduce original token bytes: equivalent exponent spellings
(`1e0` / `1e+00`), unescaped versus escaped strings, ordering, whitespace,
and integer `-0` versus `0` can still collapse under a canonical projection.
That distinction is deliberate. Only the original preserved ZIP is presently
byte-lossless. V2 does not read private archives, change SQL schemas, encrypt
records, authenticate a user, perform a migration, or grant memory/model/tool
authority. No current V1 reader automatically recognizes this candidate.

## Required separately authorized migration

1. Pin the exact running host implementation, format, key/owner scope and
   existing authenticated backup/restore evidence. Establish a recoverable
   read-only rehearsal without touching the existing V1 rows or key file.
2. Parse source using an explicitly Decimal-preserving path (for ijson,
   `use_float=False`), with bounded rows. Do **not** construct V2 from already
   rounded V1 JSON: lost numeric precision cannot be reconstructed that way.
3. Introduce a separate versioned index namespace/table and explicit codec ID;
   apply a distinct AEAD AAD and HMAC domain for V2. Never reinterpret V1
   ciphertext or digests as V2. Keep V1 available for rollback/recomparison.
4. If per-conversation **byte-exact** evidence is a requirement, capture and
   authenticate the original raw source-token span/digest during streaming
   parse, or derive directly from the authenticated full ZIP on demand. A
   canonical Decimal projection alone is insufficient for this claim.
5. Qualify duplicate-ID handling, old/new mixed formats, crash recovery,
   idempotence, source SHA, complete recount, owner-revocation behavior,
   Windows/Android compatibility, disk exhaustion and backup/restore.
6. Separately authorize private host installation, then independently observe
   readback and selected-model behavior. Neither a codec test nor an imported
   historical assertion automatically admits personal/current memory or
   triggers neural-weight training.

## Synthetic verification and exact scope

Run from STM source checkout:

```sh
python -B -m unittest test_chatgpt_decimal_codec_v2 -v
```

The tests include paired high-precision decimals, exponent spelling, integer
negative zero, NaN/Infinity, duplicate keys, canonical ordering, legacy V1
separation, resource limits and marker rejection. A PASS is **test evidence for
this candidate codec**, not a qualified V2 migration or Lappy runtime read.
