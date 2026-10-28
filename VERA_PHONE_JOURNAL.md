# Vera Phone Journal — encrypted local transcript archive

This is a separate, opt-in **full-history archive** for Vera mobile inference.
It is deliberately distinct from STM's bounded working-context API and the
`v-e-r-a` encrypted operator-owned transcript vault.

- AES-256-GCM encrypts each accepted user/assistant turn with unique nonces
  and authenticated session/request association.
- SQLite stores ciphertext, timestamps, opaque session/request IDs and a keyed
  integrity binding. It does **not** store plaintext prompts or replies.
- Existing requests can be idempotently deduplicated using the same request ID;
  reusing an ID with different contents is rejected.
- `recent(session_id,limit,max_bytes)` returns **bounded** short-term context
  for an authorized local caller. The archive retains all successful turns
  until the operator explicitly deletes that session.
- The archive is **untrusted conversation evidence**, not validated facts,
  long-term distilled memory, tool authority or ChatGPT account history.
- No HTTP, token-sharing, discovery, implicit automatic exports, LLM training
  or storage to public GitHub is implemented in this package.

`cryptography` is required for AESGCM. The encryption key is **exactly 32
random bytes**, created separately and stored outside the repository. Protect
the parent directory, key and journal with filesystem ACLs; the key is not
automatically escrowed. Losing the key makes ciphertext unrecoverable. Copying
both key and DB defeats encryption, so encryption cannot replace machine
security. On Windows, the calling service identity must have access.

For example, from a private local script **not in the repository**:

```python
from pathlib import Path
from stm_phone_journal import EncryptedJournal
j = EncryptedJournal(Path("private/transcripts.sqlite3"), Path("private/key.bin"))
j.append_turn("session_from_phone_20261028", "request_from_phone_20261028",
              "vera-local:latest", "example question", "example reply")
print(j.count("session_from_phone_20261028"))
print(j.recent("session_from_phone_20261028", limit=5))
```

This is a source candidate for an opt-in gateway integration, not proof that
Vera is already archiving mobile chats. Do not merge this package into canonical
STM behavior without a separate API and security review. To import older
ChatGPT history, use an explicit export with source provenance and consent;
no local code automatically accesses ChatGPT's entire account history.
