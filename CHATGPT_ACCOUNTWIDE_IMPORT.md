# Entire ChatGPT account export — lossless private Lappy import

This is a **separate** account-wide export ingest, not just Build Team Two,
a Project, an individual conversation, or a replacement for the short-term
turn journal. The implementation is deliberately scoped to **all conversations
present in each ChatGPT data-export ZIP provided by the account owner**.

## Coverage rules

- Read every `conversations.json` and numbered
  `conversations_1.json`, `conversations-1.json`, etc., even if nested
  inside an export directory. Large JSON arrays are streamed via `ijson`.
- Preserve each entire conversation object (ID, title, timestamps, full message
  mapping including metadata, image/file references, project/archival fields
  when supplied, unrecognized fields) **encrypted**, without reducing it to
  plain text or a summary.
- Keep a **lossless AES-256-GCM encrypted copy of the entire original ZIP**
  including any images, files, and unrelated account data it contains.
  Attachments are not independently indexed, but remain recoverable from the
  encrypted original archive by future authorized tooling.
- Reconcile source rows = unique conversation IDs + duplicate identical rows;
  conflicting IDs, unknown numbered-part naming, malformed JSON, encrypted
  entries, zero conversation records, and lost archive integrity fail closed.
- Verify source ZIP encryption and every indexed record by authenticated
  decryption and SHA/HMAC checks before stating it was imported.
- Re-importing the identical ZIP is idempotent. Later exports are retained as
  separately timestamped, content-complete versions; existing history is not
  overwritten.
- The import does not create model beliefs, train a model, change chat records
  on ChatGPT, or grant tools/authorization based on imported text. All chats
  are historical, **untrusted source data**.

## What "all" means

The account export reflects data the service actually makes available for
that account/workspace at export time. Archived and Project conversations
should be examined within the export; there is **no Project filter** here.
Deleted chats and temporary chats that are no longer available cannot be
reconstructed. If the user has multiple OpenAI accounts or organizational
workspaces, obtain a separate eligible export from each. An unsupported
format will fail rather than quietly produce a misleading partial archive.

## Secure local setup (Lappy only)

The runtime vault is outside source control at:

`%LOCALAPPDATA%\VeraPhoneGateway\chatgpt-account-history`

Its random 32-byte key is local and private. Protect the vault folder and
key using Windows ACLs for the operator, SYSTEM and Administrators. The key is
*not committed*, copied into Blotter, or transmitted by the phone gateway.
Because the key resides on the same Lappy, this does not protect against
a fully compromised operator account; plan an offline recovery backup before
relying on the archive as the only surviving copy.

Dependencies: `pip install -r requirements-account-import.txt`

Place the newest **official ChatGPT export ZIP** on Lappy via a private
transfer; do not commit it to any GitHub repo. No ZIP is available at the time
this importer was initially prepared. On the user-selected local file:

```powershell
$vault = "$env:LOCALAPPDATA\VeraPhoneGateway\chatgpt-account-history"
py -3 chatgpt_archive.py import --vault-dir $vault --key-file "$vault\key.bin" --zip "C:\private\ChatGPT-export.zip"
py -3 chatgpt_archive.py status --vault-dir $vault --key-file "$vault\key.bin"
py -3 chatgpt_archive.py verify --vault-dir $vault --key-file "$vault\key.bin" --export-sha256 "<digest returned by import>"
```

Do not substitute an old ChatGPT export for the current state. OpenAI's
download links expire and an account-wide export may take several days.

## Operational and security limits

- A successful **synthetic test** qualifies the importer code, NOT historical
  account coverage; only a fresh real ZIP and source/index readback qualify it.
- The ciphertext index provides exact conversation-ID retrieval in Python;
  this first version is not a phone-network search API or semantic retriever.
- No raw archives, encryption keys, conversation text, or account metadata
  should be pushed to the **public** `thebrazenbeard/stm` repository.
- Storage for attachments is encrypted via the full ZIP, but attachment file
  extraction and binary-media indexing require separate reviewed tools.
- Avoid republishing account data in support logs, CI, Blotter or chat.
