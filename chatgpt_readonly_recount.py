"""Read-only operator entrypoint for reconciling a private ChatGPT export.

The ordinary ChatGPTArchive constructor initializes SQLite schema and can
write. This view deliberately bypasses that constructor and opens a preexisting
index using SQLite's ``mode=ro`` URI. It must run only inside the owner's
private host boundary: paths, source IDs, archive keys and conversations are
never written to a report or returned to a model.

Successful source/index reconciliation is *not* a memory-admission, ownership,
model-inference, or training qualification. Optional ciphertext readback is a
separate and substantially more expensive audit.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hmac
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from chatgpt_archive import ChatGPTArchive, ImportFailure, _AAD, _SHA
from chatgpt_source_recount import verify_source_index


class ReadOnlyArchiveView(ChatGPTArchive):
    """Existing vault reader with no schema setup or write-capable DB handle."""

    def __init__(self, vault_dir: str | Path, key_file: str | Path):
        root_input = Path(vault_dir)
        key_input = Path(key_file)
        if (root_input.is_symlink() or not root_input.is_dir()
                or key_input.is_symlink() or not key_input.is_file()):
            raise ImportFailure("preexisting private vault and key are required")
        self.root = root_input.resolve(strict=True)
        self.key_file = key_input.resolve(strict=True)
        self.db_path = self.root / "index.sqlite3"
        if self.db_path.is_symlink() or not self.db_path.is_file():
            raise ImportFailure("preexisting private archive index required")
        self.key = self.key_file.read_bytes()
        if len(self.key) != 32:
            raise ImportFailure("invalid private archive key")
        self.cipher = AESGCM(self.key)
        self._index_uri = self.db_path.resolve(strict=True).as_uri() + "?mode=ro"
        with closing(self._db()) as db:
            check = db.execute("SELECT key_check FROM vault_meta WHERE id=1").fetchone()
            expected = hmac.digest(self.key, _AAD + b"key-check", "sha256")
            if check is None or not hmac.compare_digest(check[0], expected):
                raise ImportFailure("private archive key authentication failed")

    def _db(self):
        db = sqlite3.connect(self._index_uri, uri=True, timeout=30)
        db.execute("PRAGMA query_only=ON")
        return db

    def import_zip(self, source: str | Path):
        """Do not expose the base class's filesystem-writing import path."""
        raise ImportFailure("read-only archive view cannot import sources")

    def _encrypted_zip_copy(self, source, export_sha):
        """Fail closed even when an inherited import helper is called."""
        raise ImportFailure("read-only archive view cannot write sealed sources")

    def sole_verified_export(self) -> str:
        """Refuse ambiguous vaults instead of printing/guessing source IDs."""
        with closing(self._db()) as db:
            # Two rows suffice to reject ambiguity; a malformed/untrusted
            # index must not make this operator audit materialize an
            # unbounded number of source IDs in process memory.
            rows = db.execute(
                "SELECT export_sha FROM imports WHERE verified=1 LIMIT 2"
            ).fetchall()
        if len(rows) != 1 or not isinstance(rows[0][0], str) or not _SHA.fullmatch(rows[0][0]):
            raise ImportFailure("expected exactly one complete indexed source")
        return rows[0][0]


def recount_existing_vault(
    *, vault_dir: str | Path, key_file: str | Path, original_zip: str | Path,
    verify_ciphertext: bool = False,
) -> dict[str, int | bool]:
    """Reconcile selected original ZIP using an existing read-only index.

    Does not call ``ChatGPTArchive.__init__`` or mutate the source, key,
    ciphertext, index or verified flags. When asked, independently authenticates
    the encrypted original ZIP and each indexed conversation; this adds a full
    encrypted-source pass and all-record decryption to the source recount.
    """
    if type(verify_ciphertext) is not bool:
        raise ImportFailure("invalid verification option")
    archive = ReadOnlyArchiveView(vault_dir, key_file)
    export_sha = archive.sole_verified_export()
    result = verify_source_index(archive, original_zip, export_sha)
    if verify_ciphertext:
        sealed = archive.verify(export_sha)
        if not sealed["archive_verified"] or sealed["verified"] != result["unique_conversations"]:
            raise ImportFailure("source/index and encrypted archive count mismatch")
    return {**result, "read_only_index": True,
            "ciphertext_authenticated_in_this_run": verify_ciphertext,
            "memory_admitted": False, "model_learning_performed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description="Owner-local read-only ChatGPT source/index audit")
    parser.add_argument("--vault-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--zip", dest="source_zip", type=Path, required=True)
    parser.add_argument("--verify-ciphertext", action="store_true")
    args = parser.parse_args()
    try:
        result = recount_existing_vault(
            vault_dir=args.vault_dir, key_file=args.key_file,
            original_zip=args.source_zip,
            verify_ciphertext=args.verify_ciphertext,
        )
    except Exception:
        # CLI error text must not echo a source path, export fingerprint, ID,
        # parser body, authentication key or historical message.
        print(json.dumps({"status": "FAILED", "private_details_emitted": False}))
        return 2
    print(json.dumps({"status": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
