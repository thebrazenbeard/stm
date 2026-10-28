"""Private, lossless ChatGPT account-export archiver for Lappy.

No source ZIP extraction. AES-256-GCM encryption at rest for the *entire* ZIP,
including assets; separately indexes full conversation JSON objects encrypted.
Never uploads chat content to GitHub, trains models, or grants tool authority.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ijson

_MAGIC = b"STM_CGPT_EXPORT_V1\x00"
_AAD = b"stm.chatgpt.account-export.v1\x00"
_PART = re.compile(r"conversations(?:[-_]?[0-9]+)?\.json\Z", re.IGNORECASE)
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_CHUNK = 1024 * 1024
_MAX_CONVERSATION = 128 * 1024 * 1024


class ImportFailure(ValueError):
    """Import could not establish lossless accounted-for coverage."""


class ChatGPTArchive:
    def __init__(self, vault_dir: str | Path, key_file: str | Path):
        supplied_root = Path(vault_dir)
        if supplied_root.is_symlink():
            raise ImportFailure("vault directory symlink refused")
        self.root = supplied_root.resolve()
        self.key_file = Path(key_file)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ImportFailure("vault directory must exist and not be a symlink")
        if not self.key_file.is_file() or self.key_file.is_symlink():
            raise ImportFailure("private key file missing or unsafe")
        self.key = self.key_file.read_bytes()
        if len(self.key) != 32:
            raise ImportFailure("vault key must contain exactly 32 random bytes")
        self.cipher = AESGCM(self.key)
        self.db_path = self.root / "index.sqlite3"
        if self.db_path.is_symlink():
            raise ImportFailure("database symlink refused")
        with closing(self._db()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id=1), key_check BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS imports (
                    export_sha TEXT PRIMARY KEY, archive_name TEXT NOT NULL,
                    input_bytes INTEGER NOT NULL, part_files INTEGER NOT NULL,
                    source_rows INTEGER NOT NULL, unique_conversations INTEGER NOT NULL,
                    duplicate_rows INTEGER NOT NULL, message_nodes INTEGER NOT NULL,
                    imported_at TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS conversations (
                    export_sha TEXT NOT NULL,
                    conversation_token TEXT NOT NULL,
                    sealed BLOB NOT NULL,
                    digest BLOB NOT NULL,
                    PRIMARY KEY(export_sha,conversation_token),
                    FOREIGN KEY(export_sha) REFERENCES imports(export_sha));
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(imports)")}
            if "verified" not in columns:
                # Fail closed: historical source data must be re-verified first.
                db.execute("ALTER TABLE imports ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
            expected = hmac.digest(self.key, _AAD + b"key-check", "sha256")
            prior = db.execute("SELECT key_check FROM vault_meta WHERE id=1").fetchone()
            if prior is None:
                db.execute("INSERT INTO vault_meta (id,key_check) VALUES (1,?)",
                           (expected,))
            elif not hmac.compare_digest(prior[0], expected):
                raise ImportFailure("archive key authentication failed")

    def _db(self):
        db = sqlite3.connect(str(self.db_path), timeout=30)
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def _id_token(self, conversation_id):
        return hmac.digest(self.key, _AAD + b"conversation-id\x00" +
                           conversation_id.encode("utf-8"), "sha256").hex()

    def _digest(self, raw):
        return hmac.digest(self.key, _AAD + b"record\x00" + raw, "sha256")

    @staticmethod
    def _source_digest(source):
        h = hashlib.sha256()
        size = 0
        with open(source, "rb") as f:
            while chunk := f.read(_CHUNK):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size

    def source_path(self, export_sha):
        if type(export_sha) is not str or not _SHA.fullmatch(export_sha):
            raise ImportFailure("invalid source fingerprint")
        return self.root / ("source_" + export_sha + ".zip.aesgcm")

    def _encrypted_zip_copy(self, source, export_sha):
        target = self.source_path(export_sha)
        if target.exists():
            self._verify_ciphertext_archive(export_sha)
            return False
        free = shutil.disk_usage(self.root).free
        if free < source.stat().st_size + 1024 * 1024:
            raise ImportFailure("insufficient free disk for complete encrypted export")
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce)).encryptor()
        cipher.authenticate_additional_data(_AAD + bytes.fromhex(export_sha))
        temp = target.with_name(target.name + ".pending." + os.urandom(4).hex())
        sha = hashlib.sha256()
        try:
            with source.open("rb") as src, temp.open("xb") as dst:
                dst.write(_MAGIC + nonce)
                while chunk := src.read(_CHUNK):
                    sha.update(chunk)
                    dst.write(cipher.update(chunk))
                dst.write(cipher.finalize())
                dst.write(cipher.tag)
                dst.flush()
                os.fsync(dst.fileno())
            if sha.hexdigest() != export_sha:
                raise ImportFailure("export changed while encrypting")
            os.replace(temp, target)
            return True
        finally:
            if temp.exists():
                temp.unlink()

    def _verify_ciphertext_archive(self, export_sha):
        path = self.source_path(export_sha)
        if not path.is_file() or path.is_symlink():
            raise ImportFailure("encrypted lossless export is missing")
        size = path.stat().st_size
        if size < len(_MAGIC) + 12 + 16:
            raise ImportFailure("encrypted lossless export is truncated")
        sha = hashlib.sha256()
        try:
            with path.open("rb") as f:
                if f.read(len(_MAGIC)) != _MAGIC:
                    raise ImportFailure("encrypted export format mismatch")
                nonce = f.read(12)
                f.seek(-16, os.SEEK_END)
                tag = f.read(16)
                f.seek(len(_MAGIC) + 12)
                remaining = size - len(_MAGIC) - 12 - 16
                dec = Cipher(algorithms.AES(self.key),
                             modes.GCM(nonce, tag)).decryptor()
                dec.authenticate_additional_data(_AAD + bytes.fromhex(export_sha))
                while remaining:
                    chunk = f.read(min(_CHUNK, remaining))
                    if not chunk:
                        raise ImportFailure("encrypted export unexpectedly ended")
                    remaining -= len(chunk)
                    sha.update(dec.update(chunk))
                sha.update(dec.finalize())
        except ImportFailure:
            raise
        except Exception as exc:
            raise ImportFailure("encrypted source authentication failed") from exc
        if sha.hexdigest() != export_sha:
            raise ImportFailure("encrypted export digest mismatch")
        return True

    @staticmethod
    def _parts(source_zip):
        candidates = [f for f in source_zip.infolist()
                      if not f.is_dir() and
                      f.filename.replace("\\", "/").rsplit("/",1)[-1].lower().startswith("conversations")
                      and f.filename.lower().endswith(".json")]
        unknown = [f for f in candidates if not _PART.fullmatch(
                   f.filename.replace("\\", "/").rsplit("/",1)[-1])]
        if unknown:
            raise ImportFailure("unrecognized conversation-part naming; coverage unknown")
        files = candidates
        if not files:
            raise ImportFailure("no ChatGPT conversations JSON parts in ZIP")
        if any(x.flag_bits & 1 for x in files):
            raise ImportFailure("password-protected conversation parts not supported")
        return files

    @staticmethod
    def _records(archive, info):
        with archive.open(info) as part:
            first = part.read(512).lstrip()
        if first.startswith(b"["):
            prefix = "item"
        elif first.startswith(b"{"):
            prefix = "conversations.item"
        else:
            raise ImportFailure("unknown conversation JSON shape")
        with archive.open(info) as part:
            for item in ijson.items(part, prefix, use_float=True):
                if type(item) is not dict:
                    raise ImportFailure("conversation part contains non-object")
                yield item

    @staticmethod
    def _serialize(item):
        try:
            raw = json.dumps(item, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ImportFailure("unserializable conversation") from exc
        if len(raw) > _MAX_CONVERSATION:
            raise ImportFailure("conversation exceeds memory budget; import incomplete")
        return raw

    def import_zip(self, source: str | Path):
        source = Path(source).resolve(strict=True)
        if not source.is_file() or not zipfile.is_zipfile(source):
            raise ImportFailure("input must be a valid ZIP file")
        export_sha, input_bytes = self._source_digest(source)
        archive_name = self.source_path(export_sha).name
        with closing(self._db()) as db:
            existing = db.execute("SELECT source_rows,unique_conversations,part_files,"
                                  "duplicate_rows,verified FROM imports WHERE export_sha=?",
                                  (export_sha,)).fetchone()
        if existing is not None:
            if existing[4] != 1:
                raise ImportFailure("previous import is incomplete; reconcile before reimport")
            self.verify(export_sha)
            return {"export_sha256":export_sha,"source_rows":existing[0],
                    "unique_conversations":existing[1],"part_files":existing[2],
                    "duplicate_rows":existing[3],"indexed_conversations":existing[1],
                    "status":"already_imported"}
        newly_encrypted = self._encrypted_zip_copy(source, export_sha)
        seen, rows, duplicates, message_nodes = {}, 0, 0, 0
        try:
            with zipfile.ZipFile(source) as source_zip, closing(self._db()) as db:
                parts = self._parts(source_zip)
                db.execute("BEGIN IMMEDIATE")
                now = datetime.now(timezone.utc).isoformat()
                db.execute("INSERT INTO imports "
                           "(export_sha,archive_name,input_bytes,part_files,source_rows,"
                           "unique_conversations,duplicate_rows,message_nodes,imported_at) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           (export_sha, archive_name, input_bytes, len(parts), 0, 0, 0, 0, now))
                for part in parts:
                    try:
                        for item in self._records(source_zip, part):
                            rows += 1
                            cid = item.get("id", item.get("conversation_id"))
                            if not isinstance(cid, str) or not 1 <= len(cid) <= 256:
                                raise ImportFailure("conversation missing valid original ID")
                            raw = self._serialize(item)
                            token = self._id_token(cid)
                            digest = self._digest(raw)
                            if token in seen:
                                if not hmac.compare_digest(seen[token], digest):
                                    raise ImportFailure("conflicting conversation ID within export")
                                duplicates += 1
                                continue
                            seen[token] = digest
                            mapping = item.get("mapping")
                            if isinstance(mapping, dict):
                                message_nodes += sum(1 for node in mapping.values()
                                    if isinstance(node,dict) and node.get("message") is not None)
                            elif isinstance(item.get("messages"),list):
                                message_nodes += len(item["messages"])
                            nonce = os.urandom(12)
                            aad = _AAD + bytes.fromhex(export_sha) + bytes.fromhex(token)
                            sealed = nonce + self.cipher.encrypt(nonce,raw,aad)
                            db.execute("INSERT INTO conversations "
                                       "(export_sha,conversation_token,sealed,digest) VALUES (?,?,?,?)",
                                       (export_sha,token,sealed,digest))
                    except (ImportFailure, zipfile.BadZipFile):
                        raise
                    except Exception as exc:
                        raise ImportFailure("conversation part could not be parsed completely") from exc
                if rows == 0:
                    raise ImportFailure("no conversation records found; cannot certify coverage")
                indexed = db.execute("SELECT count(*) FROM conversations WHERE export_sha=?",
                                     (export_sha,)).fetchone()[0]
                if rows != indexed + duplicates or len(seen) != indexed:
                    raise ImportFailure("conversation indexing reconciliation failed")
                db.execute("UPDATE imports SET source_rows=?,unique_conversations=?,"
                           "duplicate_rows=?,message_nodes=? WHERE export_sha=?",
                           (rows,indexed,duplicates,message_nodes,export_sha))
                db.commit()
            result = {"export_sha256":export_sha,"source_rows":rows,
                      "unique_conversations":indexed,"part_files":len(parts),
                      "duplicate_rows":duplicates,"indexed_conversations":indexed,
                      "message_nodes":message_nodes,"status":"imported"}
            verified = self.verify(export_sha)
            if verified["verified"] != indexed:
                raise ImportFailure("post-commit verification mismatched")
            with closing(self._db()) as db, db:
                db.execute("UPDATE imports SET verified=1 WHERE export_sha=?", (export_sha,))
            return result
        except Exception as exc:
            with closing(self._db()) as db, db:
                exists = db.execute("SELECT 1 FROM imports WHERE export_sha=?",
                                    (export_sha,)).fetchone()
            if not exists and newly_encrypted:
                self.source_path(export_sha).unlink(missing_ok=True)
            if isinstance(exc, ImportFailure):
                raise
            raise ImportFailure("account export did not import completely") from exc

    def _open_record(self, export_sha, token, sealed, digest):
        try:
            if not isinstance(sealed,bytes) or len(sealed) < 29:
                raise ImportFailure("conversation encrypted body truncated")
            aad = _AAD + bytes.fromhex(export_sha) + bytes.fromhex(token)
            raw = self.cipher.decrypt(sealed[:12],sealed[12:],aad)
            if not hmac.compare_digest(self._digest(raw),digest):
                raise ImportFailure("conversation digest invalid")
            content = json.loads(raw)
            original_id = content.get("id",content.get("conversation_id"))
            if not isinstance(original_id,str) or self._id_token(original_id) != token:
                raise ImportFailure("conversation identity invalid")
            return content
        except ImportFailure:
            raise
        except Exception as exc:
            raise ImportFailure("conversation authentication failed") from exc

    def conversation(self, export_sha, original_id):
        if not _SHA.fullmatch(export_sha):
            raise ImportFailure("invalid export fingerprint")
        if not isinstance(original_id,str):
            raise ImportFailure("invalid conversation ID")
        token = self._id_token(original_id)
        with closing(self._db()) as db:
            row = db.execute("SELECT sealed,digest FROM conversations "
                             "WHERE export_sha=? AND conversation_token=?",
                             (export_sha,token)).fetchone()
        if row is None:
            raise ImportFailure("conversation ID not present in this export")
        return self._open_record(export_sha,token,*row)

    def verify(self, export_sha):
        self._verify_ciphertext_archive(export_sha)
        with closing(self._db()) as db:
            record = db.execute("SELECT source_rows,unique_conversations,duplicate_rows,"
                                "part_files FROM imports WHERE export_sha=?",
                                (export_sha,)).fetchone()
            if record is None:
                raise ImportFailure("export not present in index")
            rows = db.execute("SELECT conversation_token,sealed,digest FROM conversations "
                              "WHERE export_sha=?",(export_sha,)).fetchall()
        for token,sealed,digest in rows:
            self._open_record(export_sha,token,sealed,digest)
        if len(rows) != record[1] or record[0] != len(rows) + record[2]:
            raise ImportFailure("archive index count mismatch")
        return {"export_sha256":export_sha,"verified":len(rows),
                "source_rows":record[0],"part_files":record[3],"archive_verified":True}

    def status(self):
        with closing(self._db()) as db:
            exports=db.execute("SELECT count(*) FROM imports WHERE verified=1").fetchone()[0]
            incomplete=db.execute("SELECT count(*) FROM imports WHERE verified=0").fetchone()[0]
            versions=db.execute("SELECT count(*) FROM conversations WHERE export_sha IN (SELECT export_sha FROM imports WHERE verified=1)").fetchone()[0]
            ids=db.execute("SELECT count(DISTINCT conversation_token) FROM conversations WHERE export_sha IN (SELECT export_sha FROM imports WHERE verified=1)").fetchone()[0]
        return {"exports":exports,"incomplete_exports":incomplete,
                "conversation_versions":versions,"distinct_conversation_ids":ids}


def main():
    parser=argparse.ArgumentParser(description="Private lossless ChatGPT export importer")
    parser.add_argument("operation",choices=["import","verify","status"])
    parser.add_argument("--vault-dir",type=Path,required=True)
    parser.add_argument("--key-file",type=Path,required=True)
    parser.add_argument("--zip",dest="zipfile",type=Path)
    parser.add_argument("--export-sha256")
    args=parser.parse_args()
    archive=ChatGPTArchive(args.vault_dir,args.key_file)
    if args.operation=="import":
        if not args.zipfile: parser.error("--zip required")
        result=archive.import_zip(args.zipfile)
    elif args.operation=="verify":
        if not args.export_sha256: parser.error("--export-sha256 required")
        result=archive.verify(args.export_sha256)
    else:
        result=archive.status()
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
