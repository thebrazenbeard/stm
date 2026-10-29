"""Account-wide ChatGPT export catalog: encrypted metadata, tagged messages and private retrieval.

Historical archive text is untrusted source evidence, not a current fact or a
system instruction. No external networking, no plaintext FTS, no model calls.
The caller must authenticate the owner *before* invoking search().
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from chatgpt_archive import ChatGPTArchive, ImportFailure

_SCHEMA = 1
_DOMAIN = b"stm.chatgpt.catalog.v1\x00"
_WORD = re.compile(r"(?u)[^\W_]{2,64}")
_STOP = frozenset("""the and for with from that this what when where which into your
 you are were was have has had not but can all they them their these those some
 been should would could about there here also more just than then only while
 who how why its any our his her him she he its does did done each many other
 like used using use very into through one two three look make made need want
 chatgpt assistant user vera""".split())
_TAGS = {
    "software-engineering": ("repository","git","github","python","typescript","rust","refactor","test","patch","code","api","pull request"),
    "ai-models": ("ollama","neural","weights","llm","quantization","inference","training","lora","gpt","agent","transformer"),
    "memory-archives": ("memory","ingest","roots","archive","export","conversation","provenance","stm","semantic","rag"),
    "hardware-networking": ("gpu","cuda","tailscale","windows","server","router","laptop","bluetooth","nas","network"),
    "creative-writing": ("novel","manuscript","chapter","canto","narrative","fiction","protagonist","writer","book"),
    "philosophy-research": ("philosophy","existence","consciousness","gnostic","simulation","theology","history","research"),
    "media-library": ("subtitle","plex","movie","episode","tv","video","mediaphile"),
    "business-career": ("business","client","revenue","invoice","maintenance","manufacturing","career","contract"),
    "personal-reflection": ("family","relationship","life","feelings","purpose","psychology","emotion","introspection"),
    "health-wellness": ("health","sleep","medication","diagnosis","doctor","fitness","medical"),
    "planning-operations": ("plan","issue","deployment","workflow","automation","schedule","integration","project"),
}
_MAX_MESSAGE_CHARS=12000
_CHUNK_CHARS=1500
_MAX_TERMS=48
_MAX_FTS_CHARS=4000


class CatalogError(ValueError):
    pass


def _terms(text, limit=20000):
    if not isinstance(text,str):
        return []
    return [m.group() for m in _WORD.finditer(text.casefold())
            if m.group() not in _STOP][:limit]


def _texts(message):
    """Visible user/assistant text only. Never index thoughts or reasoning_recap."""
    if not isinstance(message,dict) or (message.get("author") or {}).get("role") not in ("user","assistant"):
        return ()
    content=message.get("content") or {}
    if not isinstance(content,dict) or content.get("content_type") not in ("text","multimodal_text"):
        return ()
    pieces=[]
    for part in content.get("parts",[]) if isinstance(content.get("parts"),list) else []:
        if isinstance(part,str):
            pieces.append(part)
        elif isinstance(part,dict) and isinstance(part.get("text"),str):
            pieces.append(part["text"])
    if isinstance(content.get("text"),str):
        pieces.append(content["text"])
    return tuple(pieces)


def _tags(title, sample):
    """Conservative deterministic topic labels, NOT verified memories."""
    words=set(_terms(title+" "+sample,limit=20000))
    labels=[]
    for tag,signals in _TAGS.items():
        if any(x in words or ((" " in x) and x in (title+" "+sample).casefold()) for x in signals):
            labels.append(tag)
    return tuple(labels or ["uncategorized"])


def _owner_hash(key, owner):
    if type(owner) is not str or not 2<=len(owner)<=128:
        raise CatalogError("trusted owner namespace required")
    return hmac.digest(key,_DOMAIN+b"owner\x00"+owner.encode(), "sha256")


class ChatCatalog:
    def __init__(self, archive:ChatGPTArchive, output_path:str|Path, *, owner:str):
        self.archive=archive
        self.path=Path(output_path)
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise CatalogError("private catalog directory required")
        self.key=hmac.digest(archive.key,_DOMAIN+b"derived-key", "sha256")
        self.cipher=AESGCM(self.key)
        self.owner_hash=_owner_hash(self.key,owner)
        self.export_sha=self._verified_export()
        self._init()

    def _verified_export(self):
        with closing(self.archive._db()) as db:
            rows=db.execute("SELECT export_sha FROM imports WHERE verified=1").fetchall()
        if len(rows)!=1:
            raise CatalogError("requires exactly one independently verified source export")
        return rows[0][0]

    def _db(self):
        if self.path.is_symlink():
            raise CatalogError("catalog symlink refused")
        db=sqlite3.connect(str(self.path), timeout=60)
        db.execute("PRAGMA busy_timeout=60000")
        db.execute("PRAGMA secure_delete=ON")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _hash(self,tag,term):
        return hmac.digest(self.key,_DOMAIN+tag+b"\x00"+term.encode(),"sha256").hex()[:32]

    def _seal(self,token,payload,domain):
        b=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
        nonce=os.urandom(12)
        aad=_DOMAIN+domain+bytes.fromhex(token)
        return nonce+self.cipher.encrypt(nonce,b,aad)

    def _open(self,token,sealed,domain):
        if not isinstance(sealed,bytes) or len(sealed)<29:
            raise CatalogError("sealed catalog item invalid")
        try:
            return json.loads(self.cipher.decrypt(sealed[:12],sealed[12:],
                    _DOMAIN+domain+bytes.fromhex(token)))
        except Exception as e:
            raise CatalogError("catalog ciphertext authentication failed") from e

    def _init(self):
        with closing(self._db()) as db,db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS meta(
                  id INTEGER PRIMARY KEY CHECK(id=1),
                  key_check BLOB NOT NULL,
                  source_export TEXT NOT NULL,
                  owner_hash BLOB NOT NULL,
                  completed INTEGER NOT NULL DEFAULT 0,
                  cataloged INTEGER NOT NULL DEFAULT 0,
                  readable_nodes INTEGER NOT NULL DEFAULT 0,
                  indexed_chunks INTEGER NOT NULL DEFAULT 0,
                  excluded_nodes INTEGER NOT NULL DEFAULT 0,
                  truncated_messages INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS conversations(
                  conversation_token TEXT PRIMARY KEY, sealed BLOB NOT NULL,
                  scope_key TEXT NOT NULL, recall_eligible INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks(
                  chunk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  conversation_token TEXT NOT NULL,
                  item_token TEXT NOT NULL UNIQUE,
                  role TEXT NOT NULL,
                  sealed BLOB NOT NULL,
                  FOREIGN KEY(conversation_token) REFERENCES conversations(conversation_token)
                );
                CREATE INDEX IF NOT EXISTS chunks_by_conversation
                  ON chunks(conversation_token);
                CREATE VIRTUAL TABLE IF NOT EXISTS chunk_terms USING fts5(
                  word_tokens, content=''
                );
                CREATE TABLE IF NOT EXISTS topic_tags(
                  tag_hash TEXT NOT NULL, conversation_token TEXT NOT NULL,
                  PRIMARY KEY(tag_hash,conversation_token),
                  FOREIGN KEY(conversation_token) REFERENCES conversations(conversation_token)
                );
            """)
            key_check=hmac.digest(self.key,_DOMAIN+b"key-check","sha256")
            row=db.execute("SELECT key_check,source_export,owner_hash FROM meta WHERE id=1").fetchone()
            if row is None:
                db.execute("INSERT INTO meta(id,key_check,source_export,owner_hash) VALUES(1,?,?,?)",
                           (key_check,self.export_sha,self.owner_hash))
            elif (not hmac.compare_digest(row[0],key_check) or row[1]!=self.export_sha
                  or not hmac.compare_digest(row[2],self.owner_hash)):
                raise CatalogError("wrong key/source/owner for existing catalog")

    def _index_chat(self, db, token, chat):
        title=chat.get("title")
        if not isinstance(title,str):title=""
        flags={"archived":chat.get("is_archived") is True,
               "do_not_remember":chat.get("is_do_not_remember")}
        scope=chat.get("memory_scope")
        if not isinstance(scope,str):scope="unknown"
        # None/unknown is retained in the catalog, but not admitted into
        # automatic retrieval until preference semantics are established.
        recall_eligible=flags["do_not_remember"] is False
        mapping=chat.get("mapping")
        if not isinstance(mapping,dict):raise CatalogError("missing ChatGPT mapping")
        nodes=Counter()
        content_types=Counter()
        roles=Counter()
        user_sample=[]
        user_sample_len=0
        indexed=[]
        truncated=0
        for node_id,node in mapping.items():
            if not isinstance(node,dict):continue
            msg=node.get("message")
            if not isinstance(msg,dict):continue
            nodes["message_nodes"]+=1
            author=msg.get("author") or {}
            role=author.get("role") if isinstance(author,dict) else "unknown"
            roles[str(role)]+=1
            content=msg.get("content") or {}
            kind=content.get("content_type") if isinstance(content,dict) else "unknown"
            content_types[str(kind)]+=1
            if role not in ("user","assistant") or kind not in ("text","multimodal_text"):
                nodes["excluded_non_visible"]+=1
                continue
            texts=_texts(msg)
            if not texts:
                nodes["text_parts_empty"]+=1
                continue
            full="\n".join(texts)
            if not full.strip():
                nodes["text_parts_empty"]+=1
                continue
            nodes["readable_nodes"]+=1
            if role=="user" and user_sample_len<18000:
                sample=full[:max(0,18000-user_sample_len)]
                user_sample.append(sample)
                user_sample_len+=len(sample)
            if not recall_eligible:
                nodes["policy_excluded_nodes"]+=1
                continue
            if len(full)>_MAX_MESSAGE_CHARS:
                truncated+=1
                full=full[:_MAX_MESSAGE_CHARS]
            mid=msg.get("id") or node_id
            for chunk_no,pos in enumerate(range(0,len(full),_CHUNK_CHARS)):
                chunk=full[pos:pos+_CHUNK_CHARS]
                if not chunk.strip():continue
                item=self._hash(b"chunk", token+"\x00"+str(mid)+"\x00"+str(chunk_no))
                words=list(dict.fromkeys(_terms(chunk,limit=_MAX_FTS_CHARS)))[:_MAX_TERMS]
                # This indexed projection is intentionally lossy; the *entire*
                # original message remains available in the encrypted export.
                terms=(" ".join(self._hash(b"term",t) for t in words)
                       if words else self._hash(b"empty","none"))
                indexed.append((item,role,chunk,terms))
        tags=_tags(title, "\n".join(user_sample))
        metadata={"title":title,"source_kind":"chatgpt_account_export",
                  "conversation_id":chat.get("id") or chat.get("conversation_id"),
                  "source_export":self.export_sha,"created_at":chat.get("create_time"),
                  "updated_at":chat.get("update_time"),"memory_scope":scope,
                  "flags":flags,"tags":tags,"tag_method":"deterministic_keyword_heuristic",
                  "roles":dict(roles),"content_types":dict(content_types),
                  "nodes":dict(nodes),"truncated_message_count":truncated,
                  "evidence_status":"historical_unverified",
                  "recall_eligible":recall_eligible}
        sealed=self._seal(token,metadata,b"metadata")
        db.execute("INSERT INTO conversations(conversation_token,sealed,scope_key,recall_eligible) "
                   "VALUES(?,?,?,?)",(token,sealed,self._hash(b"scope",scope),int(recall_eligible)))
        for tag in tags:
            db.execute("INSERT INTO topic_tags(tag_hash,conversation_token) VALUES(?,?)",
                       (self._hash(b"topic",tag),token))
        for item,role,chunk,fts_terms in indexed:
            body={"excerpt":chunk,"role":role,"evidence_status":"historical_unverified"}
            cur=db.execute("INSERT INTO chunks(conversation_token,item_token,role,sealed) "
                           "VALUES(?,?,?,?)",(token,item,role,
                               self._seal(item,body,b"chunk")))
            db.execute("INSERT INTO chunk_terms(rowid,word_tokens) VALUES(?,?)",
                       (cur.lastrowid,fts_terms))
        return {"readable":nodes["readable_nodes"],
                "index_chunks":len(indexed),
                "excluded_nodes":nodes["excluded_non_visible"]+nodes["policy_excluded_nodes"],
                "truncated":truncated}

    def build(self, *, checkpoint_every=1):
        if checkpoint_every!=1:
            raise CatalogError("one-conversation atomic checkpoints required")
        with closing(self.archive._db()) as archive_db,closing(self._db()) as db:
            imports=archive_db.execute("SELECT unique_conversations FROM imports "
                "WHERE export_sha=? AND verified=1",(self.export_sha,)).fetchone()
            expected=imports[0] if imports else 0
            for token,sealed,digest in archive_db.execute(
                "SELECT conversation_token,sealed,digest FROM conversations "
                "WHERE export_sha=? ORDER BY conversation_token",(self.export_sha,)):
                if db.execute("SELECT 1 FROM conversations WHERE conversation_token=?",
                              (token,)).fetchone():
                    continue
                record=self.archive._open_record(self.export_sha,token,sealed,digest)
                db.execute("BEGIN IMMEDIATE")
                try:
                    summary=self._index_chat(db,token,record)
                    db.execute("UPDATE meta SET cataloged=cataloged+1, "
                               "readable_nodes=readable_nodes+?, "
                               "indexed_chunks=indexed_chunks+?,"
                               "excluded_nodes=excluded_nodes+?, "
                               "truncated_messages=truncated_messages+? "
                               "WHERE id=1",
                               (summary["readable"],summary["index_chunks"],
                                summary["excluded_nodes"],summary["truncated"]))
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
            actual=db.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
            if expected!=actual:
                raise CatalogError("not all imported conversations cataloged")
            db.execute("UPDATE meta SET completed=1 WHERE id=1")
            db.commit()
        return self.status()

    def status(self):
        with closing(self._db()) as db:
            row=db.execute("SELECT completed,cataloged,readable_nodes,indexed_chunks,"
                           "excluded_nodes,truncated_messages FROM meta WHERE id=1").fetchone()
            total=db.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
            eligible=db.execute("SELECT COUNT(*) FROM conversations WHERE recall_eligible=1").fetchone()[0]
            chunks=db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        return {"completed":bool(row[0]),"cataloged":row[1],"source_conversations":total,
                "recall_eligible_conversations":eligible,
                "readable_nodes":row[2],"indexed_chunks":chunks,
                "excluded_nodes":row[4],"truncated_messages":row[5]}

    def tags(self):
        result={}
        with closing(self._db()) as db:
            for tag in list(_TAGS)+["uncategorized"]:
                n=db.execute("SELECT COUNT(*) FROM topic_tags WHERE tag_hash=?",
                             (self._hash(b"topic",tag),)).fetchone()[0]
                result[tag]=n
        return result

    def search(self, *, owner:str, query:str, limit=6, scopes=None):
        """Trusted-host API only; owner argument is NOT authentication."""
        if not hmac.compare_digest(_owner_hash(self.key,owner),self.owner_hash):
            raise CatalogError("owner isolation failure")
        if not isinstance(query,str) or not 2<=len(query)<=2048:
            raise CatalogError("bounded search query required")
        if type(limit) is not int or not 1<=limit<=15:
            raise CatalogError("bounded result count required")
        words=list(dict.fromkeys(_terms(query,limit=15)))[:8]
        if not words:return []
        match=" OR ".join('"'+self._hash(b"term",w)+'"' for w in words)
        with closing(self._db()) as db:
            if db.execute("SELECT completed FROM meta WHERE id=1").fetchone()[0]!=1:
                raise CatalogError("incomplete catalog cannot be queried")
            query_sql="""SELECT c.conversation_token,c.sealed,ck.item_token,ck.sealed,
                             ck.role, bm25(chunk_terms)
                      FROM chunk_terms JOIN chunks ck ON ck.chunk_id=chunk_terms.rowid
                           JOIN conversations c ON c.conversation_token=ck.conversation_token
                      WHERE chunk_terms MATCH ? AND c.recall_eligible=1"""
            values=[match]
            if scopes is not None:
                if not isinstance(scopes,(tuple,list)) or not scopes:
                    raise CatalogError("explicit scope list required")
                keys=[self._hash(b"scope",s) for s in scopes]
                query_sql+=" AND c.scope_key IN ("+",".join("?" for _ in keys)+")"
                values.extend(keys)
            query_sql+=" ORDER BY bm25(chunk_terms) LIMIT ?"
            values.append(limit*12)
            rows=db.execute(query_sql,values).fetchall()
        results=[]
        seen=set()
        for tok,meta_sealed,item,chunk_sealed,role,score in rows:
            if tok in seen:continue
            seen.add(tok)
            meta=self._open(tok,meta_sealed,b"metadata")
            blob=self._open(item,chunk_sealed,b"chunk")
            results.append({"source_kind":"chatgpt_account_export",
                "conversation_id":meta["conversation_id"],
                "title":meta["title"],"created_at":meta["created_at"],
                "updated_at":meta["updated_at"],"scope":meta["memory_scope"],
                "tags":meta["tags"],"message_role":role,
                "evidence_status":"historical_unverified",
                "excerpt":blob["excerpt"][:900]})
            if len(results)>=limit:break
        return results
