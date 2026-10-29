"""Synthetic catalog regression tests: no real ChatGPT messages are fixtures."""
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
import zipfile
import json
import gc

from chatgpt_archive import ChatGPTArchive
from chatgpt_catalog import ChatCatalog, CatalogError


def conversation(cid="synthetic-convo", *, title="Rose garden engineering",
                 role="user", optout=False, scope="global", body="Rose garden source notes",
                 thoughts=True):
    nodes={
        "n1":{"message":{"id":"m1","author":{"role":role},
                         "content":{"content_type":"text","parts":[body]}}},
        "n2":{"message":{"id":"m2","author":{"role":"assistant"},
                         "content":{"content_type":"text","parts":["Response regarding: "+body[:80]]}}}
    }
    if thoughts:
        nodes["n3"]={"message":{"id":"m3","author":{"role":"assistant"},
                 "content":{"content_type":"thoughts","parts":["SECRET HIDDEN REASONING NOT FOR RECALL"]}}}
    return {"id":cid,"title":title,"create_time":1700000000.0,
            "update_time":1700001000.0,"is_archived":True,
            "is_do_not_remember":optout,"memory_scope":scope,"mapping":nodes}


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.vault=self.root/"vault"
        self.vault.mkdir()
        self.key=self.vault/"key.bin"
        self.key.write_bytes(os.urandom(32))
        self.archive=ChatGPTArchive(self.vault,self.key)
        self.path=self.vault/"catalog.sqlite3"

    def tearDown(self):
        self.archive = None
        gc.collect()

    def setup_archive(self, *convs):
        path=self.root/"source.zip"
        with zipfile.ZipFile(path,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("conversations-000.json",json.dumps(convs))
        self.archive.import_zip(path)
        return ChatCatalog(self.archive,self.path,owner="owner-local")

    def test_all_conversations_and_tagged_index(self):
        c=self.setup_archive(conversation(),conversation("two",title="Novel manuscript",body="Chapter one begins"))
        outcome=c.build()
        self.assertEqual(outcome["cataloged"],2)
        self.assertTrue(outcome["completed"])
        self.assertEqual(outcome["readable_nodes"],4)
        self.assertEqual(outcome["indexed_chunks"],4)
        self.assertEqual(outcome["excluded_nodes"],2)
        self.assertEqual(len(c.search(owner="owner-local",query="rose garden")),1)
        self.assertEqual(len(c.search(owner="owner-local",query="chapter begins")),1)
        self.assertIn("creative-writing",c.tags())
        self.assertEqual(c.tags()["creative-writing"],1)
        indexbytes=self.path.read_bytes()
        self.assertNotIn(b"Rose garden source notes",indexbytes)
        self.assertNotIn(b"SECRET HIDDEN REASONING",indexbytes)

    def test_optout_and_unspecified_prevent_memory_recall(self):
        opt=conversation("private",title="secret moon",optout=True,body="secret moon")
        unspecified=conversation("unknown",title="secret wave",optout=None,body="secret wave")
        c=self.setup_archive(opt,unspecified)
        result=c.build()
        self.assertEqual(result["cataloged"],2)
        self.assertEqual(result["recall_eligible_conversations"],0)
        self.assertEqual(result["indexed_chunks"],0)
        self.assertEqual(c.search(owner="owner-local",query="secret moon"),[])

    def test_wrong_owner_and_wrong_key_refused(self):
        c=self.setup_archive(conversation())
        c.build()
        with self.assertRaises(CatalogError):
            c.search(owner="other-owner",query="rose garden")
        self.key.write_bytes(os.urandom(32))
        with self.assertRaises(Exception):
            ChatCatalog(ChatGPTArchive(self.vault,self.key),self.path,owner="owner-local")

    def test_scope_filter_and_idempotence(self):
        c=self.setup_archive(conversation(scope="project-X"),
                             conversation("two",title="Rose garden",body="roses",scope="global"))
        first=c.build()
        second=c.build()
        self.assertEqual(first,second)
        self.assertEqual(first["cataloged"],2)
        self.assertEqual(len(c.search(owner="owner-local",query="rose garden",scopes=["project-X"])),1)

    def test_tampering_refused(self):
        c=self.setup_archive(conversation())
        c.build()
        with sqlite3.connect(self.path) as db:
            sealed=db.execute("SELECT sealed FROM chunks LIMIT 1").fetchone()[0]
            db.execute("UPDATE chunks SET sealed=?",
                       (sealed[:-1]+bytes([sealed[-1]^0xff]),))
        with self.assertRaises(CatalogError):
            c.search(owner="owner-local",query="rose garden")

    def test_bounds_and_unverified_import_refused(self):
        c=self.setup_archive(conversation())
        c.build()
        with self.assertRaises(CatalogError):
            c.search(owner="owner-local",query="rose",limit=30)
        with self.assertRaises(CatalogError):
            c.search(owner="owner-local",query="x")
        with sqlite3.connect(self.archive.db_path) as db:
            db.execute("UPDATE imports SET verified=0")
        with self.assertRaises(CatalogError):
            ChatCatalog(self.archive,self.root/"other_catalog.sqlite3",owner="owner-local")

if __name__=="__main__":
    unittest.main()
