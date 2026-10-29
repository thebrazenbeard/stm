import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from evidence_memory import EvidenceMemory, EvidenceError

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.key=self.root/"key.bin"
        self.key.write_bytes(os.urandom(32))
        self.db=self.root/"vault.sqlite3"
        self.memory=EvidenceMemory(self.db,self.key)

    def add(self, *, owner="owner_alpha", text="The archived rose garden had blue flowers.",
            source_id="drive:synthetic"):
        return self.memory.ingest(owner=owner,source_id=source_id,
            title="Rose garden notes",text=text,
            locator="gdrive://file/synthetic",
            observed_at="2025-01-01")

    def test_provenance_and_encrypted_retrieval(self):
        self.add()
        found=self.memory.search(owner="owner_alpha",query="rose garden")
        self.assertEqual(len(found),1)
        self.assertEqual(found[0]["source_id"],"drive:synthetic")
        self.assertEqual(found[0]["epistemic_status"],"historical_unverified")
        self.assertNotIn(b"rose garden",self.db.read_bytes())
        self.assertIn("untrusted",self.memory.context(owner="owner_alpha",query="rose"))

    def test_owner_bound_index(self):
        self.add(owner="owner_alpha")
        self.assertEqual([],self.memory.search(owner="owner_beta",query="rose garden"))
        self.assertEqual(0,self.memory.status(owner="owner_beta")["encrypted_source_revisions"])

    def test_duplicate_idempotent_and_revisions(self):
        self.assertTrue(self.add()["stored"])
        self.assertFalse(self.add()["stored"])
        self.add(text="Later notes reclassified the rose garden.")
        self.assertEqual(2,self.memory.status(owner="owner_alpha")["encrypted_source_revisions"])

    def test_unrelated_query_returns_no_context(self):
        self.add()
        self.assertEqual("",self.memory.context(owner="owner_alpha",query="jet engines"))

    def test_no_source_can_self_verify(self):
        with self.assertRaises(EvidenceError):
            self.memory.ingest(owner="owner",source_id="drive:1",
                title="Claim",text="a",locator="drive://1",
                epistemic_status="verified_current")

    def test_wrong_key_refused(self):
        self.add()
        self.key.write_bytes(os.urandom(32))
        with self.assertRaises(EvidenceError):
            EvidenceMemory(self.db,self.key)

    def test_ciphertext_tamper_refused(self):
        self.add()
        with sqlite3.connect(self.db) as db:
            sealed=db.execute("SELECT ciphertext FROM entries").fetchone()[0]
            db.execute("UPDATE entries SET ciphertext=?",(sealed[:-1]+bytes([sealed[-1]^0xff]),))
        with self.assertRaises(EvidenceError):
            self.memory.search(owner="owner_alpha",query="rose")

    def test_request_bounds(self):
        with self.assertRaises(EvidenceError):
            self.memory.search(owner="owner_alpha",query="rose",limit=25)
        with self.assertRaises(EvidenceError):
            self.add(text="x"*(1024*1024+1))

if __name__=="__main__": unittest.main()
