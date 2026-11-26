"""Synthetic regression at the existing STM public consumer seam."""
import pathlib,sys,unittest
from datetime import datetime,timezone,timedelta
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from stm.core import STM
class Attribution(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,1,1,tzinfo=timezone.utc)
        self.s=STM(clock=lambda:self.now).open_session(owner_id='fictional-owner',agent_id='fictional-agent',session_id='fictional-session')
    def add(self,role,source='conversation:fictional',text='I agree',privacy='private'):
        self.now+=timedelta(seconds=1)
        return self.s.append(text,role=role,source=source,privacy=privacy)
    def test_public_retrieval_retains_both_roles(self):
        a=self.add('user');b=self.add('assistant')
        rows=self.s.retrieve('agree',limit=8)
        self.assertEqual({(r.id,r.role,r.source) for r in rows},{(a.id,a.role,a.source),(b.id,b.role,b.source)})
    def test_packed_context_retains_both_roles(self):
        a=self.add('user');b=self.add('assistant')
        p=self.s.assemble_context('agree',token_budget=1000)
        self.assertEqual({(r.id,r.role,r.source) for r in p.selected},{(a.id,a.role,a.source),(b.id,b.role,b.source)})
        self.assertIn('role=user',p.text);self.assertIn('role=assistant',p.text)
    def test_legitimate_duplicates_still_deduplicate(self):
        self.add('user');b=self.add('user')
        self.assertEqual([r.id for r in self.s.retrieve('agree',limit=8)],[b.id])
    def test_exact_authorized_lookup_preserves_roles(self):
        a=self.add('user');b=self.add('assistant')
        for r in (a,b):
            self.assertEqual(self.s.get(r.id),r)
    def test_privacy_filter_before_packing(self):
        a=self.add('user',privacy='private');self.add('assistant',privacy='shared')
        p=self.s.assemble_context('agree',token_budget=1000,authorized_privacy_scopes=frozenset({'private'}))
        self.assertEqual([r.id for r in p.selected],[a.id])
if __name__=='__main__':unittest.main(verbosity=2)

