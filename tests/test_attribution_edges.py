import pathlib,sys,unittest
from datetime import datetime,timezone,timedelta
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from stm.core import STM
from stm.retrieval import ContextRetriever
from stm.history import HistoricalEvidence,HISTORICAL_ONLY
class Edge(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,1,1,tzinfo=timezone.utc)
        self.s=STM(clock=lambda:self.now).open_session(owner_id='fictional-owner',agent_id='fictional-agent',session_id='fictional-session')
    def add(self,source,text='I agree',role='user',privacy='private'):
        self.now+=timedelta(seconds=1)
        return self.s.append(text,role=role,source=source,privacy=privacy)
    def test_same_role_different_sources_survive(self):
        a=self.add('fictional:one');b=self.add('fictional:two')
        self.assertEqual({r.id for r in self.s.retrieve('agree',limit=8)},{a.id,b.id})
    def test_distinct_case_preserved(self):
        a=self.add('fictional:one','Code US');b=self.add('fictional:one','Code us')
        self.assertEqual({r.id for r in self.s.retrieve('code',limit=8)},{a.id,b.id})
    def test_limit_is_still_bounded(self):
        self.add('fictional:one');self.add('fictional:two',role='assistant')
        self.assertEqual(len(self.s.retrieve('agree',limit=1)),1)
    def test_low_level_default_preserves_group_provenance(self):
        a=self.add('fictional:one');b=self.add('fictional:two',role='assistant')
        rows=ContextRetriever().rank('agree',[a,b],scope=self.s.key,now=self.now)
        self.assertEqual(len(rows),1)
        self.assertEqual(set(rows[0].provenance_ids),{a.id,b.id})
    def test_legacy_historical_constructor(self):
        e=HistoricalEvidence('fictional:one','I agree',('fictional:one',),'private','historical','as of event',None,None,'fictional://one',self.now,HISTORICAL_ONLY)
        self.assertEqual(e.result_semantics,HISTORICAL_ONLY)
        self.assertIsNone(getattr(e,'speaker_role',None))
if __name__=='__main__':unittest.main(verbosity=2)

