import pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from stm.archive import ConversationArchive,ArchiveScope
from stm.archive_adapter import ArchiveHistoryReader
from stm.history import HISTORICAL_ONLY
from stm.models import SessionKey
class ArchiveAttribution(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scope=ArchiveScope('fictional-tenant','fictional-owner','fictional-agent')
        self.session=SessionKey('fictional-tenant','fictional-owner','fictional-agent','new-chat')
        self.archive=ConversationArchive(str(pathlib.Path(self.tmp.name)/'synthetic.sqlite3'),authorize=lambda principal,action,scope:principal=='fixture-authorized' and scope==self.scope)
        self.addCleanup(self.archive.close)
        self.turns=[self.archive.append_turn('fixture-authorized',self.scope,conversation_id='fictional-chat',role=r,content='I agree',source='conversation:fictional',privacy='private') for r in ('user','assistant')]
    def read(self,principal='fixture-authorized',scope=None):
        return ArchiveHistoryReader(self.archive,principal).search('agree',scope=scope or self.session,authorized_privacy_scopes=frozenset({'private'}))
    def test_distinct_roles_survive_projection(self):
        evidence=self.read()
        self.assertEqual({(e.memory_id,getattr(e,'speaker_role',None),e.source_ids) for e in evidence},{(t.turn_id,t.role,(t.turn_id,t.source)) for t in self.turns})
    def test_custody_and_provenance_preserved(self):
        evidence=self.read()
        self.assertEqual({e.memory_id for e in evidence},{t.turn_id for t in self.turns})
        self.assertTrue(all(e.result_semantics==HISTORICAL_ONLY and e.ledger_path.endswith(e.memory_id) for e in evidence))
    def test_unauthorized_reader_denied(self):
        with self.assertRaises(PermissionError):self.read('unverified')
        with self.assertRaises(PermissionError):self.read(scope=SessionKey('fictional-tenant','other-owner','fictional-agent','new-chat'))
if __name__=='__main__':unittest.main(verbosity=2)

