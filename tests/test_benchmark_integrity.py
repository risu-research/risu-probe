
"""Benchmark scoring integrity checks, without fetching or executing any third-party source."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmarks'/'p6b'))
from run import blobhash,summarize

ROOT=Path(__file__).resolve().parents[1]
class Metrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=json.loads((ROOT/'benchmarks/p6b/cases.json').read_text())['cases']
    def test_inventory_is_public_and_immutable(self):
        self.assertEqual(len(self.cases),7)
        self.assertEqual(len({x['id'] for x in self.cases}),7)
        self.assertTrue(all(len(x['commit'])==40 and len(x['git_blob'])==40 for x in self.cases))
    def test_git_blob_fingerprint(self):
        self.assertEqual(blobhash(b'hello\n'),'ce013625030ba8dba906f756967f9e9ca394464a')
    def test_tuned_detection_does_not_affect_other_denominators(self):
        rows=[{**r,'candidate':{'target_detected':r['id']=='F5030-before','findings':[]}} for r in self.cases]
        x=summarize(rows,'candidate')
        self.assertEqual((x['positive_cases'],x['detected'],x['missed']),(3,1,2))
        self.assertEqual((x['repaired_cases'],x['false_alarms_on_repairs']),(2,0))
        self.assertEqual((x['out_of_scope_excluded'],x['unlabeled_excluded']),(1,1))
    def test_no_private_dependency_or_secret_in_manifest(self):
        text=json.dumps(self.cases).lower()
        for word in ('ghp_', 'private-repo', 'secret=', 'token=', 'password='):
            self.assertNotIn(word,text)
if __name__=='__main__':unittest.main()
