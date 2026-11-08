"""Unit regressions for the seven-family independent holdout ledger.

These are scorer tests, not another evaluation sample or new actual bug evidence.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCORER_PATH=ROOT/'benchmarks/p6b9/aggregate_scores.py'
spec=importlib.util.spec_from_file_location('p6b9_independent_scoreboard',SCORER_PATH)
scorer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(scorer)

def make_score(family: str, *, reproduced: bool=True, detected: bool=True,
               normal: bool=True)->dict:
    schema,truth,truth_ok,rule,control=scorer.SCHEMA[family]
    rec={'schema':schema,'family':family,
         'role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
         truth:truth_ok if reproduced else None,
         rule:detected,
         control:({'absent_control':normal,'scalar_control':normal}
                   if family=='PHP673' else normal),
         'fixed_findings':[],
         'old_findings':(['RMC501'] if detected else []),
         'fixed_unverified':[],
         'fixed_unverified_codes':[],
    }
    return rec

def audit_cases(tmp:Path, cases:dict):
    mapping={}
    for key,record in cases.items():
        path=tmp/(key+'.json')
        path.write_text(json.dumps(record,sort_keys=True),encoding='utf-8')
        mapping[key]=path
    return scorer.audit(ROOT/'benchmarks/p6b9/prelocked_seven_families.json',mapping)

class TestP6B9FrozenLedger(unittest.TestCase):
    def test_all_seven_accounted_and_misses_remain(self):
        with tempfile.TemporaryDirectory() as d:
            reports={key:make_score(key,detected=key not in scorer.BEHAVIOR)
                     for key in scorer.SCHEMA}
            s=audit_cases(Path(d),reports)
            self.assertEqual(s['summary']['families_preselected'],7)
            self.assertEqual(s['summary']['verified_reproduced_families'],7)
            self.assertEqual(s['summary']['issue_relevant_detected_families'],5)
            self.assertEqual(s['summary']['observed_direct_adapter_mismatches'],3)
            self.assertEqual(s['summary']['observed_incomplete_catalog_diagnostics'],2)
            self.assertEqual(s['summary']['reproduced_families_missed'],2)
            self.assertEqual(s['summary']['normal_controls_failed_families'],0)
            self.assertEqual(len(s['case_rows']),7)
            self.assertEqual({x['family'] for x in s['case_rows']},set(scorer.SCHEMA))
    def test_missing_evidence_keeps_selection_denominator(self):
        with tempfile.TemporaryDirectory() as d:
            s=audit_cases(Path(d),{'PHP673':make_score('PHP673')})
            self.assertEqual(s['summary']['families_preselected'],7)
            self.assertEqual(s['summary']['families_scored'],1)
            self.assertEqual(s['summary']['not_verified_or_not_executed'],6)
            self.assertEqual(sum(x['status']=='UNVERIFIED_NOT_EXECUTED'
                                 for x in s['case_rows']),6)
    def test_failed_upstream_control_not_awarded(self):
        with tempfile.TemporaryDirectory() as d:
            s=audit_cases(Path(d),{'PHP673':make_score('PHP673',normal=False)})
            self.assertEqual(s['summary']['verified_reproduced_families'],0)
            self.assertEqual(s['summary']['issue_relevant_detected_families'],0)
            self.assertEqual(s['summary']['normal_controls_failed_families'],1)
    def test_unreproduced_case_does_not_count_as_miss(self):
        with tempfile.TemporaryDirectory() as d:
            s=audit_cases(Path(d),{'GO1139':make_score('GO1139',reproduced=False,
                                                       detected=False)})
            self.assertEqual(s['summary']['verified_reproduced_families'],0)
            self.assertEqual(s['summary']['reproduced_families_missed'],0)
    def test_schema_forgery_refused(self):
        with tempfile.TemporaryDirectory() as d:
            z=make_score('PHP673')
            z['schema']='wrong-source'
            with self.assertRaises(ValueError):
                audit_cases(Path(d),{'PHP673':z})
    def test_wrong_family_refused(self):
        with tempfile.TemporaryDirectory() as d:
            z=make_score('PHP673')
            z['family']='GO1139'
            with self.assertRaises(ValueError):
                audit_cases(Path(d),{'PHP673':z})
    def test_unselected_family_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                audit_cases(Path(d),{'NOT_IN_MANIFEST':make_score('PHP673')})
    def test_manifest_selection_and_engine_unchanged(self):
        s=json.loads((ROOT/'benchmarks/p6b9/prelocked_seven_families.json').read_text())
        self.assertEqual(s['family_count_preselected'],7)
        self.assertEqual(s['engine_frozen_blob_git_sha1'],
                         'b709cc61e37657ff18f90b15113aa500334e6762')
        self.assertEqual(len({c['repo'] for c in s['cases']}),6)
        self.assertEqual(len({c['id'] for c in s['cases']}),7)
    def test_scorer_does_not_suggest_population_precision(self):
        with tempfile.TemporaryDirectory() as d:
            s=audit_cases(Path(d),{})
            self.assertTrue(s['summary']['ecosystem_precision'].startswith('NOT_ESTIMABLE'))
            self.assertTrue(s['summary']['false_positive_rate'].startswith('NOT_ESTIMABLE'))

if __name__=='__main__':
    unittest.main()
