"""Offline P6-B3 evidence-verification contract; no SDK, network, or user source execution."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from risu_mcp_replay import ReplayEvidenceError,evaluate_pair,as_sarif,KNOWN_CAPTURE

HERE=Path(__file__).resolve().parent/'fixtures'
OLD=HERE/'sdk_old.json'
FIXED=HERE/'sdk_fixed.json'

class SavedMCPContract(unittest.TestCase):
    def test_pinned_ci_has_exact_two_verified_findings(self):
        d=evaluate_pair(OLD,FIXED)
        self.assertEqual(d['verified_case_count'],2)
        self.assertEqual(d['origin_integrity'],'PINNED_PUBLIC_CI_SHA256_PAIR')
        self.assertEqual({x['rule_id'] for x in d['cases']},{'RMC401','RMC402'})
        self.assertTrue(all(x['verdict']=='CONFIRMED_IN_PINNED_PUBLIC_CI_REPLAY' for x in d['cases']))
        self.assertEqual(d['coverage']['external_mcp_server'],'NOT_TESTED')
        self.assertEqual(d['coverage']['stdio_mcp_wire'],'NOT_CAPTURED')
        self.assertEqual(d['capture_sha256']['old'],KNOWN_CAPTURE['old'])

    def test_single_changed_note_is_no_longer_verified_origin(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            d=json.loads(OLD.read_text())
            d['claim_boundary']='same reported data but rewritten by user'
            old.write_text(json.dumps(d,sort_keys=True),encoding='utf-8')
            got=evaluate_pair(old,FIXED)
            self.assertEqual(got['verified_case_count'],0)
            self.assertEqual(got['origin_integrity'],'UNATTESTED_SELF_REPORTED_JSON')
            self.assertTrue(all(x['verdict']=='CONSISTENT_BUT_UNATTESTED' for x in got['cases']))

    def test_fail_closed_missing_root_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            d=json.loads(OLD.read_text());d['scenario_recursive']['live_mcp']['protocol_transport']='FAKE_STDIO'
            old.write_text(json.dumps(d))
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_fail_closed_accepted_but_error_reported(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            d=json.loads(OLD.read_text());d['scenario_bool']['native_validation']['2025-11-25']['accepted']=True
            old.write_text(json.dumps(d))
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_fail_closed_changed_protocol_version(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            d=json.loads(OLD.read_text());d['official_package_versions']['mcp']='0.0.1'
            old.write_text(json.dumps(d))
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_duplicates_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            old.write_text('{"schema":"ok","schema":"fake"}')
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json'
            try:old.symlink_to(OLD)
            except (NotImplementedError,OSError):self.skipTest('Symlinks unavailable')
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_oversized_capture_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            old=Path(t)/'old.json';old.write_text('{"x":"'+'A'*40000+'"}')
            with self.assertRaises(ReplayEvidenceError):evaluate_pair(old,FIXED)

    def test_sarif_contains_exact_verified_rules(self):
        d=as_sarif(evaluate_pair(OLD,FIXED))
        self.assertEqual(d['version'],'2.1.0')
        self.assertEqual({x['ruleId'] for x in d['runs'][0]['results']},{'RMC401','RMC402'})

    def test_cli_standalone_and_source_check_separate(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'sample.py').write_text('answer = 42\n')
            env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            def run(*args):
                return subprocess.run([sys.executable,'-m','risu_p5d_cli',*map(str,args)],capture_output=True,text=True,env=env,timeout=30)
            d=run('verify-mcp','--old',OLD,'--fixed',FIXED,'--format','json','--fail-on-confirmed')
            self.assertEqual(d.returncode,1,d.stderr)
            self.assertEqual(json.loads(d.stdout)['verified_case_count'],2)
            no=run('check',root,'--format','json');self.assertEqual(no.returncode,0,no.stderr)
            base=json.loads(no.stdout)
            self.assertEqual(base['mcp_semantic_verification']['semantic_verification'],'NOT_RUN')
            self.assertEqual(base['source_analysis']['python_parsed'],1)
            proof=run('check',root,'--mcp-sdk-old',OLD,'--mcp-sdk-fixed',FIXED,'--format','json','--fail-on-confirmed')
            self.assertEqual(proof.returncode,1,proof.stderr)
            report=json.loads(proof.stdout)
            self.assertEqual(report['source_analysis']['python_parsed'],1)
            self.assertEqual(report['mcp_semantic_verification']['verified_case_count'],2)
            self.assertEqual(report['summary']['confirmed_saved_replay'],0) # P5B unaffected

    def test_tampered_capture_cannot_gate_ci(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);old=root/'old.json';d=json.loads(OLD.read_text())
            d['claim_boundary']='Unattested rewrite';old.write_text(json.dumps(d))
            env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            p=subprocess.run([sys.executable,'-m','risu_p5d_cli','verify-mcp','--old',str(old),
                             '--fixed',str(FIXED),'--format','json','--fail-on-confirmed'],
                             capture_output=True,text=True,env=env,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout)['verified_case_count'],0)

if __name__=='__main__':unittest.main()
