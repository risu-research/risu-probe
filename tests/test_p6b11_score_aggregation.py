"""B11 preregistered independent publisher scorebook safety tests."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("b11_scores",
    ROOT/"benchmarks/p6b11/aggregate_three_organizations.py")
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
MANIFEST=ROOT/"benchmarks/p6b11/prelocked_three_organizations.json"

def score(family:str, *,reproduced=True,normal=True,detected=True):
    return {"schema":"risu-p6b11-source-real-stdio-scored-v1",
        "family":family,"role":"PRELOCKED_NEW_CROSS_ORGANIZATION_SOURCE_FAMILY",
        "origin_is_native_mcp_server":family=="PARTICULARS15",
        "upstream_original_bugfix_reproduced":reproduced,
        "normal_controls_passed":normal,
        "frozen_risu_detected_old_not_fixed":detected,
        "old_risu_findings":[M.FAMILIES[family]] if detected else [],
        "official_fixed_risu_findings":[],
        "old_original_trace_sha256":"a"*64,
        "fixed_original_trace_sha256":"b"*64,
        "transport":"NATIVE_ORIGINAL_MCP_CLI_RAW_STDIO" if family=="PARTICULARS15" else "SDK_STDIO_TEST_WRAPPER"}

def run_cases(cases):
    with tempfile.TemporaryDirectory() as d:
        paths={}
        for key,datum in cases.items():
            path=Path(d)/(key+".json")
            path.write_text(json.dumps(datum))
            paths[key]=path
        return M.audit(MANIFEST,paths)

class TestB11LockedScore(unittest.TestCase):
    def test_all_three_independent_publishers_counted_once(self):
        r=run_cases({f:score(f) for f in M.FAMILIES})
        s=r["summary"]
        self.assertEqual(s["preselected_defect_families"],3)
        self.assertEqual(s["different_repository_owners"],3)
        self.assertEqual(s["source_reproductions_with_normal_controls"],3)
        self.assertEqual(s["relevant_detections"],3)
        self.assertEqual(s["native_source_original_mcp_stdio_verified"],1)
        self.assertEqual(s["actual_source_with_sdk_stdio_wrapper_verified"],2)
    def test_missing_case_kept_in_denominator(self):
        r=run_cases({"PARTICULARS15":score("PARTICULARS15")})
        self.assertEqual(r["summary"]["preselected_defect_families"],3)
        self.assertEqual(r["summary"]["unverified_or_missing"],2)
        self.assertEqual(r["summary"]["relevant_detections"],1)
    def test_failed_normal_not_counted_as_detection(self):
        r=run_cases({"HITCH60":score("HITCH60",normal=False)})
        self.assertEqual(r["summary"]["relevant_detections"],0)
        self.assertEqual(r["summary"]["unverified_or_missing"],3)
    def test_reproduced_but_missed_still_counted(self):
        r=run_cases({"ROBOT682":score("ROBOT682",detected=False)})
        self.assertEqual(r["summary"]["source_reproductions_with_normal_controls"],1)
        self.assertEqual(r["summary"]["confirmed_misses"],1)
    def test_claimed_detection_with_no_old_findings_refused(self):
        x=score("HITCH60");x["old_risu_findings"]=[]
        with self.assertRaises(ValueError):
            run_cases({"HITCH60":x})
    def test_claimed_fixed_bad_finding_refused(self):
        x=score("ROBOT682");x["official_fixed_risu_findings"]=["RMC507"]
        with self.assertRaises(ValueError):
            run_cases({"ROBOT682":x})
    def test_provenance_tier_forgery_refused(self):
        x=score("ROBOT682");x["origin_is_native_mcp_server"]=True
        with self.assertRaises(ValueError):
            run_cases({"ROBOT682":x})
    def test_unknown_family_refused(self):
        with self.assertRaises(ValueError):
            run_cases({"CANDIDATE_EXTRA":score("PARTICULARS15")})
    def test_no_population_claim(self):
        r=run_cases({})
        self.assertIn("NOT_ESTIMABLE",r["summary"]["ecosystem_detection_rate"])
        self.assertIn("NOT_ESTIMABLE",r["summary"]["ecosystem_false_positive_rate"])
    def test_frozen_engine_identity(self):
        s=json.loads(MANIFEST.read_text())
        self.assertEqual(s["frozen_engine"],M.FROZEN)
        self.assertEqual(len({v["repository"].split("/")[0] for v in s["cases"]}),3)

if __name__=="__main__":unittest.main()
