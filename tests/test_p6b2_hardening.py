"""P6-B2 benchmark contract tests. No network, no installation, no target execution."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"benchmarks"/"p6b2"))
from evaluate import freeze_check, calculate, FROZEN_MANIFEST_SHA256

M=json.loads((ROOT/"benchmarks"/"p6b2"/"frozen_cases.json").read_text())

class TestIndependentHoldout(unittest.TestCase):
    def test_frozen_source_file_hash(self):
        raw=(ROOT/"benchmarks"/"p6b2"/"frozen_cases.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),FROZEN_MANIFEST_SHA256)

    def test_freeze_inventory(self):
        freeze_check(M)
        self.assertEqual(len(M["cases"]),7)

    def test_no_development_cases(self):
        body=json.dumps(M)
        for marker in ("5030","3717","40471"):
            self.assertNotIn("issues/"+marker,body)

    def test_wrong_commit_rejected(self):
        changed=copy.deepcopy(M)
        changed["cases"][0]["commit"]="not-a-commit"
        with self.assertRaises(AssertionError):freeze_check(changed)

    def test_label_inventory_rejected(self):
        changed=copy.deepcopy(M)
        changed["cases"][0]["label"]="official_fixed"
        # Changed label counts fail when constructing the score even when metadata is valid.
        rows=[{"label":c["label"],"scan":{"parsed":1,"finding_count":0,"status":"NO_STATIC_FINDINGS"},
               "issue_matched_detection":False,"issue_specific_capability":False}
              for c in changed["cases"]]
        with self.assertRaises(AssertionError):calculate(rows)

    def test_escape_path_rejected(self):
        changed=copy.deepcopy(M)
        changed["cases"][0]["path"]="../secrets.txt"
        with self.assertRaises(AssertionError):freeze_check(changed)

    def test_zero_detection_qualifier(self):
        rows=[]
        for c in M["cases"]:
            unsupported=c["label"]=="unsupported"
            rows.append({"label":c["label"],"scan":{"parsed":0 if unsupported else 1,
                 "status":"UNSUPPORTED_LANGUAGE" if unsupported else "NO_STATIC_FINDINGS",
                 "finding_count":0},"issue_matched_detection":False,"issue_specific_capability":False})
        score=calculate(rows)
        self.assertEqual(score["independent_known_defects"],2)
        self.assertEqual(score["issue_matched_false_negative"],2)
        self.assertEqual(score["semantic_assurance_absent"],2)
        self.assertIsNone(score["precision"])
        self.assertEqual(score["unsupported_excluded"],1)

    def test_false_alarm_accounting(self):
        rows=[]
        for c in M["cases"]:
            unsupported=c["label"]=="unsupported"
            alarm=c["id"]=="M3353-fixed"
            rows.append({"label":c["label"],"scan":{"parsed":0 if unsupported else 1,
                 "status":"UNSUPPORTED_LANGUAGE" if unsupported else "STATIC_WARNINGS" if alarm else "NO_STATIC_FINDINGS",
                 "finding_count":int(alarm)},"issue_matched_detection":alarm,"issue_specific_capability":False})
        score=calculate(rows)
        self.assertEqual(score["issue_matched_false_alarm"],1)
        self.assertEqual(score["unreviewed_ancillary_warning_count"],1)

if __name__=="__main__":
    unittest.main()
