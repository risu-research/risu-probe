"""B30 four-original-case claim closure versus false cross-experiment joins.

Always use exact original native GitHub Actions evidence artifacts and prior
independent audits when RISU_B30_MATRIX_EVIDENCE_DIR is configured. Mutations
are generated AFTER all originals are loaded and held unchanged as controls.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import risu_mcp_claim_sufficiency as m

FILENAMES={
 "b30":"b30-original/original_b25_effect_closure.json",
 "b29":"b29-original/b25-original-github-self-review.json",
 "b27":"b27-original/independent_capability_matrix.json",
 "b28":"b28-original/.b28-record-certificate.json",
}

class TestB30FourRealOriginalCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=os.environ.get("RISU_B30_MATRIX_EVIDENCE_DIR")
        if not root:
            raise unittest.SkipTest("Exact pinned real GitHub Actions original artifacts required")
        base=Path(root)
        cls.orig={}
        for name,path in FILENAMES.items():
            p=base/path
            if not p.is_file():
                raise AssertionError("Missing pinned original GitHub evidence artifact "+str(p))
            cls.orig[name]=m.strict_load(p)
        cls.report=m.analyze(*(cls.orig[x] for x in ("b30","b29","b27","b28")))

    def test_four_unrelated_positive_sources_are_distinct(self):
        r=self.report
        self.assertEqual(r["subject_count"],4)
        self.assertEqual(len({x["subject_key"] for x in r["subjects"]}),4)
        self.assertFalse(r["owner_approved_full_execution_proven"])
        self.assertEqual(r["full_closure_subject_keys"],[])
        self.assertEqual(r["status"],"FOUR_INDEPENDENT_ORIGINAL_CLAIM_SUBJECTS_NEVER_FALSE_JOINED")

    def test_naive_oracle_mixes_unrelated_original_successes(self):
        r=self.report["naive_subject_agnostic_baseline"]
        self.assertTrue(r["would_report_full_authorized_execution"])
        self.assertEqual(r["evidence_conflation_count"],4)
        self.assertFalse(self.report["owner_approved_full_execution_proven"])

    def test_exact_source_scope_is_never_inherited(self):
        by={x["label"]:x for x in self.report["subjects"]}
        b25=by["B25_REAL_GITHUB_OWNER_REVIEWED_ONE_FILE"]
        b28=by["B28_EXTERNAL_OPENBAO_POSTGRESQL_LEASE"]
        s3=by["B27_EXTERNAL_SEAWEEDFS_S3"]
        pg=by["B27_EXTERNAL_POSTGRESQL_RLS"]
        self.assertNotEqual(b25["subject"]["kind"],b28["subject"]["kind"])
        self.assertTrue(b25["obligations"]["exact_approved_result_bytes"])
        self.assertFalse(b25["obligations"]["native_revocation"])
        self.assertTrue(b28["obligations"]["native_revocation"])
        self.assertTrue(b28["obligations"]["replay_refused"])
        self.assertFalse(s3["obligations"]["exact_approved_result_bytes"])
        self.assertFalse(s3["obligations"]["replay_refused"])
        self.assertTrue(pg["obligations"]["replay_refused"])
        self.assertTrue(all("real_independent_owner_approval" in x["missing"]
                            for x in self.report["subjects"]))

    def test_verified_refuted_and_unverified_are_three_distinct_evidence_states(self):
        by={x["label"]:x for x in self.report["subjects"]}
        s3=by["B27_EXTERNAL_SEAWEEDFS_S3"]
        b28=by["B28_EXTERNAL_OPENBAO_POSTGRESQL_LEASE"]
        b25=by["B25_REAL_GITHUB_OWNER_REVIEWED_ONE_FILE"]
        self.assertEqual(s3["evidence_states"]["exact_approved_result_bytes"],
                         "REFUTED")
        self.assertEqual(s3["evidence_states"]["replay_refused"],"REFUTED")
        self.assertEqual(s3["evidence_states"]["real_independent_owner_approval"],
                         "UNVERIFIED")
        self.assertEqual(b25["evidence_states"]["independent_resource_effect_audit"],
                         "UNVERIFIED")
        self.assertEqual(b28["evidence_states"]["native_revocation"],
                         "VERIFIED")
        self.assertEqual(b28["refuted"],[])
        self.assertEqual(b28["unverified"],["real_independent_owner_approval"])
        self.assertEqual(len(self.report["subjects"]),4)
        self.assertTrue(self.report["explicit_original_counterexample"]
                        ["not_an_upstream_security_bug_claim"])

    def test_missing_obligations_are_minimal_case_specific(self):
        best=self.report["closest_individual_evidence"]
        self.assertEqual(best["label"],"B28_EXTERNAL_OPENBAO_POSTGRESQL_LEASE")
        self.assertEqual(best["missing"],["real_independent_owner_approval"])

    def must_reject(self,kind,change):
        docs=copy.deepcopy(self.orig)
        change(docs)
        with self.subTest(mutation=kind),self.assertRaises(m.Rejected):
            m.analyze(*(docs[x] for x in ("b30","b29","b27","b28")))

    def test_mismatched_b25_review_source_cannot_be_attached_to_closure(self):
        self.must_reject("wrong B29 repo ID",
          lambda d:d["b29"]["original_github_review_source"].update(repo_id=1234))
        self.must_reject("wrong B29 run",
          lambda d:d["b29"]["claimed_effect_source"].update(run_id=43377450878))
        self.must_reject("wrong original head sha",
          lambda d:d["b29"]["original_github_review_source"].update(head_sha="f"*40))
        self.must_reject("same repo other attempt",
          lambda d:d["b29"]["claimed_effect_source"].update(attempt=2))

    def test_original_b25_claim_must_not_fake_owner(self):
        self.must_reject("false independent owner",
          lambda d:d["b30"]["supported_claims"].update(independent_human_resource_owner=True))
        self.must_reject("native path scoped GITHUB_TOKEN",
          lambda d:d["b30"]["supported_claims"].update(native_github_token_file_path_scope=True))
        self.must_reject("fake record original GitHub REST",
          lambda d:d["b30"].update(verifier_mode="STRUCTURAL_ONLY"))
        self.must_reject("fake B29 distinct reviewer",
          lambda d:d["b29"].update(status="PLATFORM_DISTINCT_ACCOUNT_REVIEW_BOUND_TO_SAME_RUN"))

    def test_original_b27_heldout_backend_direction_and_exact_bytes(self):
        def changed(name,property_,value):
            def apply(d):
                for x in d["b27"]["backends"]:
                    if x["backend"]==name:x[property_]["enforced"]=value
            return apply
        self.must_reject("S3 wrong content claimed native",
            changed("SeaweedFS","exact_desired_bytes",True))
        self.must_reject("S3 one-time claimed native",
            changed("SeaweedFS","one_time_effect",True))
        self.must_reject("S3 native scope stripped",
            changed("SeaweedFS","path_object_scope",False))
        self.must_reject("PostgreSQL unsupported content",
            changed("PostgreSQL","exact_desired_bytes",False))
        self.must_reject("PostgreSQL audit false",
            lambda d:d["b27"]["backends"][0].update(
                actual_effect_independently_audited=False))

    def test_original_b28_native_issuer_and_resource_claim_mutation(self):
        def mutate_claim(d,name,value):
            for x in d["b28"]["claims"]:
                if x["claim"]==name:x["supported_by_recorded_evidence"]=value
        self.must_reject("B28 native lease revoked incorrectly",
            lambda d:mutate_claim(d,"native_credential_revocation_enforced_at_new_login",False))
        self.must_reject("B28 fake independent human",
            lambda d:mutate_claim(d,"independent_real_human_resource_owner",True))
        self.must_reject("B28 fake recipient crypto binding",
            lambda d:mutate_claim(d,"wrapping_token_cryptographically_binds_recipient",True))
        self.must_reject("B28 altered preimage digest",
            lambda d:d["b28"].update(owner_before_sha256="a"*64))
        self.must_reject("B28 no original audit",
            lambda d:mutate_claim(d,"independent_readonly_original_data_audit",False))

    def test_cli_uses_actual_original_artifacts(self):
        base=os.environ["RISU_B30_MATRIX_EVIDENCE_DIR"]
        with tempfile.TemporaryDirectory() as t:
            outfile=Path(t)/"result.json"
            args=[]
            for arg,relative in FILENAMES.items():
                args.extend(["--"+arg,str(Path(base)/relative)])
            args.extend(["--out",str(outfile)])
            self.assertEqual(m.main(args),0)
            result=json.loads(outfile.read_text())
            self.assertEqual(result["schema"],m.SCHEMA)
            self.assertFalse(result["owner_approved_full_execution_proven"])
            self.assertEqual(m.main(args),2)

class TestB30StrictSafeReader(unittest.TestCase):
    def test_duplicate_json_field_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"case.json"
            p.write_text('{"approval":true,"approval":false}')
            with self.assertRaises(m.Rejected):
                m.strict_load(p)
    def test_missing_artifact_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(m.Rejected):
                m.strict_load(Path(tmp)/"absent.json")
    def test_symlinked_original_artifact_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            actual=root/"original.json"
            actual.write_text('{"x":1}')
            link=root/"copy.json"
            link.symlink_to(actual)
            with self.assertRaises(m.Rejected):
                m.strict_load(link)

if __name__=="__main__":
    unittest.main()
