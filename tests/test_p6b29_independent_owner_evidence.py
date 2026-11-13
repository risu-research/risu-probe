"""B29 independent principal evidence semantics and anti-stitching tests.

These test documents are SYNTHETIC. A structurally valid two-account test
does NOT demonstrate a real independent human or external owner. Real B25
and B28 observations are separately checked against live GitHub REST in CI.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import risu_mcp_independent_owner_evidence as m

ENV="resource-independent-review"
R1=441
REPO_ID=700
ACTOR=1001
REVIEWER=1002
SHA="a"*40

def example():
    run={
      "id":R1,"run_attempt":1,"status":"completed","conclusion":"success",
      "run_started_at":"2026-11-13T03:00:00Z",
      "head_sha":SHA,"actor":{"id":ACTOR,"login":"actor"},
      "triggering_actor":{"id":ACTOR,"login":"actor"},
      "repository":{"id":REPO_ID,"full_name":"owner/resource"},
    }
    env={
      "id":990,"name":ENV,"can_admins_bypass":False,
      "updated_at":"2026-11-13T02:50:00Z",
      "deployment_branch_policy":{"protected_branches":False,
                                  "custom_branch_policies":True},
      "protection_rules":[
        {"type":"branch_policy"},
        {"type":"required_reviewers","prevent_self_review":True,
         "reviewers":[{"type":"User","reviewer":{"id":REVIEWER,
                                                "login":"reviewer"}}]}
      ],
    }
    approvals=[{"state":"approved","user":{"id":REVIEWER,"login":"reviewer"},
                "environments":[{"id":990,"name":ENV}]}]
    return {"review_run":run,"review_environment":env,
            "review_events":approvals,"effect_run":copy.deepcopy(run),
            "expected_environment":ENV,"source":"SYNTHETIC_ONLY"}

class TestNativeGithubIndependentApproval(unittest.TestCase):
    def report(self,change=None):
        data=example()
        if change:change(data)
        return m.assess(data)

    def codes(self,change=None):
        return self.report(change)["refusals"]

    def test_synthetic_two_account_configuration_is_structurally_valid_but_not_real_owner(self):
        out=self.report()
        self.assertEqual(out["status"],"PLATFORM_DISTINCT_ACCOUNT_REVIEW_BOUND_TO_SAME_RUN")
        self.assertEqual(out["refusals"],[])
        self.assertFalse(out["supported_claims"]["independently_controlled_human_owner"])
        self.assertFalse(out["supported_claims"]["owner_signed_exact_resource_intent"])
        self.assertFalse(out["supported_claims"]["real_remote_resource_effect_independently_verified"])
        self.assertEqual(out["mode"],"OFFLINE_TEST_OR_RECORDED_DATA")

    def test_self_reviewer_disqualifies_independence(self):
        def tamper(d):
            d["review_run"]["actor"]["id"]=REVIEWER
            d["review_run"]["triggering_actor"]["id"]=REVIEWER
        self.assertIn("SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL",
                      self.codes(tamper))

    def test_retriggering_user_cannot_self_review_replay(self):
        self.assertIn("SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL",
            self.codes(lambda d:d["review_run"]["triggering_actor"].update(id=REVIEWER)))

    def test_disabled_self_review_protection_deny(self):
        self.assertIn("GITHUB_NATIVE_PREVENT_SELF_REVIEW_DISABLED",
            self.codes(lambda d:d["review_environment"]["protection_rules"][1].update(
                prevent_self_review=False)))

    def test_admin_bypass_protection_required(self):
        self.assertIn("GITHUB_NATIVE_ADMIN_BYPASS_NOT_DISABLED",
            self.codes(lambda d:d["review_environment"].update(can_admins_bypass=True)))

    def test_environment_branch_protection_required(self):
        def change(d):
            d["review_environment"]["deployment_branch_policy"]={
                 "protected_branches":False,"custom_branch_policies":False}
        self.assertIn("GITHUB_DEPLOYMENT_BRANCH_SCOPE_NOT_PROTECTED",self.codes(change))

    def test_approval_from_unlisted_person_deny(self):
        self.assertIn("APPROVER_NOT_EXACT_GITHUB_REQUIRED_USER",
            self.codes(lambda d:d["review_events"][0]["user"].update(id=3009)))

    def test_team_only_review_requires_independent_user_proof(self):
        def change(d):
            d["review_environment"]["protection_rules"][1]["reviewers"]=[
                {"type":"Team","reviewer":{"id":400}}]
        self.assertIn("APPROVER_NOT_EXACT_GITHUB_REQUIRED_USER",self.codes(change))

    def test_no_review_deny(self):
        self.assertIn("APPROVAL_RECORD_FOR_EXACT_RUN_AND_ENVIRONMENT_MISSING",
            self.codes(lambda d:d.update(review_events=[])))

    def test_review_for_other_environment_deny(self):
        self.assertIn("APPROVAL_RECORD_FOR_EXACT_RUN_AND_ENVIRONMENT_MISSING",
            self.codes(lambda d:d["review_events"][0]["environments"][0].update(
                id=10001,name="other")))

    def test_fake_two_account_but_wrong_run_denied(self):
        self.assertIn("CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING",
            self.codes(lambda d:d["effect_run"].update(id=442)))

    def test_cross_repository_stitch_denied(self):
        self.assertIn("CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING",
            self.codes(lambda d:d["effect_run"]["repository"].update(id=701)))

    def test_other_head_sha_deny(self):
        self.assertIn("CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING",
            self.codes(lambda d:d["effect_run"].update(head_sha="b"*40)))

    def test_other_run_attempt_deny(self):
        self.assertIn("CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING",
            self.codes(lambda d:d["effect_run"].update(run_attempt=2)))

    def test_approval_does_not_certify_failed_execution(self):
        self.assertIn("GITHUB_RUN_IDENTITY_OR_EXECUTION_UNVERIFIED",
            self.codes(lambda d:d["review_run"].update(conclusion="failure")))

    def test_effect_job_failed_deny(self):
        self.assertIn("CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING",
            self.codes(lambda d:d["effect_run"].update(conclusion="failure")))

    def test_invalid_numeric_account_identity_deny(self):
        self.assertIn("GITHUB_RUN_IDENTITY_OR_EXECUTION_UNVERIFIED",
            self.codes(lambda d:d["review_run"]["actor"].update(id="1001")))

    def test_protection_config_changed_after_original_run_deny(self):
        self.assertIn("POST_HOC_ENVIRONMENT_PROTECTION_CHANGE_OR_UNVERIFIABLE_TIME",
            self.codes(lambda x:x["review_environment"].update(
                updated_at="2026-11-13T03:05:00Z")))

    def test_missing_historical_protection_time_deny(self):
        self.assertIn("POST_HOC_ENVIRONMENT_PROTECTION_CHANGE_OR_UNVERIFIABLE_TIME",
            self.codes(lambda x:x["review_environment"].pop("updated_at")))

    def test_missing_original_run_start_time_deny(self):
        self.assertIn("POST_HOC_ENVIRONMENT_PROTECTION_CHANGE_OR_UNVERIFIABLE_TIME",
            self.codes(lambda x:x["review_run"].pop("run_started_at")))

    def test_retriggered_approval_attempt_without_per_attempt_proof_deny(self):
        def changed(x):
            x["review_run"]["run_attempt"]=2
            x["effect_run"]["run_attempt"]=2
        self.assertIn("REVIEW_EVENT_NOT_BOUND_TO_SPECIFIC_RETRY_ATTEMPT",
            self.codes(changed))

    def test_malformed_reviewer_rule_fails_closed_without_crashing(self):
        self.assertIn("NATIVE_REQUIRED_REVIEWER_PROTECTION_MISSING",
            self.codes(lambda x:x["review_environment"].update(
                protection_rules=[None,42,"bad"])))

    def test_unprotected_reviewer_metadata_deny(self):
        def change(d):
            d["review_environment"]["protection_rules"]=[]
        self.assertIn("NATIVE_REQUIRED_REVIEWER_PROTECTION_MISSING",self.codes(change))

    def test_ambiguous_reviewer_protection_deny(self):
        def change(d):
            d["review_environment"]["protection_rules"].append(
                copy.deepcopy(d["review_environment"]["protection_rules"][1]))
        self.assertIn("NATIVE_REQUIRED_REVIEWER_PROTECTION_MISSING",self.codes(change))

    def test_rejected_review_record_deny(self):
        def change(d):
            d["review_events"].append({
               "state":"rejected","user":{"id":REVIEWER},
               "environments":[{"id":990,"name":ENV}]})
        self.assertIn("REJECTED_DEPLOYMENT_NOT_APPROVED",self.codes(change))

    def test_no_credentials_enter_persistent_certificate(self):
        d=example()
        d["review_run"]["private_disallowed_secret"]="DO_NOT_PERSIST"
        report=self.report(lambda x:x["review_run"].update(private_disallowed_secret="DO_NOT_PERSIST"))
        self.assertNotIn("DO_NOT_PERSIST",json.dumps(report))
        self.assertNotIn("access_token",json.dumps(report))

    def test_api_path_is_constrained_before_network(self):
        with self.assertRaises(ValueError):
            m._get("/unsafe/path",None)
        with self.assertRaises(ValueError):
            m._get("/repos/owner/name/../secrets",None)

    def test_acquire_refuses_invalid_repo_without_any_network(self):
        with patch.object(m,"_get",side_effect=AssertionError("must not fetch")):
            with self.assertRaises(ValueError):
                m.acquire_original("../creds",R1,ENV)
            with self.assertRaises(ValueError):
                m.acquire_original("owner/resource",-1,ENV)
            with self.assertRaises(ValueError):
                m.acquire_original("owner/resource",R1,"env/no")

    def test_live_cli_refusal_persists_safe_diagnostic_only(self):
        def fake_acquire(*args,**kwargs):
            return example()
        def self_approval(data):
            data["review_run"]["actor"]["id"]=REVIEWER
            return data
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)/"b29.json"
            with patch.object(m,"acquire_original",side_effect=lambda *a,**k:
                              self_approval(fake_acquire())):
                status=m.main(["--repo","owner/resource","--run-id",str(R1),
                    "--environment",ENV,"--out",str(out)])
            self.assertEqual(status,2)
            v=json.loads(out.read_text())
            self.assertEqual(v["status"],"REFUSED_UNSUPPORTED_INDEPENDENT_APPROVAL")
            self.assertIn("SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL",
                          v["refusals"])
            self.assertEqual(m.main(["--repo","owner/resource","--run-id",str(R1),
                "--environment",ENV,"--out",str(out)]),2)

if __name__=="__main__":
    unittest.main()
