"""B30 original GitHub source-to-effect closure and adversarial tests.

Fetch the B25 original approved run, exact proposal and actual remote Git
once per process. Every mutation is performed after fetching; no substitute
fixtures may count as original evidence. These mutation tests are not claimed
to be previously unknown GitHub vulnerabilities.
"""
from __future__ import annotations
import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import risu_mcp_effect_closure as m

REPO="risu-research/risu-verify"
ENV="risu-b25-human-owner-approval"
RUN=43355918665
SOURCE="e9409d8ef4a6a71a3a93705909fe5c777d014bbc"
EFFECT="26ac7506d27a76290a7a1eb945ef0f9ea6059e09"
PROPOSAL="benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json"
RESOURCE="benchmarks/p6b25/owner_only_resource.txt"

class TestB30LocalLogic(unittest.TestCase):
    def test_blob_git_sha_matches_original_pinned_owner_resource(self):
        before=b"RISU B25 human-reviewed one-file fixture\nstate=AWAITING_GITHUB_ENVIRONMENT_REVIEW\nscope=EXACT_ONE_FILE\n"
        self.assertEqual(m.blob_id(before),"c84690efad2ac44fa96605a4d1b7c34efbff52de")
        self.assertEqual(m.digest(before),"fe8092741095803fd70cf7c62e516fa752ba296ed8688fc15bb320db5cc64b18")

    def test_json_duplicate_key_refused(self):
        with self.assertRaises(ValueError):
            m.strict_json_bytes('{"x":1,"x":2}')

    def test_invalid_proposal_path_refused(self):
        for p in ("", "../secret","/absolute","folder//file","a\\b","a/./b","a/../b","a b"):
            with self.subTest(path=p):
                self.assertFalse(m.valid_path(p))

    def test_noncanonical_base64_rejected(self):
        payload=b"data\n"
        obj={"encoding":"base64","type":"file","size":len(payload),
             "sha":m.blob_id(payload),"content":"ZGF0YQo="}
        self.assertEqual(m.decode_contents(obj),payload)
        obj["content"]="ZGF0YQp="
        with self.assertRaises(ValueError):
            m.decode_contents(obj)

    def test_invalid_original_data_structure_rejected(self):
        with self.assertRaises(ValueError):
            m.assess_closure({})

    def test_no_mutating_github_http_requests(self):
        import inspect
        source=inspect.getsource(m._read)
        self.assertNotIn("method=\"PUT\"",source)
        self.assertNotIn("method=\"POST\"",source)

class TestB30RealGitHubOriginal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("RISU_B30_REAL_GITHUB")!="1":
            raise unittest.SkipTest("Original GitHub REST required for this group")
        cls.original=m.fetch_live(
             REPO,RUN,ENV,PROPOSAL,EFFECT,
             token=os.environ.get("GITHUB_TOKEN",""))
        cls.base=m.assess_closure(cls.original)
        if not cls.base["observed_structural_closure"]:
            raise AssertionError("Expected frozen original B25 source/effect closure, got "+
                                 str(cls.base["refusals"]))

    def test_real_original_positive_lower_tier(self):
        s=self.base
        self.assertTrue(s["observed_structural_closure"])
        self.assertEqual(s["source"]["effect_commit"],EFFECT)
        self.assertEqual(s["source"]["run_head_commit"],SOURCE)
        self.assertEqual(s["source"]["run_id"],RUN)
        self.assertEqual(s["source"]["preimage_git_blob"],
                         "c84690efad2ac44fa96605a4d1b7c34efbff52de")
        self.assertEqual(s["source"]["postimage_git_blob"],
                         "806f70a8733e3bb3ac68119166d65d9ae433ae9d")
        # A structural check never has authority to self-declare LIVE proof.
        self.assertEqual(s["status"],"RECORDED_STRUCTURE_MATCH_NOT_LIVE_PROOF")
        self.assertFalse(s["supported_claims"]["independent_human_resource_owner"])
        self.assertFalse(s["supported_claims"]["same_run_source_to_exact_one_file_effect"])

    def test_cross_repo_original_effect_mismatch(self):
        d=copy.deepcopy(self.original)
        d["run"]["repository"]["id"]=1448998079
        self.assertIn("PROPOSAL_OR_RESOURCE_SCOPE_NOT_BOUND_TO_ORIGINAL_REPOSITORY",
                      m.assess_closure(d)["refusals"])

    def refusal(self,label,change,reason):
        d=copy.deepcopy(self.original)
        change(d)
        with self.subTest(label=label):
            try: got=m.assess_closure(d)
            except ValueError:
                return
            self.assertFalse(got["observed_structural_closure"],label)
            self.assertIn(reason,got["refusals"],label)

    def test_real_original_approval_binding_mutations(self):
        self.refusal("missing approval",
           lambda d:d.update(approvals=[]),"NO_ORIGINAL_RUN_SPECIFIC_HUMAN_REVIEW")
        self.refusal("other environment",
           lambda d:d["approvals"][0]["environments"][0].update(id=123),
           "NO_ORIGINAL_RUN_SPECIFIC_HUMAN_REVIEW")
        self.refusal("other approver",
           lambda d:d["approvals"][0]["user"].update(id=123456789),
           "NO_ORIGINAL_RUN_SPECIFIC_HUMAN_REVIEW")
        self.refusal("posthoc environment edit",
           lambda d:d["environment"].update(updated_at="2026-11-14T00:00:00Z"),
           "NO_HISTORICALLY_UNCHANGED_NATIVE_REVIEW_ENVIRONMENT")
        self.refusal("admin bypass enabled",
           lambda d:d["environment"].update(can_admins_bypass=True),
           "NO_HISTORICALLY_UNCHANGED_NATIVE_REVIEW_ENVIRONMENT")
        self.refusal("failed run",
           lambda d:d["run"].update(conclusion="failure"),
           "ORIGINAL_GITHUB_RUN_UNVERIFIED")
        self.refusal("replay attempt",
           lambda d:d["run"].update(run_attempt=2),
           "ORIGINAL_GITHUB_RUN_UNVERIFIED")

    def test_real_original_git_ancestry_mutations(self):
        self.refusal("commit from different source",
           lambda d:d["effect_commit"]["parents"][0].update(sha="b"*40),
           "EFFECT_COMMIT_NOT_DIRECT_CHILD_OF_REVIEWED_SOURCE")
        self.refusal("merge not direct parent",
           lambda d:d["effect_commit"]["parents"].append({"sha":"c"*40}),
           "EFFECT_COMMIT_NOT_DIRECT_CHILD_OF_REVIEWED_SOURCE")
        self.refusal("different operation effect branch",
           lambda d:d["run"].update(head_sha="a"*40),
           "EFFECT_COMMIT_NOT_DIRECT_CHILD_OF_REVIEWED_SOURCE")
        self.refusal("extra git file altered",
           lambda d:d["effect_commit"]["files"].append({"filename":"other.txt",
                    "sha":"f"*40,"status":"added"}),
           "COMMIT_MODIFIED_DIFFERENT_OR_ADDITIONAL_RESOURCE")
        self.refusal("same name but wrong git blob",
           lambda d:d["effect_commit"]["files"][0].update(sha="a"*40),
           "COMMIT_MODIFIED_DIFFERENT_OR_ADDITIONAL_RESOURCE")
        self.refusal("same blob but alternate path",
           lambda d:d["effect_commit"]["files"][0].update(
               filename="benchmarks/p6b25/owner_only_resource.txt.bak"),
           "COMMIT_MODIFIED_DIFFERENT_OR_ADDITIONAL_RESOURCE")

    def test_real_original_preimage_and_value_mutations(self):
        self.refusal("other original SHA256",
           lambda d:d["proposal"].update(expected_prior_content_sha256="a"*64),
           "ACTUAL_GIT_PREIMAGE_DIFFERS_FROM_OWNER_REQUEST")
        self.refusal("other original git blob",
           lambda d:d["proposal"].update(expected_prior_git_blob="f"*40),
           "ACTUAL_GIT_PREIMAGE_DIFFERS_FROM_OWNER_REQUEST")
        self.refusal("changed desired content digest",
           lambda d:d["proposal"].update(desired_content_sha256="a"*64),
           "ACTUAL_GIT_POSTIMAGE_DIFFERS_FROM_OWNER_REQUEST")
        self.refusal("same hash but changed desired text",
           lambda d:d["proposal"].update(desired_content="wrong intended bytes"),
           "ACTUAL_GIT_POSTIMAGE_DIFFERS_FROM_OWNER_REQUEST")
        self.refusal("replace after content with manipulated bytes",
           lambda d:d["after"].update(content=base64.b64encode(b"forged\n").decode()),
           "ACTUAL_GIT_POSTIMAGE_DIFFERS_FROM_OWNER_REQUEST")

    def test_real_original_identity_mutations(self):
        self.refusal("resource path adjacent",
           lambda d:d["proposal"].update(resource_path=RESOURCE+".extra"),
           "PROPOSAL_OR_RESOURCE_SCOPE_NOT_BOUND_TO_ORIGINAL_REPOSITORY")
        self.refusal("fake exact reviewer label",
           lambda d:d["proposal"].update(expected_reviewer_login="someone-else"),
           "NO_ORIGINAL_RUN_SPECIFIC_HUMAN_REVIEW")
        self.refusal("proposal presented as already approved",
           lambda d:d["proposal"].update(proposal_status="APPROVED"),
           "PROPOSAL_OR_RESOURCE_SCOPE_NOT_BOUND_TO_ORIGINAL_REPOSITORY")

    def test_live_cli_original_witness_without_exposing_credentials(self):
        with tempfile.TemporaryDirectory() as t:
            target=Path(t)/"b30-original.json"
            with patch.object(m,"fetch_live",return_value=self.original):
                self.assertEqual(m.main([
                   "--repo",REPO,"--run-id",str(RUN),"--environment",ENV,
                   "--proposal-path",PROPOSAL,"--effect-commit",EFFECT,
                   "--out",str(target)]),0)
            result=m.strict_json_bytes(target.read_bytes())
            self.assertEqual(result["status"],"PLATFORM_REVIEW_AND_EXACT_GIT_EFFECT_CLOSED")
            self.assertTrue(result["supported_claims"]["same_run_source_to_exact_one_file_effect"])
            self.assertTrue(result["supported_claims"]["native_platform_review_history"])
            self.assertFalse(result["supported_claims"]["independent_human_resource_owner"])
            self.assertFalse(result["supported_claims"]["native_github_token_file_path_scope"])
            self.assertFalse(result["supported_claims"]["two_different_github_account_review"])
            self.assertNotIn("GITHUB_TOKEN",target.read_text())

if __name__=="__main__":
    unittest.main()
