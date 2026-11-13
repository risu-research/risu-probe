"""B33 adversarial original source/run/signature/time/effect evidence closure tests.

The original GitHub & Sigstore facts are collected afresh by the previous
CI step. These mutation tests are STRICTLY STRUCTURAL; only the CLI
verify-signed-effect-chain may report LIVE cryptographic verification.
"""
from __future__ import annotations
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
from io import BytesIO

import risu_signed_effect_chain as m

class B33ParserAndTrustBoundary(unittest.TestCase):
    def test_original_rest_retries_transient_http_without_weakening_evidence(self):
        response=MagicMock()
        response.__enter__.return_value.status=200
        response.__enter__.return_value.read.return_value=b'{"id":43458536273}'
        temporary=HTTPError("https://api.github.com/test",502,"Bad Gateway",{},BytesIO(b""))
        with patch.object(m,"urlopen",side_effect=[temporary,response]) as get, \
             patch.object(m.time,"sleep") as sleep:
            self.assertEqual(m.api("risu-research/risu-verify","/test","test-token"),
                             {"id":43458536273})
        self.assertEqual(get.call_count,2)
        sleep.assert_called_once_with(1)

    def test_original_rest_does_not_retry_permanent_missing_or_denied(self):
        for code in (401,403,404):
            error=HTTPError("https://api.github.com/test",code,"Denied",{},BytesIO(b""))
            with self.subTest(status=code), \
                 patch.object(m,"urlopen",side_effect=error) as get, \
                 patch.object(m.time,"sleep") as sleep:
                with self.assertRaisesRegex(m.Refused,f"ORIGINAL_GITHUB_REST_HTTP_{code}"):
                    m.api("risu-research/risu-verify","/test","test-token")
                self.assertEqual(get.call_count,1)
                sleep.assert_not_called()

    def test_original_rest_refuses_after_bounded_transport_retries(self):
        with patch.object(m,"urlopen",side_effect=OSError("intermittent lookup")) as get, \
             patch.object(m.time,"sleep") as sleep:
            with self.assertRaisesRegex(m.Refused,"ORIGINAL_GITHUB_REST_LOOKUP_FAILED"):
                m.api("risu-research/risu-verify","/test","test-token")
            self.assertEqual(get.call_count,3)
            self.assertEqual(sleep.call_count,2)
    def test_no_path_escape(self):
        for bad in ("/tmp/a","../a","a/../b","a//b","a/./b","a\\b","",
                    "a b","a/%2e%2e","a;b"):
            self.assertFalse(m.valid_path(bad),bad)
        self.assertTrue(m.valid_path("benchmarks/p6b33/owner_resource.txt"))

    def test_no_repo_lookalike(self):
        for bad in ("../../repo","a/..","a/.","a/b/c","../a","a/-repo","-owner/repo",""):
            self.assertFalse(m.valid_repo(bad),bad)
        self.assertTrue(m.valid_repo("risu-research/risu-verify"))

    def test_no_ref_backtracking(self):
        for bad in ("refs/heads/../main","refs/heads/./main",
                    "refs/tags/v1","refs/heads/a b","refs/heads//branch",""):
            self.assertFalse(m.valid_ref(bad),bad)
        self.assertTrue(m.valid_ref(
            "refs/heads/qualification/p6b33-signed-execution-effect-live-20261113"))

    def test_duplicate_json_key_refused(self):
        with self.assertRaisesRegex(m.Refused,"EVIDENCE_DUPLICATE_JSON_KEY"):
            m.strict('{"status":"VERIFIED","status":"INVALID"}')

    def test_nan_refused(self):
        with self.assertRaisesRegex(m.Refused,"EVIDENCE_NONFINITE_NUMBER"):
            m.strict('{"time":NaN}')

    def test_git_blob_sha(self):
        raw=b"B33 scope-controlled GitHub resource\nstate=INITIAL\nscope=ONE_TARGET_PATH\n"
        self.assertEqual(m.blob_sha1(raw),"8aadf1603c17e9966a7831c904ee0dcca620337c")
        self.assertEqual(m.sha256(raw),"3d94021520c4e5cbfe28f22e9a427caafcc8356a551ef54d36ad16c280418870")

    def test_remote_github_base64_folding_allowed_but_not_ambiguous(self):
        data=b"hello b33\n"
        enc=base64.b64encode(data).decode()
        orig={"type":"file","encoding":"base64","content":enc[:4]+"\n"+enc[4:],
              "size":len(data),"sha":m.blob_sha1(data)}
        self.assertEqual(m.decode_contents(orig),data)
        for bad in ("a!"+enc[1:],enc[:-2]+"==\nextra",enc[:-1]+"A"):
            x=orig.copy();x["content"]=bad
            with self.assertRaises(m.Refused):
                m.decode_contents(x)

    def test_no_signature_can_be_derived_from_synthetic_json_in_offline_mode(self):
        with self.assertRaises(m.Refused):
            m.normalize({"schema":m.SOURCE_SCHEMA,"run":{}})
        with self.assertRaisesRegex(m.Refused,
                                    "OFFICIAL_GITHUB_SIGSTORE_VERIFIER_UNAVAILABLE"):
            with tempfile.TemporaryDirectory() as t:
                p=Path(t)/"script.py";p.write_bytes(b"mock source")
                with patch.object(m.shutil,"which",return_value=None):
                    m.gh_verified(p,"owner/repo","https://github.com/owner/repo/.github/workflows/a.yml@refs/heads/main",
                                  "refs/heads/main","a"*40,1,"unused")
    def test_invalid_missing_token_and_run_refused_before_network(self):
        with self.assertRaises(m.Refused):
            m.collect_live("owner/../repo",43458536273,"artifact",
                           ".github/workflows/a.yml","secret")
        with self.assertRaises(m.Refused):
            m.collect_live("risu-research/risu-verify",0,"artifact",
                           ".github/workflows/a.yml","secret")
        with self.assertRaisesRegex(m.Refused,"UNSAFE_ORIGINAL_INTENT_PATH"):
            m.collect_live("risu-research/risu-verify",43458536273,"artifact",
                           ".github/workflows/a.yml","not-a-token",
                           intent_path="../forged.json")

class B33OriginalVerifiedFactsAdversarial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        location=os.environ.get("RISU_B33_ORIGINAL_FACTS_DIR")
        if not location:
            raise unittest.SkipTest("Actual original GitHub/Sigstore snapshot needed; original REST verified in separate step")
        p=Path(location)/"B33_ORIGINAL_NORMALIZED_SOURCE_FACTS.json"
        cls.original=m.strict(p.read_bytes())
        cls.base=m.normalize(cls.original)

    def test_actual_source_structural_positive_is_not_cryptographic_verification(self):
        r=self.base
        self.assertEqual(r["status"],"ORIGINAL_STRUCTURAL_SOURCE_RUN_EFFECT_FACTS_CLOSED")
        self.assertEqual(r["verification_mode"],
                         "STRUCTURAL_ONLY_ORIGINAL_SIGSTORE_GITHUB_FACTS_NEED_FRESH_VERIFICATION")
        self.assertEqual(r["source_repository"],"risu-research/risu-verify")
        self.assertEqual(r["original_run_id"],43458536273)
        self.assertEqual(r["original_source_sha"],
                         "9b02c07eed9293b3703e484562be322eaec10ac1")
        self.assertEqual(r["effect_commit"],
                         "ccd589714359eaefd8a84335d8d4982596dc6a4c")
        self.assertEqual(r["exact_resource_path"],
                         "benchmarks/p6b33/owner_resource.txt")
        self.assertEqual(r["claim_states"]["independent_human_resource_owner_approval"],
                         "UNVERIFIED")
        self.assertEqual(r["claim_states"]["repository_token_file_scoped_by_github"],
                         "REFUTED")
        self.assertEqual(r["claim_states"]["actual_instruction_trace_in_trusted_hardware"],
                         "UNVERIFIED")
        self.assertEqual(len(r["time_sequence"]),10)

    def refuse(self,name,change):
        x=copy.deepcopy(self.original)
        change(x)
        with self.subTest(forged=name):
            with self.assertRaises(m.Refused):
                m.normalize(x)

    def test_genuine_signatures_but_from_another_run_fail(self):
        self.refuse("replayed source run",
            lambda x:x["run"].update(id=43458536274))
        self.refuse("same actor alternate run attempt",
            lambda x:x["run"].update(attempt=2))
        self.refuse("other signature run",
            lambda x:x["signatures"]["receipt"].update(run_id=43458536274))
        self.refuse("cross-repo original",
            lambda x:x["run"].update(repository="other-owner/other-repo"))
        self.refuse("other head sha",
            lambda x:x["run"].update(head_sha="b"*40))
        self.refuse("other source ref",
            lambda x:x["run"].update(source_ref="refs/heads/main"))
        self.refuse("other source policy path",
            lambda x:x.update(intent_path="../foreign-intent.json"))
        self.refuse("wrong signed signer",
            lambda x:x["signatures"]["candidate"].update(signer_identity="https://github.com/bad/bad/.github/workflows/a.yml@refs/heads/main"))
        self.refuse("other signed source commit",
            lambda x:x["signatures"]["broker"].update(source_sha="c"*40))
        self.refuse("other signed receipt",
            lambda x:x["signatures"]["receipt"].update(signed_subject_sha256="0"*64))
        self.refuse("program source digest replaced",
            lambda x:x.update(candidate_program_sha256="a"*64))
        self.refuse("broker source digest replaced",
            lambda x:x.update(broker_program_sha256="a"*64))
        self.refuse("runtime program hash replaced",
            lambda x:x["candidate"].update(tool_program_sha256="a"*64))

    def test_original_actor_and_platform_authority_substitution(self):
        self.refuse("runner actor changed",
            lambda x:x["run"].update(actor="another-account"))
        self.refuse("receipt actor changed",
            lambda x:x["receipt"].update(actor="another-account"))
        self.refuse("no job success",
            lambda x:x["writer_job"].update(conclusion="failure"))
        self.refuse("no run success",
            lambda x:x["run"].update(conclusion="failure"))
        self.refuse("wrong job name",
            lambda x:x["writer_job"].update(name="fake-successful-run"))
        self.refuse("no native workflow contents write",
            lambda x:x["authorization"].update(source_workflow_declares_contents_write=False))
        self.refuse("auditor not readonly",
            lambda x:x["authorization"].update(source_audit_job_read_only=False))
        self.refuse("repo token declared path scoped",
            lambda x:x["receipt"].update(trusted_broker_write_token_scope="ONE_FILE_GITHUB_TOKEN"))
        self.refuse("candidate had write token",
            lambda x:x["candidate"].update(tool_write_credential_available=True))
        self.refuse("fraudulent independent-human consent",
            lambda x:x["receipt"].update(human_owner_approval_proven=True))

    def test_exact_source_to_one_remote_resource_pre_and_post(self):
        self.refuse("different target resource",
            lambda x:x["receipt"].update(resource_path="benchmarks/p6b33/unapproved.txt"))
        self.refuse("extra modified resource",
            lambda x:x["original"].update(changed_count=2))
        self.refuse("different Git child",
            lambda x:x["original"].update(effect_parents=["f"*40]))
        self.refuse("merge commit with alternative parent",
            lambda x:x["original"].update(effect_parents=[
                x["run"]["head_sha"],"f"*40]))
        self.refuse("wrong original commit",
            lambda x:x["receipt"].update(remote_effect_commit="e"*40))
        self.refuse("no real effect",
            lambda x:x["original"].update(remote_git_effect_observed=False))
        self.refuse("unchanged remote state",
            lambda x:x["original"].update(after_sha256=x["original"]["before_sha256"]))
        self.refuse("wrong source preimage hash",
            lambda x:x["intent"].update(expected_prior_sha256="a"*64))
        self.refuse("false observed afterhash",
            lambda x:x["original"].update(after_sha256="b"*64))
        self.refuse("other original Git blob",
            lambda x:x["receipt"].update(after_git_blob="a"*40))
        self.refuse("renamed object",
            lambda x:x["original"].update(changed_status="renamed"))
        self.refuse("different owner policy",
            lambda x:x["intent"].update(owner_repository="another-owner/another-repo"))
        self.refuse("unsigned candidate receipt inserted",
            lambda x:x.update(candidate_receipt_sha256="b"*64))
        self.refuse("policy digest substituted",
            lambda x:x.update(policy_sha256="b"*64))

    def test_verified_timing_chronology_breaks_on_independent_sources(self):
        self.refuse("signed candidate after tool execution",
            lambda x:x["signatures"]["candidate"].update(signed_at="2026-11-13T16:05:01Z"))
        self.refuse("signed broker after runtime request",
            lambda x:x["signatures"]["broker"].update(signed_at="2026-11-13T16:06:00Z"))
        self.refuse("signed receipt before effect",
            lambda x:x["signatures"]["receipt"].update(signed_at="2026-11-13T16:00:00Z"))
        self.refuse("remote Git effect before original job",
            lambda x:x["original"].update(effect_commit_time="2026-11-13T10:00:00Z"))
        self.refuse("native job finished too early",
            lambda x:x["writer_job"].update(completed_at="2026-11-13T16:01:55Z"))
        self.refuse("broker executed before program",
            lambda x:x["receipt"].update(broker_started_at="2026-11-13T15:02:03Z"))
        self.refuse("tool run end before tool start",
            lambda x:x["candidate"].update(returned_at="2026-11-13T16:00:00Z"))
        self.refuse("unverified bogus UTC timezone",
            lambda x:x["signatures"]["candidate"].update(signed_at="2026-11-13 16:02:03"))

    def test_full_original_trace_does_not_substitute_for_independent_owner(self):
        self.assertEqual(self.base["claim_states"]["native_job_actor_source_ref_binding"],"VERIFIED")
        self.assertEqual(self.base["claim_states"]["fixed_one_resource_actual_git_effect"],"VERIFIED")
        self.assertNotIn("independent_human_resource_owner_approval",
                         [k for k,v in self.base["claim_states"].items() if v=="VERIFIED"])

class B33TwoIndependentLiveOriginalRunsCannotBeStitched(unittest.TestCase):
    """Real valid Sigstore evidence from two distinct repos cannot be joined.

    Both H1 and H2 completed actual GitHub writes and separate readonly audits.
    This tests mixed ORIGINAL POSITIVES, not fabricated fake attestations.
    """
    @classmethod
    def setUpClass(cls):
        location=os.environ.get("RISU_B33_ORIGINAL_FACTS_DIR")
        if not location:
            raise unittest.SkipTest("Requires two fresh original GitHub/Sigstore source snapshots")
        root=Path(location)
        cls.h1=m.strict((root/"B33_ORIGINAL_NORMALIZED_SOURCE_FACTS.json").read_bytes())
        cls.h2=m.strict((root/"B33_H2_ORIGINAL_NORMALIZED_SOURCE_FACTS.json").read_bytes())
        cls.a=m.normalize(cls.h1)
        cls.b=m.normalize(cls.h2)

    def test_both_independently_authentic_original_runs_have_valid_structural_chain(self):
        self.assertEqual(self.a["original_run_id"],43458536273)
        self.assertEqual(self.b["original_run_id"],43461936460)
        self.assertNotEqual(self.a["source_repository"],self.b["source_repository"])
        self.assertNotEqual(self.a["original_source_sha"],self.b["original_source_sha"])
        self.assertNotEqual(self.a["source_candidate_sha256"],self.b["source_candidate_sha256"])
        self.assertNotEqual(self.a["source_broker_sha256"],self.b["source_broker_sha256"])
        self.assertNotEqual(self.a["signed_execution_receipt_sha256"],
                            self.b["signed_execution_receipt_sha256"])
        self.assertNotEqual(self.a["effect_commit"],self.b["effect_commit"])
        self.assertEqual(self.a["original_before_sha256"],self.b["original_before_sha256"])
        self.assertEqual(self.a["original_after_sha256"],self.b["original_after_sha256"])
        self.assertEqual(self.a["original_actor"],self.b["original_actor"])
        self.assertEqual(self.h1["authorization"],self.h2["authorization"])
        self.assertNotEqual(self.a["source_repository"],self.b["source_repository"])

    def reject_genuine_cross_run_mix(self,label,field):
        mixed=copy.deepcopy(self.h1)
        mixed[field]=copy.deepcopy(self.h2[field])
        with self.subTest(mixed_real_original=label):
            with self.assertRaises(m.Refused):
                m.normalize(mixed)

    def test_actual_crypto_verified_other_run_source_is_not_approval(self):
        # Platform permissions are the same on both runs by design; the
        # read-only source-verified permissions are policy properties, not
        # a unique subject/run identity, so swapping identical values is valid.
        for key in ("run","writer_job","signatures","candidate","receipt",
                    "intent","original"):
            self.reject_genuine_cross_run_mix(key,key)

    def test_specific_valid_signatures_cannot_move_between_original_runs(self):
        for role in ("candidate","broker","receipt"):
            mixed=copy.deepcopy(self.h1)
            mixed["signatures"][role]=copy.deepcopy(self.h2["signatures"][role])
            with self.subTest(signed_actual_other_run=role):
                with self.assertRaises(m.Refused):
                    m.normalize(mixed)

    def test_exactly_matching_old_new_content_hashes_are_not_enough(self):
        # The *same* initial/desired text in two independent GitHub repos is
        # the deliberately strong identity-collision case; the bound source
        # commit, actor-run ID, program and remote commit still prevent joining.
        self.assertEqual(self.h1["original"]["before_sha256"],
                         self.h2["original"]["before_sha256"])
        self.assertEqual(self.h1["original"]["after_sha256"],
                         self.h2["original"]["after_sha256"])
        mixed=copy.deepcopy(self.h1)
        mixed["receipt"]["remote_effect_commit"]=self.h2["original"]["effect_sha"]
        mixed["original"]=copy.deepcopy(self.h2["original"])
        with self.assertRaises(m.Refused):
            m.normalize(mixed)

    def test_real_certificate_identity_differs_even_for_same_github_actor(self):
        self.assertEqual(self.h1["run"]["actor"],self.h2["run"]["actor"])
        self.assertNotEqual(self.h1["run"]["signer_identity"],
                            self.h2["run"]["signer_identity"])
        for role in ("candidate","broker","receipt"):
            self.assertNotEqual(self.h1["signatures"][role]["source_sha"],
                                self.h2["signatures"][role]["source_sha"])
            self.assertNotEqual(self.h1["signatures"][role]["run_id"],
                                self.h2["signatures"][role]["run_id"])

    def test_neither_operator_controlled_original_proves_external_human(self):
        for conclusion in (self.a,self.b):
            self.assertEqual(conclusion["claim_states"]["independent_human_resource_owner_approval"],
                             "UNVERIFIED")
            self.assertEqual(conclusion["claim_states"]["actual_instruction_trace_in_trusted_hardware"],
                             "UNVERIFIED")
            self.assertEqual(conclusion["claim_states"]["repository_token_file_scoped_by_github"],
                             "REFUTED")

if __name__=="__main__":
    unittest.main()
