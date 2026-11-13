"""B31 signed attestation verification tests. No false claim of mock crypto.

Development: GitHub CLI 2.62 signed archive.
Locked independent holdout: Sigstore Fulcio 1.10 signed binary.
Real crypto tests enabled ONLY by B31_ORIGINAL_RELEASE_DIR and executed with
the actual official gh verifier + Sigstore trust root, not fixture JSON.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import risu_signed_release_verifier as m

DEVELOPMENT={
 "repo":"cli/cli",
 "filename":"gh_2.62.0_linux_amd64.tar.gz",
 "signer_workflow":"cli/cli/.github/workflows/deployment.yml",
 "source_ref":"refs/heads/trunk",
 "expected_digest":"41c8b0698ad3003cb5c44bde672a1ffd5f818595abd80162fbf8cc999418446a",
}
HOLDOUT={
 "repo":"sigstore/fulcio",
 "filename":"fulcio-linux-amd64",
 "signer_workflow":"sigstore/fulcio/.github/workflows/release.yml",
 "source_ref":"refs/tags/v1.10.0",
 "expected_digest":"92092b98fbb78ec24585982f970367a734ac8ab035fde42df05ef9b0c48cb07d",
}

class StructuralTest(unittest.TestCase):
    def test_duplicate_json_rejected(self):
        with self.assertRaises(m.Refused):
            m.safe_json('{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(m.Refused):
            m.safe_json('{"x":NaN}')
    def test_invalid_repository_and_signer(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"a.bin";path.write_bytes(b"artifacts")
            h=m.digest(path)
            with self.assertRaises(m.Refused):
                m.preflight(path,"../escape","a.bin","../escape/.github/workflows/a.yml","refs/heads/main",h)
            with self.assertRaises(m.Refused):
                m.preflight(path,"cli/cli","a.bin","sigstore/fulcio/.github/workflows/release.yml","refs/heads/main",h)
    def test_missing_official_verifier_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/"gh_2.62.0_linux_amd64.tar.gz"
            p.write_bytes(b"synthetic test only")
            args=DEVELOPMENT.copy();args["expected_digest"]=m.digest(p)
            with patch.object(m.shutil,"which",return_value=None):
                with self.assertRaisesRegex(m.Refused,"OFFICIAL_GITHUB_VERIFIER_MISSING"):
                    m.verify_artifact(p,**args)
    def test_synthetically_forged_signed_json_is_not_live_cryptography(self):
        # A fake fully marked verified object must never bypass the official
        # verifier subprocess: only verify_artifact invokes the trust root.
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/DEVELOPMENT["filename"];p.write_bytes(b"impostor")
            args=DEVELOPMENT.copy();args["expected_digest"]=m.digest(p)
            with patch.object(m.shutil,"which",return_value=None):
                with self.assertRaises(m.Refused):
                    m.verify_artifact(p,**args)
    def test_official_cryptographic_failure_refused_even_given_positive_json(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/DEVELOPMENT["filename"];p.write_bytes(b"mock only")
            args=DEVELOPMENT.copy();args["expected_digest"]=m.digest(p)
            class Failed:
                returncode=1
                stdout='[{"verificationResult":{"status":"VERIFIED"}}]'
                stderr="broken signature"
            with patch.object(m.shutil,"which",return_value="/usr/bin/gh"),patch.object(
                   m.subprocess,"run",return_value=Failed()):
                with self.assertRaisesRegex(m.Refused,"OFFICIAL_SIGSTORE_SIGNATURE"):
                    m.verify_artifact(p,**args)
    def test_official_cmd_must_enforce_expected_signer_and_source(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/DEVELOPMENT["filename"];p.write_bytes(b"mock only")
            args=DEVELOPMENT.copy();args["expected_digest"]=m.digest(p)
            class Failed:
                returncode=1
                stdout=""
                stderr=""
            calls=[]
            def invoke(argv,**kw):
                calls.append(argv);return Failed()
            with patch.object(m.shutil,"which",return_value="/usr/bin/gh"),patch.object(
                  m.subprocess,"run",side_effect=invoke):
                with self.assertRaises(m.Refused):m.verify_artifact(p,**args)
            cmd=calls[0]
            for key,val in (("--repo",DEVELOPMENT["repo"]),
                            ("--signer-workflow",DEVELOPMENT["signer_workflow"]),
                            ("--source-ref",DEVELOPMENT["source_ref"]),
                            ("--predicate-type",m.PREDICATE)):
                self.assertIn(key,cmd)
                self.assertEqual(cmd[cmd.index(key)+1],val)
            self.assertNotIn("--bundle",cmd)
            self.assertNotIn("--no-public-good",cmd)
    def test_subject_semantics_cannot_be_forged_by_omitting_expected(self):
        x={"verificationResult":{"statement":{
            "_type":m.STATEMENT,"predicateType":m.PREDICATE,
            "subject":[{"name":DEVELOPMENT["filename"],"digest":{"expected_digest":"0"*64}}],
            "predicate":{"buildDefinition":{"externalParameters":{"workflow":{
                "repository":"https://github.com/cli/cli",
                "path":".github/workflows/deployment.yml","ref":"refs/heads/trunk"}}}}},
            "signature":{"certificate":{}},"verifiedTimestamps":[{}]}}
        with self.assertRaisesRegex(m.Refused,"SIGNED_SUBJECT_DIGEST_MISMATCH"):
            m.validate_crypto_verified_output([x],DEVELOPMENT["repo"],
                   DEVELOPMENT["filename"],DEVELOPMENT["signer_workflow"],
                   DEVELOPMENT["source_ref"],DEVELOPMENT["expected_digest"])
        y=copy.deepcopy(x);y["verificationResult"]["statement"]["subject"][0]["digest"]["expected_digest"]=DEVELOPMENT["expected_digest"]
        y["verificationResult"]["statement"]["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"]="https://github.com/other/repo"
        with self.assertRaisesRegex(m.Refused,"ATTESTED_SOURCE_REPO_WORKFLOW_REF_MISMATCH"):
            m.validate_crypto_verified_output([y],DEVELOPMENT["repo"],
                   DEVELOPMENT["filename"],DEVELOPMENT["signer_workflow"],
                   DEVELOPMENT["source_ref"],DEVELOPMENT["expected_digest"])

class RealOriginallySignedReleaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=os.environ.get("B31_ORIGINAL_RELEASE_DIR")
        if not path:raise unittest.SkipTest("Requires original signed external release assets")
        cls.root=Path(path)
        for v in (DEVELOPMENT,HOLDOUT):
            if not (cls.root/v["filename"]).is_file():
                raise AssertionError("Expected exact original signed release unavailable")

    def check_live(self,v):
        res=m.verify_artifact(self.root/v["filename"],**v)
        self.assertEqual(res["verification_mode"],
            "LIVE_OFFICIAL_GITHUB_SIGSTORE_CRYPTOGRAPHIC_VERIFIER")
        self.assertEqual(res["status"],"VERIFIED_SIGNED_SOURCE_ONLY_NOT_OWNER_CONSENT")
        self.assertEqual(res["actual_artifact_sha256"],v["expected_digest"])
        self.assertEqual(res["signer_repository"],v["repo"])
        self.assertGreater(res["original_verified_timestamp_count"],0)
        self.assertFalse(res["full_resource_owner_authorization_certified"])
        self.assertFalse(res["cross_project_resource_consent_transfer_permitted"])
        self.assertEqual(res["claim_evidence_states"]["specific_external_owner_approval"],"UNVERIFIED")
        self.assertEqual(res["claim_evidence_states"]["same_operation_resource_effect"],"UNVERIFIED")
        return res

    def test_original_development_github_cli_signed_slsa_provenance(self):
        self.check_live(DEVELOPMENT)

    def test_original_independent_holdout_fulcio_signed_slsa_provenance(self):
        self.check_live(HOLDOUT)

    def test_actual_byte_tamper_rejected_before_signature_check(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/DEVELOPMENT["filename"]
            p.write_bytes((self.root/DEVELOPMENT["filename"]).read_bytes())
            with p.open("r+b") as f:
                byte=f.read(1);f.seek(0);f.write(bytes([byte[0]^1]))
            with self.assertRaisesRegex(m.Refused,"ORIGINAL_SIGNED_ASSET_BYTES_CHANGED"):
                m.verify_artifact(p,**DEVELOPMENT)

    def test_original_signed_but_wrong_publisher_does_not_authorize_other_resource(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/DEVELOPMENT["filename"]
            p.write_bytes((self.root/DEVELOPMENT["filename"]).read_bytes())
            mis=DEVELOPMENT.copy()
            mis["repo"]="sigstore/fulcio"
            mis["signer_workflow"]="sigstore/fulcio/.github/workflows/release.yml"
            mis["source_ref"]="refs/tags/v1.10.0"
            with self.assertRaisesRegex(m.Refused,"OFFICIAL_SIGSTORE_SIGNATURE_IDENTITY_VERIFICATION_FAILED"):
                m.verify_artifact(p,**mis)

    def test_true_signed_development_release_never_proves_b25_owner_write(self):
        res=self.check_live(DEVELOPMENT)
        self.assertEqual(res["claim_evidence_states"]["original_signed_SLSA_provenance"],"VERIFIED")
        self.assertEqual(res["claim_evidence_states"]["specific_external_owner_approval"],"UNVERIFIED")
        self.assertFalse(res["cross_project_resource_consent_transfer_permitted"])

    def test_unseen_holdout_origin_does_not_inherit_development_issuer(self):
        hold=self.check_live(HOLDOUT)
        dev=self.check_live(DEVELOPMENT)
        self.assertNotEqual(hold["signer_repository"],dev["signer_repository"])
        self.assertNotEqual(hold["actual_artifact_sha256"],dev["actual_artifact_sha256"])
        self.assertFalse(hold["full_resource_owner_authorization_certified"])

if __name__=="__main__":unittest.main()
