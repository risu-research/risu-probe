"""B32 adversarial signer/source/subject boundary tests.

Pure policy fixtures are NOT cryptographically verified. Original signed
release tests use the official gh verifier against the frozen real artifacts.
Separate heldouts are evaluated only after source and policy are locked.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import risu_delegated_signer as m

SAMPLES={
 "h2":{
  "source_repo":"txn2/kubefwd",
  "signer_identity":"https://github.com/txn2/kubefwd/.github/workflows/release.yml@refs/tags/v1.25.17",
  "source_ref":"refs/tags/v1.25.17",
  "expected_sha256":"f9a2986f26d219713429477511f5f570df12c811e0f79d42b244569746e8eba1",
  "filename":"kubefwd_Linux_x86_64.tar.gz",
  "signer_repo":"txn2/kubefwd",
  "delegated":False,
 },
 "h3":{
  "source_repo":"UpCloudLtd/upcloud-cli",
  "signer_identity":"https://github.com/UpCloudLtd/workflows/.github/workflows/build-provenance.yaml@refs/heads/main",
  "source_ref":"refs/tags/v3.37.0",
  "expected_sha256":"ce2d381bdf49ce74a74582f390490542c49957079d7e606303e1426138b7e3d6",
  "filename":"upcloud-cli_3.37.0_linux_x86_64.tar.gz",
  "signer_repo":"UpCloudLtd/workflows",
  "delegated":True,
 },
 "h4":{
  "source_repo":"axonops/audit",
  "signer_identity":"https://github.com/axonops/audit/.github/workflows/goreleaser.yml@refs/heads/main",
  "source_ref":"refs/heads/main",
  "expected_sha256":"e0b075569683a2614656f7923271b8b302dd167950bb3480f0021f2bf12c3f2a",
  "filename":"audit_0.2.5_linux_amd64.tar.gz",
  "signer_repo":"axonops/audit",
  "delegated":False,
 },
}
H1={
 "source_repo":"mitre/hdf-libs",
 "signer_identity":"https://github.com/mitre/hdf-libs/.github/workflows/release.yml@refs/tags/v3.5.1",
 "source_ref":"refs/tags/v3.5.1",
 "expected_sha256":"482bc0e3a92a508d141e9285eba9985965c0d6bc67e922903359d70e06c3ae7a",
 "filename":"hdf_3.5.1_linux_amd64.tar.gz",
}

def source_args(x):
    return {k:x[k] for k in ("source_repo","signer_identity","source_ref","expected_sha256")}

class OfflineBoundaries(unittest.TestCase):
    def test_narrow_repo_input_and_confusable_path(self):
        for r in ("../escape","../..","a/..","a/.","-a/name","o/-repo","a/b/c",""):
            self.assertFalse(m.valid_repo(r),r)
        self.assertTrue(m.valid_repo("UpCloudLtd/upcloud-cli"))

    def test_single_dotslash_goreleaser_subject_not_arbitrary_path(self):
        self.assertTrue(m.subject_matches("./kubefwd_Linux_x86_64.tar.gz",
                                          "kubefwd_Linux_x86_64.tar.gz"))
        self.assertTrue(m.subject_matches("kubefwd_Linux_x86_64.tar.gz",
                                          "kubefwd_Linux_x86_64.tar.gz"))
        for x in ("../kubefwd_Linux_x86_64.tar.gz",
                  "././kubefwd_Linux_x86_64.tar.gz",
                  "other/kubefwd_Linux_x86_64.tar.gz"):
            self.assertFalse(m.subject_matches(x,"kubefwd_Linux_x86_64.tar.gz"))

    def test_malicious_duplicate_attestation_field_rejected(self):
        with self.assertRaises(m.Refused):
            m.strict_json('{"verificationResult":{},"verificationResult":{}}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(m.Refused):
            m.strict_json('[{"timestamp":NaN}]')

    def test_unsigned_json_label_cannot_verify(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h3"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"unsigned demo")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            with patch.object(m.shutil,"which",return_value=None):
                with self.assertRaisesRegex(m.Refused,
                                             "OFFICIAL_GITHUB_SIGSTORE_CRYPTOGRAPHIC_VERIFIER_MISSING"):
                    m.verify_original(p,allow_delegated=True,**args)

    def test_delegation_requires_explicit_caller_allow(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h3"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"dev fixture")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            with self.assertRaisesRegex(m.Refused,"DELEGATED_SIGNER_NOT_EXPLICITLY_AUTHORIZED"):
                m.preflight(p,allow_delegated=False,**args)

    def test_original_digest_mismatch_fails_before_gh(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h2"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"wrong data")
            with self.assertRaisesRegex(m.Refused,"ORIGINAL_SIGNED_FILE_SHA256_MISMATCH"):
                m.preflight(p,allow_delegated=False,**source_args(x))

    def test_no_valid_gh_verification_when_command_exits_failure(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h2"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"mock")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            class Failed:
                returncode=1
                stdout='[{"verified":true}]'
                stderr="missing original attestation"
            with patch.object(m.shutil,"which",return_value="/usr/bin/gh"), patch.object(
                 m.subprocess,"run",return_value=Failed()):
                with self.assertRaisesRegex(m.Refused,"ORIGINAL_GH_SIGSTORE_ATTESTATION_NOT_VERIFIED"):
                    m.verify_original(p,allow_delegated=False,**args)

    def test_gh_command_enforces_exact_source_and_distinct_signer(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h3"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"mock")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            commands=[]
            class Denied:
                returncode=1
                stdout=""
                stderr=""
            def run(args,**kw):
                commands.append(args)
                return Denied()
            with patch.object(m.shutil,"which",return_value="/usr/bin/gh"),patch.object(
                 m.subprocess,"run",side_effect=run):
                with self.assertRaises(m.Refused):
                    m.verify_original(p,allow_delegated=True,**args)
            command=commands[0]
            for flag,expected in (
              ("--repo","UpCloudLtd/upcloud-cli"),
              ("--cert-identity",x["signer_identity"]),
              ("--source-ref","refs/tags/v3.37.0"),
              ("--cert-oidc-issuer",m.ISSUER),
              ("--predicate-type",m.PREDICATE)):
                self.assertIn(flag,command)
                self.assertEqual(command[command.index(flag)+1],expected)
            self.assertNotIn("--signer-repo",command)
            self.assertNotIn("--bundle",command)

    def test_wrong_signer_or_source_ref_blocked_before_network(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h2"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"mock")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            args["signer_identity"]="https://github.com/evil/../.github/workflows/a.yml@refs/tags/v1"
            with self.assertRaises(m.Refused):
                m.preflight(p,allow_delegated=False,**args)
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            args["source_ref"]="refs/tags/../main"
            with self.assertRaises(m.Refused):
                m.preflight(p,allow_delegated=False,**args)

    def test_fake_successful_gh_json_not_sufficient(self):
        with tempfile.TemporaryDirectory() as d:
            x=SAMPLES["h2"]
            p=Path(d)/x["filename"]
            p.write_bytes(b"mock")
            args=source_args(x)
            args["expected_sha256"]=hashlib.sha256(p.read_bytes()).hexdigest()
            class Forged:
                returncode=0
                stdout='[{"verificationResult":{"statement":{"subject":[{"name":"kubefwd_Linux_x86_64.tar.gz"}]}}}]'
                stderr=""
            with patch.object(m.shutil,"which",return_value="/usr/bin/gh"),patch.object(
                m.subprocess,"run",return_value=Forged()):
                with self.assertRaises(m.Refused):
                    m.verify_original(p,allow_delegated=False,**args)

class OriginalSignedRecordsPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        location=os.environ.get("RISU_B32_NATIVE_VERIFIED_STATEMENTS_DIR")
        if not location:
            raise unittest.SkipTest("Requires frozen real gh outputs; pure policy only, never substitute for crypto")
        cls.root=Path(location)
        names={"h2":"kubefwd.json","h3":"upcloud-delegated.json","h4":"axonops.json"}
        cls.data={k:json.loads((cls.root/name).read_text()) for k,name in names.items()}

    def policy(self,key,source=None):
        c=SAMPLES[key]
        data=source if source is not None else self.data[key]
        return m.inspect_verified_record(data,c["source_repo"],c["signer_repo"],
               c["signer_identity"],c["source_ref"],c["filename"],
               c["expected_sha256"],c["delegated"])

    def test_three_original_signed_baseline_structurally_consistent(self):
        for key in ("h2","h3","h4"):
            with self.subTest(case=key):
                original=self.policy(key)
                self.assertRegex(original["source_sha"],"^[0-9a-f]{40}$")
                self.assertRegex(original["signer_sha"],"^[0-9a-f]{40}$")
        self.assertEqual(self.policy("h2")["subject_signed_name"],
                         "./kubefwd_Linux_x86_64.tar.gz")
        self.assertNotEqual(self.policy("h3")["signer_sha"],
                            self.policy("h3")["source_sha"])

    def change(self,key,edit):
        data=copy.deepcopy(self.data[key])
        edit(data[0]["verificationResult"])
        with self.assertRaises(m.Refused):
            self.policy(key,data)

    def test_signer_certificate_uri_tamper(self):
        self.change("h3",lambda v:v["signature"]["certificate"].update(
            subjectAlternativeName="https://github.com/attacker/repo/.github/workflows/release.yml@refs/heads/main"))

    def test_original_producer_repo_tamper(self):
        self.change("h3",lambda v:v["signature"]["certificate"].update(
            sourceRepositoryURI="https://github.com/txn2/kubefwd"))

    def test_source_ref_tamper(self):
        self.change("h3",lambda v:v["signature"]["certificate"].update(
            sourceRepositoryRef="refs/heads/main"))

    def test_signed_predicate_different_project(self):
        def mutate(v):
            v["statement"]["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"]="https://github.com/axonops/audit"
        self.change("h3",mutate)

    def test_signed_subject_relabel(self):
        def mutate(v):
            for obj in v["statement"]["subject"]:
                if obj.get("name")=="upcloud-cli_3.37.0_linux_x86_64.tar.gz":
                    obj["name"]="../upcloud-cli_3.37.0_linux_x86_64.tar.gz"
        self.change("h3",mutate)

    def test_original_subject_digest_wrong(self):
        def mutate(v):
            for obj in v["statement"]["subject"]:
                if obj.get("name")=="./kubefwd_Linux_x86_64.tar.gz":
                    obj["digest"]["sha256"]="f"*64
        self.change("h2",mutate)

    def test_fake_duplicate_subject_rejected(self):
        def mutate(v):
            for obj in list(v["statement"]["subject"]):
                if obj.get("name")=="./kubefwd_Linux_x86_64.tar.gz":
                    v["statement"]["subject"].append(copy.deepcopy(obj))
        self.change("h2",mutate)

    def test_producer_and_signer_must_not_be_conflated(self):
        c=SAMPLES["h3"]
        with self.assertRaises(m.Refused):
            m.inspect_verified_record(self.data["h3"],c["source_repo"],
                c["source_repo"],c["signer_identity"],c["source_ref"],
                c["filename"],c["expected_sha256"],False)

class OriginalNativeCryptoChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        location=os.environ.get("RISU_B32_ORIGINAL_RELEASE_DIR")
        if not location:raise unittest.SkipTest("Requires original external signed release bytes and gh")
        cls.root=Path(location)

    def case(self,key):
        c=SAMPLES[key]
        return m.verify_original(self.root/c["filename"],
            **source_args(c),allow_delegated=c["delegated"])

    def test_original_kubefwd_github_signature_and_dot_slash_subject(self):
        x=self.case("h2")
        self.assertTrue(x["normalized_single_dot_slash_prefix"])
        self.assertFalse(x["grants_authority_over_unrelated_resource"])

    def test_actual_upcloud_separately_operated_reusable_signer(self):
        x=self.case("h3")
        self.assertEqual(x["source_repository"],"UpCloudLtd/upcloud-cli")
        self.assertEqual(x["signer_repository"],"UpCloudLtd/workflows")
        self.assertTrue(x["delegation_explicitly_accepted"])
        self.assertFalse(x["grants_authority_over_unrelated_resource"])
        self.assertEqual(x["claim_states"]["separate_resource_owner_approval"],"UNVERIFIED")

    def test_original_axonops_main_branch_sla_attestation(self):
        x=self.case("h4")
        self.assertEqual(x["source_ref"],"refs/heads/main")
        self.assertFalse(x["delegation_explicitly_accepted"])

    def test_valid_delegation_not_implicitly_granted(self):
        c=SAMPLES["h3"]
        with self.assertRaisesRegex(m.Refused,"DELEGATED_SIGNER_NOT_EXPLICITLY_AUTHORIZED"):
            m.verify_original(self.root/c["filename"],**source_args(c),
                              allow_delegated=False)

    def test_original_release_one_byte_modified_attacker_recomputed_hash_still_cryptographically_rejected(self):
        c=SAMPLES["h2"]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/c["filename"]
            p.write_bytes((self.root/c["filename"]).read_bytes())
            with p.open("r+b") as f:
                b=f.read(1)
                f.seek(0)
                f.write(bytes([b[0]^1]))
            other=source_args(c)
            other["expected_sha256"]=m.file_sha256(p)
            with self.assertRaisesRegex(m.Refused,"ORIGINAL_GH_SIGSTORE_ATTESTATION_NOT_VERIFIED"):
                m.verify_original(p,**other,allow_delegated=False)

    def test_genuine_signed_wrong_repos_does_not_get_permission(self):
        c=SAMPLES["h2"]
        changed=source_args(c)
        changed["source_repo"]="axonops/audit"
        changed["signer_identity"]=SAMPLES["h4"]["signer_identity"]
        changed["source_ref"]=SAMPLES["h4"]["source_ref"]
        with self.assertRaisesRegex(m.Refused,"ORIGINAL_GH_SIGSTORE_ATTESTATION_NOT_VERIFIED"):
            m.verify_original(self.root/c["filename"],**changed,
                              allow_delegated=False)

if __name__=="__main__":
    unittest.main()
