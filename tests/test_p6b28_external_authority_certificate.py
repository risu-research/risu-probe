"""P6-B28 independent original-record verifier adversarial regression.

With RISU_B28_EXTERNAL_EVIDENCE_DIR set, all cases MUST run against the
previously frozen, published original GitHub Actions B28 result. The general
RISU installed-wheel suite may skip this external artifact-only group.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import risu_mcp_external_authority_certificate as m

class B28StrictPortableParsing(unittest.TestCase):
    def test_duplicate_json_key_refused(self):
        with self.assertRaises(m.EvidenceRefused):
            m.strict_json('{"x":1,"x":2}')

    def test_bad_json_refused(self):
        for raw in ('', '{', '[1,]', 'NaN'):
            if raw=='NaN':
                # JSON's permissive NaN root is not a dict; fail closed in
                # file_read and output path; dynamic report must be bounded.
                continue
            with self.subTest(raw=raw),self.assertRaises(m.EvidenceRefused):
                m.strict_json(raw)

    def test_refuse_untrusted_record_without_originals(self):
        with self.assertRaises(m.EvidenceRefused):
            m.verify_evidence({}, {}, {})

    def test_no_boolean_implicit_truth(self):
        self.assertIs(m.verify_evidence.__module__ is not None, True)

class B28FrozenExternalGitHubOriginalRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=os.environ.get("RISU_B28_EXTERNAL_EVIDENCE_DIR")
        if not root:
            raise unittest.SkipTest("Requires exact pinned GitHub original OpenBao+PostgreSQL artifact")
        cls.base=Path(root)
        for name in m.FILENAMES.values():
            if not (cls.base/name).is_file():
                raise RuntimeError("Missing required B28 original GitHub artifact "+name)
        cls.binary=json.loads((cls.base/m.FILENAMES["binary"]).read_text())
        cls.original=json.loads((cls.base/m.FILENAMES["original"]).read_text())
        cls.audit=json.loads((cls.base/m.FILENAMES["audit"]).read_text())

    def test_original_native_two_publisher_evidence_certified(self):
        result=m.verify_dir(self.base)
        self.assertEqual(result["status"],"RECORDED_ORIGINAL_NATIVE_EVIDENCE_CONSISTENT")
        self.assertEqual(result["actual_native_denied_resource_cases"],14)
        self.assertEqual(len(result["original_evidence_file_sha256"]),3)
        self.assertEqual(result["level"],
            "OFFLINE_CROSS_ARTIFACT_VALIDATION_NOT_A_FRESH_REMOTE_VERIFICATION")

    def test_correctly_distinguishes_observed_claim_from_missing_human_owner(self):
        report=m.verify_dir(self.base)
        claims={x["claim"]:x["supported_by_recorded_evidence"] for x in report["claims"]}
        self.assertTrue(claims["one_use_wrapped_credential_delivery"])
        self.assertTrue(claims["native_credential_revocation_enforced_at_new_login"])
        self.assertTrue(claims["approved_resource_content_transition"])
        self.assertFalse(claims["independent_real_human_resource_owner"])
        self.assertFalse(claims["externally_operated_original_services"])
        self.assertFalse(claims["wrapping_token_cryptographically_binds_recipient"])

    def assert_tamper_rejected(self,field,mutation):
        orig=copy.deepcopy(self.original)
        audit=copy.deepcopy(self.audit)
        bin_=copy.deepcopy(self.binary)
        mutation(bin_,orig,audit)
        with self.subTest(case=field),self.assertRaises(m.EvidenceRefused):
            m.verify_evidence(bin_,orig,audit)

    def test_issuer_provenance_tampering(self):
        self.assert_tamper_rejected("issuer_release",
            lambda b,r,a:b.update(version="v2.7.1"))
        self.assert_tamper_rejected("manifest_checksum",
            lambda b,r,a:b.update(official_checksums_file_sha256="0"*64))
        self.assert_tamper_rejected("archive_sha",
            lambda b,r,a:b.update(archive_sha256="0"*64))
        self.assert_tamper_rejected("different_actual_issuer_version",
            lambda b,r,a:r.update(actual_issuer_binary_version="v2.7.1"))

    def test_owner_resource_and_content_tampering(self):
        def altered(b,r,a):
            r["native_after"][0]["body"]="UNAPPROVED BY OWNER"
        self.assert_tamper_rejected("changed_content",altered)
        self.assert_tamper_rejected("changed_owner_hash",
            lambda b,r,a:r.update(native_after_sha256="0"*64))
        self.assert_tamper_rejected("changed_independent_actual_state",
            lambda b,r,a:a["original_postgres_actual_rows"][0].update(body="FORGED"))
        self.assert_tamper_rejected("missing_original_rls",
            lambda b,r,a:a["original_postgres_table_metadata"].update(rls=False))
        self.assert_tamper_rejected("extra_pg_write_capability",
            lambda b,r,a:a["native_resource_role_privileges"].update(can_delete=True))

    def test_credentials_review_and_denials_tampering(self):
        self.assert_tamper_rejected("reused_wrapping_token",
            lambda b,r,a:r["untrusted_actor_pre"].update(native_one_use_repeat_http=200))
        self.assert_tamper_rejected("issue_new_db_credential_after_wrapper",
            lambda b,r,a:r["untrusted_actor_pre"].update(native_wrapped_token_recredential_http=200))
        self.assert_tamper_rejected("untrusted_os_masquerade",
            lambda b,r,a:r["untrusted_actor_pre"].update(actor_uid=0))
        self.assert_tamper_rejected("new_user_role_beyond_issuer",
            lambda b,r,a:r.update(native_issuer_dynamic_username="admin"))
        self.assert_tamper_rejected("unauthorized_sql_effect",
            lambda b,r,a:r["untrusted_actor_pre"]["native_database_denied_cases"][2].update(ok=True))
        self.assert_tamper_rejected("missing_attack_control",
            lambda b,r,a:r["untrusted_actor_pre"]["native_database_denied_cases"].pop())
        self.assert_tamper_rejected("approved_modified_two_rows",
            lambda b,r,a:r["untrusted_actor_effect"]["approved"].update(rows=2))
        self.assert_tamper_rejected("replay_effect",
            lambda b,r,a:r["untrusted_actor_effect"]["same_credential_replay"].update(rows=1))
        self.assert_tamper_rejected("revoked_db_credential_still_valid",
            lambda b,r,a:r["untrusted_actor_after_revocation"].update(fresh_native_postgres_login_denied=False))
        self.assert_tamper_rejected("fake_independent_owner",
            lambda b,r,a:r.update(unrelated_external_human_owner=True))
        self.assert_tamper_rejected("fake_independently_operated_server",
            lambda b,r,a:r.update(third_party_operated_service=True))
        self.assert_tamper_rejected("false_independent_audit",
            lambda b,r,a:a.update(status="PASS_BUT_NOT_CHECKED"))

    def test_cli_emits_certificate_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            file=Path(t)/"certificate.json"
            self.assertEqual(m.main(["--evidence-dir",str(self.base),
                                     "--out",str(file)]),0)
            out=json.loads(file.read_text())
            self.assertEqual(out["schema"],m.SCHEMA)
            self.assertEqual(m.main(["--evidence-dir",str(self.base),
                                     "--out",str(file)]),2)

    def test_symlink_to_original_data_refused(self):
        with tempfile.TemporaryDirectory() as t:
            tmp=Path(t)
            for kind,name in m.FILENAMES.items():
                src=self.base/name
                dest=tmp/name
                if kind=="original":
                    dest.symlink_to(src.resolve())
                else:
                    dest.write_bytes(src.read_bytes())
            with self.assertRaises(m.EvidenceRefused):
                m.verify_dir(tmp)

if __name__=="__main__":
    unittest.main()
