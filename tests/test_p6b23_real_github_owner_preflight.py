"""B23 negative and positive *mocked* trust/API tests.

These are strictly unit tests for the already source-native verified
repository-owner grant gate. They DO NOT replace the real GitHub OIDC
signature and original GitHub MCP tool execution demonstrated in owner
repo CI run 43336892730 and independent read-only run 43337547529.
"""
from __future__ import annotations
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import risu_mcp_github_owner as m


@unittest.skipUnless(os.name=="posix","GitHub-owner one-time nonce reservation currently POSIX")
class TestB23RepoOwnerPreflight(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.p=Path(t.name)
        self.ledger=self.p/"ledger"
        self.ledger.mkdir(mode=0o700)
        self.pre=b"RISU B23 GitHub-owner resource fixture\nstate=UNAPPROVED\npurpose=bounded consent gate research\n"
        self.post="RISU B23 GitHub-owner resource fixture\nstate=APPROVED_BY_REPOSITORY_ADMIN\npurpose=bounded consent gate research\n"
        self.grant={
            "schema":m.SCHEMA,
            "grant_origin":"AUTHENTICATED_GITHUB_ADMIN_ACCOUNT_DELEGATION",
            "owner_repository":m.ISSUER_REPO,
            "owner_repository_id":m.ISSUER_REPO_ID,
            "organization_id":m.ORG_ID,
            "actor_account":m.OWNER_ACCOUNT,
            "approved_branch":m.ISSUER_BRANCH,
            "resource_path":m.EXACT_PATH,
            "tool":"create_or_update_file",
            "approved_action":"REPLACE",
            "pre_git_blob_sha1":"de0b72cd177d6f1bb7153a9925bb3a5bf285d521",
            "pre_raw_sha256":m.digest(self.pre),
            "post_raw_sha256":m.digest(self.post.encode()),
            "original_github_mcp_release":"v2.1.0",
            "original_github_mcp_linux_x86_64_archive_sha256":m.digest(b"mock-binary"),
            "validity_utc_start":"2026-11-12T00:00:00Z",
            "validity_utc_end":"2099-01-01T00:00:00Z",
            "nonce":"e"*64,
            "requested_effect":"OWNER_REPOSITORY_FILE_CONTENT_REPLACEMENT",
            "approved_tool_arguments":{
                "owner":"risu-research","repo":"risu-verify",
                "branch":m.ISSUER_BRANCH,"path":m.EXACT_PATH,
                "message":"B23 authorized bounded owner repository resource update",
                "content":self.post,
                "sha":"de0b72cd177d6f1bb7153a9925bb3a5bf285d521"},
            "owner_approval_statement":"Mock separate github owner test only",
            "limit":"No human user consent simulated here."}
        self.path=self.p/"grant.json"
        self.save()
        self.release=self.p/"official-server.tar.gz"
        self.release.write_bytes(b"mock-binary")
        self.api_data={
            "https://api.github.com/repos/"+m.ISSUER_REPO:{
                "id":m.ISSUER_REPO_ID,"owner":{"id":m.ORG_ID},"private":False},
            "https://api.github.com/repos/"+m.ISSUER_REPO+
                "/collaborators/"+m.OWNER_ACCOUNT+"/permission":{"permission":"admin"},
            "https://api.github.com/repos/"+m.ISSUER_REPO+"/actions/runs/43336892730":{
                "actor":{"login":m.OWNER_ACCOUNT},"head_branch":m.ISSUER_BRANCH,
                "path":".github/workflows/p6b23-owner-issued-github-mcp.yml",
                "event":"push"},
            "https://api.github.com/repos/"+m.ISSUER_REPO+"/branches/"+m.ISSUER_BRANCH:{
                "commit":{"sha":"0"*40}},
            "https://api.github.com/repos/"+m.ISSUER_REPO+"/contents/"+m.EXACT_PATH+
              "?ref="+m.ISSUER_BRANCH:{
                "type":"file","sha":self.grant["pre_git_blob_sha1"],
                "content":base64.b64encode(self.pre).decode()}
        }

    def save(self):
        self.path.write_text(json.dumps(self.grant,indent=2)+"\n")

    def check(self):
        with patch.object(m,"EXPECTED_RELEASE_TAR_SHA",m.digest(b"mock-binary")),\
             patch.object(m,"gh_attested",return_value={
                "owner_grant_sha256":m.digest(self.path.read_bytes()),
                "verified_count":1}),\
             patch.object(m,"github_api",side_effect=lambda url,token:self.api_data[url]):
            return m.preflight(self.path,self.release,"43336892730",
                m.OWNER_ACCOUNT,
                "DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT",
                "test-token-authenticated-by-original-GitHub-CI",self.ledger)

    def rejects(self):
        with self.assertRaises((m.Refused,ValueError,FileExistsError,KeyError)):
            self.check()

    def test_exact_real_world_schema_with_mock_external_verifiers_accepts(self):
        self.assertEqual(self.check()["verified_admin_permission"],"admin")

    def test_wrong_repository_owner_id_fails_closed(self):
        self.grant["organization_id"]=0
        self.save()
        self.rejects()

    def test_wrong_repository_id_fails_closed(self):
        self.grant["owner_repository_id"]=0
        self.save()
        self.rejects()

    def test_scope_expansion_to_readme_fails_closed(self):
        self.grant["resource_path"]="README.md"
        self.save()
        self.rejects()

    def test_other_git_branch_fails_closed(self):
        self.grant["approved_branch"]="main"
        self.save()
        self.rejects()

    def test_owner_issuer_does_not_have_admin_on_github_platform(self):
        u="https://api.github.com/repos/"+m.ISSUER_REPO+"/collaborators/"+m.OWNER_ACCOUNT+"/permission"
        self.api_data[u]={"permission":"write"}
        self.rejects()

    def test_oidc_signer_workflow_evidence_is_required(self):
        with patch.object(m,"gh_attested",side_effect=m.Refused("NO_SIGNATURE")),\
             patch.object(m,"EXPECTED_RELEASE_TAR_SHA",m.digest(b"mock-binary")):
            with self.assertRaises(m.Refused):m.preflight(
                self.path,self.release,"43336892730",m.OWNER_ACCOUNT,
                "DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT",
                "mock",self.ledger)

    def test_actor_account_not_same_actual_github_admin_run(self):
        u="https://api.github.com/repos/"+m.ISSUER_REPO+"/actions/runs/43336892730"
        self.api_data[u]["actor"]["login"]="unknown-user"
        self.rejects()

    def test_mutated_original_source_release_digest_rejected(self):
        self.release.write_bytes(b"untrusted-release")
        self.rejects()

    def test_server_current_git_blob_changed_rejected(self):
        u="https://api.github.com/repos/"+m.ISSUER_REPO+"/contents/"+m.EXACT_PATH+"?ref="+m.ISSUER_BRANCH
        self.api_data[u]["sha"]="a"*40
        self.rejects()

    def test_actual_remote_resource_bytes_changed_rejected(self):
        u="https://api.github.com/repos/"+m.ISSUER_REPO+"/contents/"+m.EXACT_PATH+"?ref="+m.ISSUER_BRANCH
        self.api_data[u]["content"]=base64.b64encode(b"not owner prestate").decode()
        self.rejects()

    def test_message_content_altered_after_approval_rejected(self):
        self.grant["approved_tool_arguments"]["content"]="attacker content"
        self.save()
        self.rejects()

    def test_native_write_sha_not_equal_predecessor_blob_rejected(self):
        self.grant["approved_tool_arguments"]["sha"]="b"*40
        self.save()
        self.rejects()

    def test_grant_expiry_rejected(self):
        self.grant["validity_utc_end"]="2026-11-12T00:01:00Z"
        self.save()
        self.rejects()

    def test_manual_approval_cannot_be_claimed_from_push_event(self):
        with patch.object(m,"EXPECTED_RELEASE_TAR_SHA",m.digest(b"mock-binary")),\
             patch.object(m,"gh_attested",return_value={"owner_grant_sha256":"a"*64}),\
             patch.object(m,"github_api",side_effect=lambda url,token:self.api_data[url]):
            with self.assertRaises(m.Refused):
                m.preflight(self.path,self.release,"43336892730",m.OWNER_ACCOUNT,
                    "DIRECT_AUTHENTICATED_OWNER_ACCOUNT_DISPATCH","mock",self.ledger)

    def test_local_atomic_nonce_cannot_run_twice_under_same_prestate(self):
        self.check()
        with self.assertRaises(m.Refused) as caught:
            self.check()
        self.assertEqual(str(caught.exception),"OWNER_GRANT_ALREADY_CONSUMED")

    def test_local_atomic_nonce_remains_replay_even_when_remote_content_has_changed(self):
        self.check()
        u="https://api.github.com/repos/"+m.ISSUER_REPO+"/contents/"+m.EXACT_PATH+"?ref="+m.ISSUER_BRANCH
        self.api_data[u]["sha"]="f"*40
        with self.assertRaises(m.Refused) as caught:
            self.check()
        self.assertEqual(str(caught.exception),"OWNER_GRANT_ALREADY_CONSUMED")

    def test_no_trust_in_unowned_or_world_writable_nonce_ledger(self):
        self.ledger.chmod(0o777)
        self.rejects()

    def test_preflight_is_not_a_global_org_user_consent_proof(self):
        self.assertEqual(self.grant["grant_origin"],
                         "AUTHENTICATED_GITHUB_ADMIN_ACCOUNT_DELEGATION")


if __name__=="__main__":
    unittest.main()
