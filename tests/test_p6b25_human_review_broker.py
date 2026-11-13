"""B25 adversarial tests; no live owner GitHub write can occur in unit tests.

A simulated GitHub review history is only a DEV fixture. The real B25
positive gate MUST be tested after the owner manually clicks Review
deployments. Missing approval is deliberately treated as not confirmed.
"""
from __future__ import annotations
import base64,copy,hashlib,json,os,tempfile,unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
import risu_mcp_human_review_broker as m

PRE="RISU B25 human-reviewed one-file fixture\nstate=AWAITING_GITHUB_ENVIRONMENT_REVIEW\nscope=EXACT_ONE_FILE\n"
POST="RISU B25 human-reviewed one-file fixture\nstate=GITHUB_HUMAN_APPROVED_BROKER_WRITE\nscope=EXACT_ONE_FILE\n"

def grant():
    return {
      "schema":m.SCHEMA,
      "proposal_status":"UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT",
      "authorization_type":"GITHUB_REQUIRED_REVIEWER_DIRECT_HUMAN_APPROVAL",
      "review_environment":m.ENVIRONMENT,
      "expected_reviewer_login":m.REVIEWER,
      "owner_org":m.OWNER,"owner_org_id":m.ORG_ID,
      "owner_repository":m.OWNER+"/"+m.REPO,
      "owner_repository_id":m.REPO_ID,
      "approved_branch":m.BRANCH,
      "resource_path":m.PATH,
      "expected_prior_git_blob":"c84690efad2ac44fa96605a4d1b7c34efbff52de",
      "expected_prior_content_sha256":m.digest(PRE.encode()),
      "desired_content":POST,"desired_content_sha256":m.digest(POST.encode()),
      "commit_message":"B25: human-reviewed one-file credential-isolated broker write",
      "run_nonce":"67b1832d0a4af297a5df18e732ee0fa6fff4d409aff4655ed63ace9cba875a8e",
      "publisher_sha256":"a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b",
      "broker_method":"SINGLE_EXACT_GITHUB_CONTENTS_PUT_NO_UNTRUSTED_CODE_WITH_WRITE_TOKEN",
      "requested_github_api_method":"PUT",
      "requested_git_path":"repos/"+m.OWNER+"/"+m.REPO+"/contents/"+m.PATH,
      "review_expiration_minutes":30,
      "limits":"Not approved until real environment review on exact run"
    }

def run():
    return {"id":81231,"event":"push","run_attempt":1,
            "head_branch":m.BRANCH,"path":m.WORKFLOW,
            "created_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
            "head_sha":"a"*40}

def approved(reviewer=m.REVIEWER,environment=m.ENVIRONMENT,state="approved"):
    return [{"user":{"login":reviewer,"id":87353042,"type":"User"},
             "environments":[{"name":environment}],"state":state}]

class B25NoConsentAndExactScope(unittest.TestCase):
    def setUp(self):
        self.policy=grant()
    def rejects_policy(self):
        with self.assertRaises(m.PolicyDenied):
            m.verify_policy(self.policy)
    def test_frozen_valid_policy_is_only_unapproved_request(self):
        self.assertEqual(m.verify_policy(self.policy)["proposal_status"],
            "UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT")
    def test_no_reviews_fails(self):
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),[])
    def test_push_event_with_no_review_is_not_human_consent(self):
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),[{"state":"pending"}])
    def test_only_named_human_reviewer_for_exact_environment(self):
        ok=m.validate_actual_review(run(),approved())
        self.assertEqual(ok["actual_github_review_state"],"approved")
    def test_wrong_human_reviewer_denied(self):
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),approved("other"))
    def test_approver_bot_denied(self):
        r=approved()
        r[0]["user"]["type"]="Bot"
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),r)
    def test_review_for_other_environment_denied(self):
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),approved(environment="other"))
    def test_rejected_approval_overrides_approved(self):
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(run(),approved()+approved(state="rejected"))
    def test_rerun_attempt_cannot_reuse_prior_human_review(self):
        r=run();r["run_attempt"]=2
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(r,approved())
    def test_event_not_push_is_denied(self):
        r=run();r["event"]="workflow_dispatch"
        with self.assertRaises(m.PolicyDenied):
            m.validate_actual_review(r,approved())
    def test_workflow_and_branch_must_match(self):
        for field,value in [("head_branch","main"),("path","other.yml")]:
            r=run();r[field]=value
            with self.assertRaises(m.PolicyDenied):
                m.validate_actual_review(r,approved())
    def test_wrong_org_identity_denied(self):
        self.policy["owner_org_id"]+=1;self.rejects_policy()
    def test_wrong_repository_id_denied(self):
        self.policy["owner_repository_id"]+=1;self.rejects_policy()
    def test_wrong_resource_path_denied(self):
        self.policy["resource_path"]="README.md";self.rejects_policy()
    def test_wrong_branch_denied(self):
        self.policy["approved_branch"]="main";self.rejects_policy()
    def test_different_put_endpoint_denied(self):
        self.policy["requested_git_path"]+=".attacker";self.rejects_policy()
    def test_arbitrary_writer_tool_denied(self):
        self.policy["broker_method"]="RUN_ANY_GITHUB_MCP_TOOL";self.rejects_policy()
    def test_malicious_post_bytes_denied(self):
        self.policy["desired_content"]="unapproved content";self.rejects_policy()
    def test_extra_scope_fields_denied(self):
        self.policy["extra_permission"]="write all files";self.rejects_policy()
    def test_missing_approval_policy_denied(self):
        self.policy["proposal_status"]="APPROVED";self.rejects_policy()
    def test_expanded_commit_message_denied(self):
        self.policy["commit_message"]="modify every file";self.rejects_policy()

@unittest.skipUnless(hasattr(os,"geteuid"),"Atomic POSIX nonce ledger only")
class B25TrustedBrokerSimulation(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.policy=grant()
        self.file=self.root/"proposal.json"
        self.file.write_text(json.dumps(self.policy))
        raw=self.file.read_bytes()
        fixture_blob=__import__("hashlib").sha1(
            b"blob "+str(len(raw)).encode()+bytes([0])+raw).hexdigest()
        pinned=patch.object(m,"EXPECTED_OWNER_PROPOSAL_GIT_BLOB",fixture_blob)
        pinned.start()
        self.addCleanup(pinned.stop)
        self.ledger=self.root/"ledger";self.ledger.mkdir(mode=0o700)
        self.url="https://api.github.com/repos/"+m.OWNER+"/"+m.REPO
        self.calls=[]
        self.commit="e"*40
    def api(self,token,route,method="GET",body=None):
        self.calls.append((method,route,body))
        if route==self.url:
            return {"id":m.REPO_ID,"owner":{"id":m.ORG_ID}}
        if route.endswith("/actions/runs/81231/approvals"):
            return approved()
        if route.endswith("/actions/runs/81231"):
            return {**run(),"head_sha":"a"*40}
        if route.endswith("/contents/"+m.PATH+"?ref="+m.BRANCH):
            return {"type":"file","sha":self.policy["expected_prior_git_blob"],
                    "content":base64.b64encode(PRE.encode()).decode()}
        if route.endswith("/contents/"+m.PATH) and method=="PUT":
            self.assertEqual(body["sha"],self.policy["expected_prior_git_blob"])
            self.assertEqual(base64.b64decode(body["content"]),POST.encode())
            return {"commit":{"sha":self.commit},"content":{"sha":"f"*40}}
        if route.endswith("/contents/"+m.PATH+"?ref="+self.commit):
            return {"type":"file","sha":"f"*40,
                    "content":base64.b64encode(POST.encode()).decode()}
        if route.endswith("/commits/"+self.commit):
            return {"files":[{"filename":m.PATH,"sha":"f"*40,"status":"modified"}]}
        raise RuntimeError("unexpected external API route "+route)
    def invoke(self,approve=True,child=False):
        def variant(token,route,method="GET",body=None):
            if route.endswith("/approvals") and not approve:return []
            return self.api(token,route,method,body)
        with patch.object(m,"api",side_effect=variant):
            return m.execute(self.file,self.ledger,self.root/"evidence.json",
                "81231","a"*40,"unit-test-github-token-never-network",
                child_probe=child)
    def test_mock_verified_review_one_exact_put_and_commit(self):
        response=self.invoke()
        self.assertEqual(response["actual_github_writes"],1)
        writes=[z for z in self.calls if z[0]=="PUT"]
        self.assertEqual(len(writes),1)
        self.assertTrue(writes[0][1].endswith("/contents/"+m.PATH))
    def test_github_real_newline_folded_pre_and_post_commit_positive(self):
        """Regression: GitHub's actual Contents API uses multiline base64."""
        original=self.api
        def real_transport(token,route,method="GET",body=None):
            response=original(token,route,method,body)
            if method=="GET" and "/contents/"+m.PATH+"?ref=" in route:
                data=dict(response)
                raw=response["content"]
                data["content"]="\\n".join(raw[i:i+60] for i in range(0,len(raw),60))+"\\n"
                return data
            return response
        with patch.object(m,"api",side_effect=real_transport):
            result=m.execute(self.file,self.ledger,self.root/"evidence.json",
                "81231","a"*40,"unit-test-real-github-folded-content",
                child_probe=False)
        self.assertEqual(result["actual_github_writes"],1)
        self.assertEqual(sum(method=="PUT" for method,_,_ in self.calls),1)

    def test_without_human_review_deny_before_any_remote_write(self):
        with self.assertRaises(m.PolicyDenied):self.invoke(approve=False)
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))
        response=json.loads((self.root/"evidence.json").read_text())
        self.assertEqual(response["actual_github_writes"],0)
    def test_actual_one_time_nonce_consumed_before_write(self):
        self.invoke()
        self.assertTrue((self.ledger/self.policy["run_nonce"]).is_file())
    def test_stale_source_blob_deny_before_put(self):
        def fail_api(token,route,method="GET",body=None):
            r=self.api(token,route,method,body)
            if route.endswith("/contents/"+m.PATH+"?ref="+m.BRANCH):
                r["sha"]="a"*40
            return r
        with patch.object(m,"api",side_effect=fail_api):
            with self.assertRaises(m.PolicyDenied):
                m.execute(self.file,self.ledger,self.root/"evidence.json",
                   "81231","a"*40,"mock",child_probe=False)
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))
    def test_private_ledger_mandatory(self):
        self.ledger.chmod(0o777)
        with self.assertRaises(m.PolicyDenied):self.invoke()
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))
    def test_untrusted_child_os_proof_must_pass_before_write(self):
        with patch.object(m,"_untrusted_child_os_proof",
                          side_effect=m.PolicyDenied("AGENT_REACHES_TOKEN")),\
             patch.object(m,"api",side_effect=self.api):
            with self.assertRaises(m.PolicyDenied):
                m.execute(self.file,self.ledger,self.root/"evidence.json",
                   "81231","a"*40,"mock",child_probe=True)
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))
    def test_stale_historic_approval_not_accepted_after_30_min(self):
        def old_run(token,route,method="GET",body=None):
            if route.endswith("/actions/runs/81231"):
                r=run()
                r["created_at"]=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat(
                    timespec="seconds").replace("+00:00","Z")
                return r
            return self.api(token,route,method,body)
        with patch.object(m,"api",side_effect=old_run):
            with self.assertRaises(m.PolicyDenied):
                m.execute(self.file,self.ledger,self.root/"evidence.json",
                    "81231","a"*40,"unit-test-expired-github-review",child_probe=False)
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))

    def test_rerun_is_never_a_fresh_human_approval(self):
        def replay_run(token,route,method="GET",body=None):
            if route.endswith("/actions/runs/81231"):
                return {**run(),"run_attempt":2,"head_sha":"a"*40}
            return self.api(token,route,method,body)
        with patch.object(m,"api",side_effect=replay_run):
            with self.assertRaises(m.PolicyDenied):
                m.execute(self.file,self.ledger,self.root/"evidence.json",
                    "81231","a"*40,"unit-test-reused-github-approval",child_probe=False)
        self.assertFalse(any(z[0]=="PUT" for z in self.calls))

class B25GitHubContentsBase64Transport(unittest.TestCase):
    def test_real_api_linefolds_are_accepted_by_writer_and_independent_auditor(self):
        import importlib.util
        path=Path(__file__).resolve().parents[1]/"benchmarks/p6b25/independent_human_review_audit.py"
        spec=importlib.util.spec_from_file_location("b25_independent_transport_test",path)
        independent=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(independent)
        payload=PRE.encode()
        canon=base64.b64encode(payload).decode("ascii")
        folded="\\n".join(canon[i:i+60] for i in range(0,len(canon),60))+"\\n"
        crlf=folded.replace("\\n","\\r\\n")
        for example in (canon,folded,crlf):
            self.assertEqual(m.decode_github_contents_base64(example),payload)
            self.assertEqual(independent.decode_github_contents_base64(example),payload)

    def test_non_github_whitespace_and_malformed_base64_are_denied(self):
        import importlib.util
        path=Path(__file__).resolve().parents[1]/"benchmarks/p6b25/independent_human_review_audit.py"
        spec=importlib.util.spec_from_file_location("b25_independent_strict_test",path)
        independent=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(independent)
        canonical=base64.b64encode(PRE.encode()).decode()
        variants=("",canonical[:7]+" "+canonical[7:],
                  canonical[:7]+"\\t"+canonical[7:],
                  canonical[:7]+"#"+canonical[7:],
                  canonical[:-1],canonical+"=",None,42)
        for malformed in variants:
            with self.subTest(sample=str(malformed)[:12]):
                with self.assertRaises(m.PolicyDenied):
                    m.decode_github_contents_base64(malformed)
                with self.assertRaises(ValueError):
                    independent.decode_github_contents_base64(malformed)

if __name__=="__main__":unittest.main()
