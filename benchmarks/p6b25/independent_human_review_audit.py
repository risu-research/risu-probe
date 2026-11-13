"""B25 independent read-only audit of a human-reviewed trusted one-file broker.

This auditor uses neither RISU writer module nor any privileged token.
It independently reads GitHub's immutable source and resulting commit,
actual Actions approval history, trusted owner workflow job identity,
and one-file result. No human approval may be inferred from a plain
push, a CI-generated OIDC attestation, or a caller-provided JSON field.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,urllib.request
from pathlib import Path

REPO="risu-research/risu-verify"
REPO_ID=1350184511
ORG_ID=316025762
BRANCH="qualification/p6b25-real-review-credential-isolation-20261112"
WORKFLOW=".github/workflows/p6b25-owner-human-reviewed-broker.yml"
ENV="risu-b25-human-owner-approval"
REVIEWER="moon10021017"
FILE="benchmarks/p6b25/owner_only_resource.txt"
PROPOSAL_BLOB="c66e2630c0c4edf15ee467fb758f601de6370ede"

def demand(x,msg):
    if not x:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def load(f):return json.loads(Path(f).read_text())
def api(token,url):
    assert url.startswith("https://api.github.com/repos/"+REPO)
    r=urllib.request.Request(url,headers={
        "Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28","User-Agent":"RISU-B25-readonly-independent-human-review-audit"})
    with urllib.request.urlopen(r,timeout=35) as reply:
        demand(reply.status==200,"GitHub independent GET not successful")
        return json.loads(reply.read(999999))
def review_state(run,records):
    demand(run.get("event")=="push" and run.get("run_attempt")==1 and
           run.get("head_branch")==BRANCH and run.get("path")==WORKFLOW,
           "Original reviewed run identity differs from actual GitHub event")
    matched=[]
    for r in records:
        u=r.get("user") or {}
        if (u.get("login")==REVIEWER and u.get("type")=="User" and
            any(x.get("name")==ENV for x in r.get("environments",[]))):
            matched.append(r.get("state"))
    demand("approved" in matched and "rejected" not in matched,
           "No independent GitHub required human reviewer approval evidence")
    return True

def audit(source,proposal,token):
    result=load(source)
    proposal_bytes=Path(proposal).read_bytes()
    git_hash=hashlib.sha1(b"blob "+str(len(proposal_bytes)).encode()+bytes([0])+proposal_bytes).hexdigest()
    demand(git_hash==PROPOSAL_BLOB,"Owner policy not the original pinned exact artifact")
    p=json.loads(proposal_bytes)
    demand(p["proposal_status"]=="UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT" and
           p["owner_repository_id"]==REPO_ID and p["owner_org_id"]==ORG_ID and
           p["resource_path"]==FILE and p["review_environment"]==ENV,
           "Owner proposal unauthorized scope")
    demand(result["status"]=="DIRECT_HUMAN_REVIEWED_EXACT_ONE_FILE_WRITE_VERIFIED" and
           result["actual_github_writes"]==1 and result["actual_changed_files"]==1 and
           result["untrusted_mcp_code_executed_with_write_token"] is False and
           result["intra_broker_os_uid_token_separation"]["token_in_child_env"] is False and
           result["intra_broker_os_uid_token_separation"]["parent_privileged_env_readable"] is False,
           "Original trusted broker execution results invalid")
    root="https://api.github.com/repos/"+REPO
    repo=api(token,root)
    demand(repo["id"]==REPO_ID and repo["owner"]["id"]==ORG_ID,
           "GitHub actual owner repository identity changed")
    rid=result["review"]["source_run_id"]
    run=api(token,root+"/actions/runs/"+str(rid))
    approvals=api(token,root+"/actions/runs/"+str(rid)+"/approvals")
    demand(review_state(run,approvals) and
           result["review"]["reviewer_login"]==REVIEWER and
           result["review"]["reviewed_environment"]==ENV and
           result["review"]["run_attempt"]==1,
           "Original write not bound to the same named human reviewer")
    pre=api(token,root+"/git/blobs/"+p["expected_prior_git_blob"])
    before=base64.b64decode(pre["content"])
    demand(sha(before)==p["expected_prior_content_sha256"] and
           pre["sha"]==p["expected_prior_git_blob"],
           "Immutable actual original GitHub file bytes disagree with owner")
    after_id=result["new_original_commit_sha"]
    commit=api(token,root+"/commits/"+after_id)
    demand(commit["sha"]==after_id and
           len(commit["files"])==1 and
           commit["files"][0]["filename"]==FILE and
           commit["files"][0]["status"]=="modified",
           "Actual GitHub commit did not restrict change to exact file")
    after_file=api(token,root+"/contents/"+FILE+"?ref="+after_id)
    after=base64.b64decode(after_file["content"])
    demand(sha(after)==p["desired_content_sha256"]==
           result["real_github_post_sha256"] and
           after==p["desired_content"].encode() and
           after_file["sha"]==result["after_git_blob"]==
           commit["files"][0]["sha"],
           "Independent actual GitHub file after-state violates signed scope")
    return {
       "schema":"risu-b25-independent-readonly-human-review-owner-resource-audit-v1",
       "actual_github_human_reviewer_account":REVIEWER,
       "actual_review":True,"approved_environment":ENV,
       "reviewed_run_id":rid,
       "owner_repository":REPO,"owner_repo_id":REPO_ID,
       "immutable_original_git_blob":pre["sha"],
       "actual_after_git_blob":after_file["sha"],
       "actual_github_remote_commit":after_id,
       "git_diff_exactly_one_owner_approved_file":True,
       "agent_can_read_trusted_job_token":False,
       "writer_posix_untrusted_child_private_token_exposure":False,
       "trusted_credential_isolation_class":"GITHUB_JOB_SEPARATE_TOKEN_AND_POSIX_CHILD_NOT_GITHUB_FILE_PATH_SCOPED",
       "human_approval_source":"GITHUB_ACTIONS_RUN_SPECIFIC_DEPLOYMENT_APPROVALS_API",
       "external_independent_third_party_owner":"NOT_TESTED",
       "upstream_external_bug_discoveries":0
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--broker-report",type=Path,required=True)
    p.add_argument("--proposal",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    token=os.getenv("GH_TOKEN")
    demand(type(token) is str and len(token)>10,"READ_ONLY_AUDITOR_TOKEN_MISSING")
    result=audit(a.broker_report,a.proposal,token)
    with a.out.open("x") as f:json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print("B25_INDEPENDENT_REAL_HUMAN_REVIEW_AND_ONE_FILE_GITHUB_EFFECT_AUDITED",
          result["actual_github_remote_commit"])

if __name__=="__main__":main()
