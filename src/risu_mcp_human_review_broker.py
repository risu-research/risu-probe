"""B25: GitHub human-reviewed owner policy and a single-operation credential broker.

The GitHub required-reviewer APPROVAL HISTORY, for THIS workflow run and
named environment, is mandatory. An ordinary push or OIDC attestation is
never treated as direct human approval.

Trust boundary:
  - proposal + agent job have contents:read only
  - protected environment waits for actual named reviewer
  - privileged trusted job alone obtains short-lived contents:write GITHUB_TOKEN
  - trusted writer implements exactly ONE GitHub Contents PUT for ONE target;
    no arbitrary MCP server, agent source or user-controlled Python code runs
    with its token
  - user-supplied repo/path/branch/bytes are checked against frozen contract
  - source integrity checked by fixed GitHub source commit & SHA before use
  - independent read-only job audits original immutable Git commit and approval.

The single-repository GITHUB_TOKEN is *repository-scoped*, not path-scoped.
It is trusted-code confinement, NOT a cryptographic file-path restriction,
and an adversary able to replace trusted job code could bypass it.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime,timezone,timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import urllib.error

OWNER="risu-research"
REPO="risu-verify"
REPO_ID=1350184511
ORG_ID=316025762
BRANCH="qualification/p6b25-real-review-credential-isolation-20261112"
WORKFLOW=".github/workflows/p6b25-owner-human-reviewed-broker.yml"
ENVIRONMENT="risu-b25-human-owner-approval"
REVIEWER="moon10021017"
PATH="benchmarks/p6b25/owner_only_resource.txt"
SCHEMA="risu-b25-single-repo-file-owner-review-request-v1"
EXPECTED_OWNER_PROPOSAL_GIT_BLOB="c66e2630c0c4edf15ee467fb758f601de6370ede"
HEX40=re.compile(r"[a-f0-9]{40}\Z")
HEX64=re.compile(r"[a-f0-9]{64}\Z")

class PolicyDenied(Exception):pass

def enforce(condition,reason):
    if not condition:raise PolicyDenied(reason)

def digest(b):return hashlib.sha256(b).hexdigest()

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode()

def strict_json(path):
    f=Path(path)
    enforce(f.is_file() and not f.is_symlink() and 0<f.stat().st_size<=16384,
            "MISSING_OR_UNSAFE_OWNER_PROPOSAL")
    def unique(parts):
        d={}
        for k,v in parts:
            if k in d:raise PolicyDenied("AMBIGUOUS_DUPLICATE_OWNER_POLICY_KEY")
            d[k]=v
        return d
    return json.loads(f.read_text("utf-8"),object_pairs_hook=unique)

def api(token,route,method="GET",body=None):
    enforce(type(token) is str and len(token)>10,"NO_PRIVILEGED_REVIEW_BROKER_TOKEN")
    enforce(route.startswith("https://api.github.com/repos/"+OWNER+"/"+REPO) and
        not route.startswith("https://api.github.com/repos/"+OWNER+"/"+REPO+"-"),
        "GITHUB_API_NOT_THE_EXACT_OWNER_REPOSITORY")
    request=urllib.request.Request(route,method=method,
         data=canonical(body) if body is not None else None,
         headers={
           "Authorization":"Bearer "+token,
           "Accept":"application/vnd.github+json",
           "X-GitHub-Api-Version":"2022-11-28",
           "Content-Type":"application/json",
           "User-Agent":"RISU-B25-exact-once-human-owner-broker"})
    with urllib.request.urlopen(request,timeout=35) as reply:
        enforce(reply.status in (200,201),"REJECTED_PLATFORM_RESPONSE")
        raw=reply.read(1048576)
        enforce(len(raw)<1048576,"UNBOUNDED_GITHUB_RESPONSE")
        return json.loads(raw)

def verify_policy(p):
    enforce(type(p) is dict and set(p)=={
        "schema","proposal_status","authorization_type","review_environment",
        "expected_reviewer_login","owner_org","owner_org_id",
        "owner_repository","owner_repository_id","approved_branch",
        "resource_path","expected_prior_git_blob","expected_prior_content_sha256",
        "desired_content","desired_content_sha256","commit_message",
        "run_nonce","publisher_sha256","broker_method",
        "requested_github_api_method","requested_git_path",
        "review_expiration_minutes","limits"},
        "UNKNOWN_OR_MISSING_POLICY_FIELD")
    enforce(p["schema"]==SCHEMA and
        p["proposal_status"]=="UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT" and
        p["authorization_type"]=="GITHUB_REQUIRED_REVIEWER_DIRECT_HUMAN_APPROVAL" and
        p["review_environment"]==ENVIRONMENT and
        p["expected_reviewer_login"]==REVIEWER and
        p["owner_org"]==OWNER and p["owner_org_id"]==ORG_ID and
        p["owner_repository"]==OWNER+"/"+REPO and
        p["owner_repository_id"]==REPO_ID and
        p["approved_branch"]==BRANCH and p["resource_path"]==PATH and
        p["broker_method"]=="SINGLE_EXACT_GITHUB_CONTENTS_PUT_NO_UNTRUSTED_CODE_WITH_WRITE_TOKEN" and
        p["requested_github_api_method"]=="PUT" and
        p["requested_git_path"]=="repos/"+OWNER+"/"+REPO+"/contents/"+PATH and
        p["review_expiration_minutes"]==30,
        "PROPOSED_OWNER_SCOPE_EXCEEDS_LOCKED_ALLOWED_PROFILE")
    enforce(type(p["expected_prior_git_blob"]) is str and
        bool(HEX40.fullmatch(p["expected_prior_git_blob"])) and
        all(type(p[x]) is str and bool(HEX64.fullmatch(p[x])) for x in (
          "expected_prior_content_sha256","desired_content_sha256","run_nonce")),
        "MALFORMED_EXACT_OWNER_RESOURCE_PRECONDITION")
    enforce(type(p["desired_content"]) is str and
        0<len(p["desired_content"].encode("utf-8"))<=4096 and
        digest(p["desired_content"].encode())==p["desired_content_sha256"] and
        type(p["commit_message"]) is str and
        p["commit_message"]=="B25: human-reviewed one-file credential-isolated broker write",
        "UNAPPROVED_CONTENT_OR_MESSAGE")
    return p

def validate_actual_review(run,approvals,reviewer=REVIEWER,env=ENVIRONMENT):
    """Fail-closed: GitHub's actual review history, not workflow args/self-claims.

    Re-run attempt>1 is rejected because original approval is tied to run,
    not to a fresh evaluation of a new execution attempt.
    """
    enforce(type(run) is dict and
        run.get("event")=="push" and
        run.get("head_branch")==BRANCH and
        run.get("path")==WORKFLOW and
        run.get("run_attempt")==1 and
        type(run.get("id")) is int,
        "WRONG_OR_RERUN_GITHUB_WORKFLOW_EVENT")
    enforce(type(approvals) is list and 0<len(approvals)<=100,
        "NO_REAL_GITHUB_REQUIRED_REVIEWER_APPROVAL")
    matched=[]
    for approval in approvals:
        if type(approval) is not dict:continue
        user=approval.get("user") or {}
        if (type(user) is dict and user.get("login")==reviewer and
            user.get("type")=="User" and
            type(approval.get("environments")) is list and
            any(type(z) is dict and z.get("name")==env
                for z in approval["environments"])):
            matched.append(approval.get("state"))
    enforce("approved" in matched and "rejected" not in matched,
        "NAMED_HUMAN_REVIEWER_HAS_NOT_APPROVED_THIS_ENVIRONMENT_RUN")
    return {"reviewer_login":reviewer,"actual_github_review_state":"approved",
            "reviewed_environment":env,"source_run_id":run["id"],
            "run_attempt":1,"auth":"GITHUB_REVIEW_HISTORY_VERIFIED"}

def require_human_review(token,run_id,workflow_sha):
    enforce(str(run_id).isdecimal() and
        type(workflow_sha) is str and bool(HEX40.fullmatch(workflow_sha)),
        "MISSING_GITHUB_WORKFLOW_EXECUTION_BINDING")
    root="https://api.github.com/repos/"+OWNER+"/"+REPO
    repo=api(token,root)
    enforce(repo.get("id")==REPO_ID and repo.get("owner",{}).get("id")==ORG_ID,
        "NOT_ISSUING_ACTUAL_GITHUB_REPOSITORY")
    reviewers=api(token,root+"/actions/runs/"+str(run_id)+"/approvals")
    run=api(token,root+"/actions/runs/"+str(run_id))
    enforce(run.get("head_sha")==workflow_sha,
            "REVIEW_NOT_FOR_EXACT_WORKFLOW_SOURCE_COMMIT")
    # The grant's 30-minute window begins when this workflow run is
    # created, not when someone reuses its historic review record.
    created=run.get("created_at")
    enforce(type(created) is str and created.endswith("Z"),
            "NO_TRUSTWORTHY_GITHUB_RUN_CREATION_TIME")
    try:created_at=datetime.fromisoformat(created.replace("Z","+00:00"))
    except ValueError:raise PolicyDenied("INVALID_GITHUB_RUN_CREATION_TIME")
    review_age=datetime.now(timezone.utc)-created_at
    enforce(timedelta(0)<=review_age<=timedelta(minutes=30),
            "OWNER_APPROVAL_WORKFLOW_RUN_WINDOW_EXPIRED")
    proof=validate_actual_review(run,reviewers)
    proof["reviewed_run_age_seconds_at_writer"]=int(review_age.total_seconds())
    return proof

def decode_github_contents_base64(content):
    """GitHub Contents API inserts CR/LF line folds into the base64 payload.

    Permit only CR/LF transport folds, then retain strict base64 validation.
    Spaces, tabs, extra symbols, invalid padding and noncanonical encodings
    must fail closed before an authorized write.
    """
    enforce(type(content) is str and 0 < len(content) < 2000000,
            "MALFORMED_GITHUB_CONTENTS_BASE64")
    folded=content.replace("\r","").replace("\n","")
    enforce(len(folded)>0 and len(folded)%4==0,
            "MALFORMED_GITHUB_CONTENTS_BASE64")
    try: raw=base64.b64decode(folded,validate=True)
    except (ValueError,base64.binascii.Error):
        raise PolicyDenied("MALFORMED_GITHUB_CONTENTS_BASE64")
    enforce(base64.b64encode(raw).decode("ascii")==folded,
            "NONCANONICAL_GITHUB_CONTENTS_BASE64")
    return raw

def original_resource_before(token,policy):
    root="https://api.github.com/repos/"+OWNER+"/"+REPO
    item=api(token,root+"/contents/"+PATH+"?ref="+BRANCH)
    enforce(item.get("type")=="file" and
            item.get("sha")==policy["expected_prior_git_blob"],
            "GITHUB_OWNER_FILE_GIT_PRECONDITION_ALREADY_CHANGED")
    try: raw=decode_github_contents_base64(item["content"])
    except (KeyError,TypeError,PolicyDenied):
        raise PolicyDenied("MALFORMED_GITHUB_OWNER_ORIGINAL_FILE")
    enforce(digest(raw)==policy["expected_prior_content_sha256"],
            "GITHUB_REAL_PRESTATE_BYTES_NOT_AUTHORIZED")
    return {"sha":item["sha"],"content_sha256":digest(raw),"len":len(raw)}

def replay_reservation(ledger,nonce,policy_sha,review):
    led=Path(ledger)
    enforce(led.is_dir() and not led.is_symlink(),"MISSING_TRUSTED_ONE_TIME_LEDGER")
    st=led.stat()
    enforce(st.st_uid==os.geteuid() and st.st_mode&0o077==0,
            "REPLAY_LEDGER_ACCESSIBLE_TO_UNTRUSTED_PROCESS")
    target=led/nonce
    try:
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        raise PolicyDenied("GITHUB_HUMAN_APPROVAL_REPLAY_BLOCKED")
    try:
        os.write(fd,canonical({"owner_review":review,
            "owner_proposal_sha256":policy_sha,
            "state":"CONSUMED_BEFORE_GITHUB_CONTENTS_PUT"}))
        os.fsync(fd)
    finally:os.close(fd)
    return digest(nonce.encode())

def _untrusted_child_os_proof(parent_pid):
    # Actual different Linux UID (nobody) has NO token. It cannot read
    # the privileged broker parent's environment /proc and cannot submit
    # a GitHub Contents write. Never transfer the parent's secret.
    code=r'''
import json,os,sys,urllib.request,urllib.error
p=sys.argv[1]
result={"child_uid":os.geteuid(),"token_in_child_env":any(
    n in os.environ for n in ("GH_TOKEN","GITHUB_TOKEN","GITHUB_PERSONAL_ACCESS_TOKEN"))}
try:
    open("/proc/"+p+"/environ","rb").read(500000)
    result["parent_privileged_env_readable"]=True
except (PermissionError,OSError):
    result["parent_privileged_env_readable"]=False
url="https://api.github.com/repos/risu-research/risu-verify/contents/benchmarks/p6b25/BYPASS_MUST_NOT_APPEAR.txt"
r=urllib.request.Request(url,method="PUT",data=b"{}",headers={
   "Accept":"application/vnd.github+json",
   "User-Agent":"RISU-B25-unprivileged-child-sandbox"})
try:
    with urllib.request.urlopen(r,timeout=12) as v:result["anonymous_write_status"]=v.status
except urllib.error.HTTPError as e:result["anonymous_write_status"]=e.code
print(json.dumps(result))
'''
    args=["sudo","-n","-u","nobody","env","-i","PATH=/usr/bin:/bin",
          "/usr/bin/python3","-c",code,str(parent_pid)]
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,timeout=35)
    enforce(result.returncode==0,"CANNOT_EXECUTE_ISOLATED_UNTRUSTED_OS_PRINCIPAL")
    try:obj=json.loads(result.stdout.strip())
    except ValueError:raise PolicyDenied("NO_INDEPENDENT_CHILD_OS_PROBE")
    enforce(obj.get("child_uid")!=os.geteuid() and
            obj.get("token_in_child_env") is False and
            obj.get("parent_privileged_env_readable") is False and
            obj.get("anonymous_write_status") in (401,403),
            "UNTRUSTED_CHILD_COULD_ACCESS_PRIVILEGED_GITHUB_BROKER_TOKEN")
    return obj

def execute(policy_path,ledger,out,run_id,workflow_sha,token,child_probe=True):
    """Only trusted code can call this. No user script or original MCP child
    is executed with write credentials. One fixed GitHub Contents endpoint.
    """
    raw_owner_proposal=Path(policy_path).read_bytes()
    owner_git_blob=hashlib.sha1(
        b"blob "+str(len(raw_owner_proposal)).encode()+bytes([0])+
        raw_owner_proposal).hexdigest()
    enforce(owner_git_blob==EXPECTED_OWNER_PROPOSAL_GIT_BLOB,
            "EXACT_OWNER_PROPOSAL_GIT_BLOB_NOT_FIXED_AT_BUILD_TIME")
    p=verify_policy(strict_json(policy_path))
    evidence={"schema":"risu-b25-real-owner-human-reviewed-credential-confined-writer-v1",
      "approval_result":"UNVERIFIED","actual_github_writes":0,
      "owner_proposal_sha256":digest(Path(policy_path).read_bytes()),
      "separate_human_review_verified":False,"untrusted_child_received_write_token":False}
    def save():
        with Path(out).open("x") as fd:
            json.dump(evidence,fd,sort_keys=True,indent=2)
            fd.write("\n")
    try:
        review=require_human_review(token,run_id,workflow_sha)
        evidence["approval_result"]="VERIFIED_GITHUB_HUMAN_REVIEW_HISTORY"
        evidence["review"]=review
        evidence["separate_human_review_verified"]=True
        # No untrusted agent/MCP code runs holding the privileged token.
        if child_probe:
            evidence["intra_broker_os_uid_token_separation"]=_untrusted_child_os_proof(os.getpid())
        previous=original_resource_before(token,p)
        evidence["original_git_before"]=previous
        evidence["nonce_sha256"]=replay_reservation(ledger,p["run_nonce"],
            evidence["owner_proposal_sha256"],review)
        route="https://api.github.com/repos/"+OWNER+"/"+REPO+"/contents/"+PATH
        content=p["desired_content"].encode()
        response=api(token,route,method="PUT",body={
            "message":p["commit_message"],"content":base64.b64encode(content).decode(),
            "branch":BRANCH,"sha":previous["sha"]})
        evidence["actual_github_writes"]=1
        evidence["new_original_commit_sha"]=response["commit"]["sha"]
        evidence["after_git_blob"]=response["content"]["sha"]
        final=api(token,"https://api.github.com/repos/"+OWNER+"/"+REPO+
                  "/contents/"+PATH+"?ref="+response["commit"]["sha"])
        real=decode_github_contents_base64(final["content"])
        enforce(digest(real)==p["desired_content_sha256"],
                "REMOTE_GITHUB_FILE_EFFECT_NOT_OWNER_APPROVED")
        commit=api(token,"https://api.github.com/repos/"+OWNER+"/"+REPO+
                   "/commits/"+response["commit"]["sha"])
        enforce(len(commit.get("files",[]))==1 and
                commit["files"][0]["filename"]==PATH and
                commit["files"][0]["sha"]==final["sha"] and
                commit["files"][0]["status"]=="modified",
                "WRITER_CHANGED_OTHER_THAN_ONE_OWNER_APPROVED_FILE")
        evidence.update({"status":"DIRECT_HUMAN_REVIEWED_EXACT_ONE_FILE_WRITE_VERIFIED",
            "real_github_post_sha256":digest(real),
            "actual_changed_files":1,"trusted_writer_method":"ONE_STATIC_CONTENTS_PUT",
            "untrusted_mcp_code_executed_with_write_token":False,
            "credential_scope_limit":"GITHUB_JOB_REPO_WRITE_TOKEN_NOT_GITHUB_PATH_SCOPED"})
        save()
        return evidence
    except Exception as exc:
        evidence.update({"status":"DENIED_OR_UNVERIFIED",
            "reason":str(exc) if isinstance(exc,PolicyDenied) else type(exc).__name__})
        save()
        raise

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--policy",required=True)
    ap.add_argument("--ledger",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--github-run-id",required=True)
    ap.add_argument("--github-head-sha",required=True)
    ap.add_argument("--skip-os-probe",action="store_true",
                    help="Only for offline tests; not accepted by the B25 live workflow")
    a=ap.parse_args()
    tok=os.environ.get("GH_TOKEN")
    enforce(type(tok) is str and len(tok)>10,"MISSING_PROTECTED_BROKER_ONLY_GITHUB_TOKEN")
    obj=execute(a.policy,a.ledger,a.out,a.github_run_id,
                a.github_head_sha,tok,child_probe=not a.skip_os_probe)
    print("B25_GITHUB_REVIEWER_VERIFIED_ONE_FILE_WRITE",obj["new_original_commit_sha"])

if __name__=="__main__":main()
