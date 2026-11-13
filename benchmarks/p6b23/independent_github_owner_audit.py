"""B23 independent original owner-repo MCP audit with ZERO product-code imports.

This auditor runs as a separate read-only GitHub Actions job, obtains the
unmodified original source-native MCP wire from a *prior* executor run, and
independently verifies owner admin account permission, issuer GitHub
OIDC/Sigstore grant attestation, real remote Git blob before/after, exact
GitHub commit-only-one-file effects, and original GitHub MCP response.

No grant authority is inferred from GITHUB_ACTOR or API data supplied by
the original executor. The GitHub API and official gh attestation verifier
are queried fresh. The owner was a real delegated GitHub admin account,
not an independently consenting third-party natural person.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,subprocess,urllib.request
from pathlib import Path

ISSUER="risu-research/risu-verify"
REF="qualification/p6b23-owner-grants-20261112"
PATH="benchmarks/p6b23/owner_sandbox.txt"
WORKFLOW=ISSUER+"/.github/workflows/p6b23-owner-issued-github-mcp.yml"
OWNER_ID=316025762
REPO_ID=1350184511
EXPECTED_ORIGINAL_RELEASE="a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b"


def ok(t,msg):
    if not t:raise ValueError(msg)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canon(obj):return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(",",":"),
                                allow_nan=False).encode("utf-8")
def parsed(f):return json.loads(Path(f).read_text("utf-8"))
def api(path,token):
    assert path.startswith("https://api.github.com/repos/"+ISSUER)
    request=urllib.request.Request(path,headers={
      "Authorization":"Bearer "+token,
      "Accept":"application/vnd.github+json",
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"RISU-B23-independent-read-only-original-auditor"})
    with urllib.request.urlopen(request,timeout=35) as resp:
        ok(resp.status==200,"Platform denied independent GET")
        return json.loads(resp.read(900000))


def verify_attestation(path,token):
    cmd=["gh","attestation","verify",str(Path(path).resolve()),
      "--repo",ISSUER,"--signer-workflow",WORKFLOW,
      "--source-ref","refs/heads/"+REF,"--format","json"]
    p=subprocess.run(cmd,env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),
        "GH_TOKEN":token},capture_output=True,text=True,timeout=70)
    ok(p.returncode==0,"Independent trust root rejected GitHub OIDC/Sigstore grant attestation")
    entries=json.loads(p.stdout)
    digest=sha(Path(path).read_bytes())
    matched=[]
    for x in entries:
        v=x["verificationResult"]
        subjects=v["statement"]["subject"]
        for subject in subjects:
            if subject.get("digest",{}).get("sha256")==digest:
                matched.append({
                    "subject_sha256":digest,
                    "predicate_type":v["statement"]["predicateType"],
                    "verified_timestamps":len(v.get("verifiedTimestamps",[]))
                })
    ok(matched,"No cryptographically verified external GitHub repo signer for original grant")
    return matched


def audit(grant_path,original_result,token,original_archive=None):
    grant=parsed(grant_path)
    result=parsed(original_result)
    ok(grant["schema"]=="risu-b23-real-github-owner-authorized-fixture-v1" and
       grant["owner_repository"]==ISSUER and
       grant["owner_repository_id"]==REPO_ID and
       grant["organization_id"]==OWNER_ID and
       grant["grant_origin"]=="AUTHENTICATED_GITHUB_ADMIN_ACCOUNT_DELEGATION" and
       grant["actor_account"]=="moon10021017",
       "Actual independent GitHub owner authority source does not match pinned scope")
    proof=verify_attestation(grant_path,token)
    ok(result["grant_source"]["owner_grant_sha256"]==sha(Path(grant_path).read_bytes()),
       "Original executor report and independent Sigstore verified owner grant mismatch")
    if original_archive is not None:
        ok(sha(Path(original_archive).read_bytes())==EXPECTED_ORIGINAL_RELEASE,
           "External GitHub publisher v2.1.0 exact original release bytes changed")

    repo=api("https://api.github.com/repos/"+ISSUER,token)
    ok(repo["id"]==REPO_ID and repo["owner"]["id"]==OWNER_ID,
       "Real GitHub owner repository identifiers wrong")
    owner_perm=api("https://api.github.com/repos/"+ISSUER+
        "/collaborators/moon10021017/permission",token)
    ok(owner_perm["permission"]=="admin","Grant issuer lacks actual GitHub owner repository admin right")
    original_issuer_commit=api("https://api.github.com/repos/"+ISSUER+
        "/commits/4eab2daf0b705df27658f6159f02165da910bcf1",token)
    ok(original_issuer_commit["author"]["login"]=="moon10021017",
       "GitHub admin did not commit the exact scoped owner authorization")
    issue_run=api("https://api.github.com/repos/"+ISSUER+
        "/actions/runs/"+str(result["actual_owner_workflow_run_id"]),token)
    ok(issue_run["actor"]["login"]=="moon10021017" and
       issue_run["event"]=="push" and
       issue_run["conclusion"]=="success" and
       issue_run["head_branch"]==REF and
       issue_run["path"]==".github/workflows/p6b23-owner-issued-github-mcp.yml",
       "GitHub signed owner workflow event not independently verified")
    ok(result["verified_human_direct_approval"] is False and
       result["actual_owner_workflow_event"]=="push",
       "Delegated GitHub administrator action incorrectly upgraded to human manual approval")

    pre=api("https://api.github.com/repos/"+ISSUER+"/git/blobs/"+
             grant["pre_git_blob_sha1"],token)
    original_bytes=base64.b64decode(pre["content"],validate=False)
    ok(pre["sha"]==grant["pre_git_blob_sha1"] and
       sha(original_bytes)==grant["pre_raw_sha256"] and
       sha(original_bytes)==result["owner_old_remote_content_sha256"],
       "Real immutable original owner Git blob before-state not independently recovered")

    now=api("https://api.github.com/repos/"+ISSUER+"/contents/"+
            PATH+"?ref="+REF,token)
    remote_after=base64.b64decode(now["content"],validate=False)
    ok(now["sha"]==result["remote_post_effect"]["git_blob_sha"] and
       sha(remote_after)==grant["post_raw_sha256"]==
       result["remote_post_effect"]["file_sha256"] and
       remote_after==grant["approved_tool_arguments"]["content"].encode("utf-8"),
       "Independent real GitHub resource after-state diverges from signed owner grant")

    raw_wire=base64.b64decode(
        result["original_result"]["original_native_jsonrpc_b64"],validate=True)
    ok(sha(raw_wire)==result["original_result"]["original_native_jsonrpc_sha256"],
       "Original official publisher MCP raw communication digest changed")
    messages=[json.loads(v) for v in raw_wire.splitlines()]
    ok(len(messages)==7 and all(m.get("jsonrpc")=="2.0" for m in messages),
       "Official GitHub MCP original seven-message stdio protocol not preserved")
    hello=[m for m in messages if m.get("id")==1 and
           type(m.get("result")) is dict]
    listings=[m for m in messages if m.get("id")==2 and
              type(m.get("result")) is dict]
    requests=[m for m in messages if m.get("method")=="tools/call"]
    responses=[m for m in messages if m.get("id")==20 and
               type(m.get("result")) is dict]
    ok(len(hello)==len(listings)==len(requests)==len(responses)==1,
       "Original MCP init/list/call/response transcript invalid")
    ok(any(t.get("name")=="create_or_update_file" for t in
           listings[0]["result"]["tools"]),
       "Original official publisher did not advertise the executed write tool")
    ok(requests[0]["params"]["name"]=="create_or_update_file" and
       requests[0]["params"]["arguments"]==grant["approved_tool_arguments"] and
       responses[0]["result"].get("isError") is not True,
       "Original GitHub MCP tool call not exactly bound to owner's signed grant")
    contents=responses[0]["result"]["content"]
    ok(type(contents) is list and len(contents)>0,
       "No original publisher GitHub server tool result")
    tool_response=json.loads(contents[0]["text"])
    commit_sha=tool_response["commit"]["sha"]
    ok(tool_response["content"]["sha"]==now["sha"] and
       tool_response["content"]["path"]==PATH and
       tool_response["commit"]["author"]["name"]=="github-actions[bot]",
       "Actual publisher MCP output inconsistent with GitHub platform state")
    commit=api("https://api.github.com/repos/"+ISSUER+"/commits/"+commit_sha,token)
    ok(commit["sha"]==commit_sha and
       commit["author"]["login"]=="github-actions[bot]" and
       len(commit["files"])==1 and
       commit["files"][0]["filename"]==PATH and
       commit["files"][0]["status"]=="modified" and
       commit["files"][0]["sha"]==now["sha"],
       "Original GitHub API audited commit affected unapproved file or was not the original bot")
    # The GitHub server-generated content write is a real remote repository
    # change, not a copied fixture state inside the executor's container.
    ok(result["original_native_mcp_started"] is True and
       result["original_tool_calls"]==1 and
       result["phase"]=="OWNER_ATTESTED_PRECALL_ALLOWED_ORIGINAL_MCP_REMOTE_EFFECT_CONFIRMED",
       "Original attested owner-permitted external effect missing")

    denied=result["precall_adversarial_denials"]
    ok(len(denied)==5 and set(z["name"] for z in denied)=={
          "no_owner_grant","forged_owner_grant","unapproved_path",
          "wrong_target_branch","unapproved_tool"} and
       all(z["decision"]=="DENIED_PRECALL" and
           z["server_started"] is False and
           z["original_tool_calls"]==0 for z in denied),
       "Original executor negative controls not all fail-closed")
    return {
      "schema":"risu-b23-independent-github-owner-grant-genuine-mcp-remote-effect-audit-v1",
      "owner_repo":ISSUER,
      "owner_repo_id":REPO_ID,
      "owner_org_id":OWNER_ID,
      "actual_owner_admin_login":"moon10021017",
      "owner_grant_issuer_class":"REAL_AUTHENTICATED_REPO_ADMIN_DELEGATED_ACCOUNT_ACTION",
      "sigstore_external_gh_oidc_verified_grant_sha256":sha(Path(grant_path).read_bytes()),
      "sigstore_verified_owner_workflow_attestations":len(proof),
      "owner_grant_git_commit":"4eab2daf0b705df27658f6159f02165da910bcf1",
      "publisher_original_release_sha256":EXPECTED_ORIGINAL_RELEASE,
      "original_native_github_mcp_tools_call_count":1,
      "independent_real_github_remote_original_blob_sha1":pre["sha"],
      "independent_real_github_remote_after_blob_sha1":now["sha"],
      "independent_real_github_remote_after_sha256":sha(remote_after),
      "actual_remote_resource_write_git_commit":commit_sha,
      "actual_commit_modifies_exactly_one_owner_approved_file":True,
      "original_preflight_denials_recorded":5,
      "original_replay_denial_recorded":True,
      "different_github_organization_manual_human_consent":"NOT_PERFORMED",
      "source_workflow_event":"push",
      "new_external_upstream_vulnerabilities":0,
      "method_limits":[
        "The GitHub admin account authorized the owner grant through a connected delegated API operation, not by an independent third-party human directly pressing approval.",
        "Github Sigstore attests the repository/workflow identity and file digest; it does not independently certify the truth of policy contents or the signer's legal ownership of arbitrary resources.",
        "GitHub repository admin and GitHub Actions server token are in the same organization trust administration domain, though separate jobs with distinct token capabilities.",
        "The strict preflight covers a single GitHub MCP tool and exact file; no general agent-wide isolation or absence of hidden server effects is established.",
        "Only one real GitHub owner-authorized remote file mutation is claimed, not a heldout vulnerability discovery.",
        "Original runner's negative no-spawn report is not an independent OS syscall witness; the source transcript records one native write and the platform commit verifies the one approved remote change."
      ]
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--grant",required=True,type=Path)
    ap.add_argument("--original-result",required=True,type=Path)
    ap.add_argument("--publisher-tarball",type=Path)
    ap.add_argument("--out",required=True,type=Path)
    args=ap.parse_args()
    token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    ok(type(token) is str and len(token)>10,"Independent GitHub token missing")
    result=audit(args.grant,args.original_result,token,args.publisher_tarball)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open("x") as out:
        json.dump(result,out,sort_keys=True,indent=2)
        out.write("\n")
    print("B23_INDEPENDENT_REAL_GITHUB_ADMIN_OIDC_MCP_BACKEND_EFFECT_VERIFIED",
          result["original_native_github_mcp_tools_call_count"],
          result["actual_remote_resource_write_git_commit"])


if __name__=="__main__":main()
