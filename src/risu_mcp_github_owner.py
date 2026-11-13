"""RISU B23 opt-in real GitHub admin owner-grant and official MCP PRE-call gate.

The owner grant is committed by a GitHub-authenticated admin account to
risu-research/risu-verify, a real organization-owned repository. A separate
GitHub Actions job attests the grant digest with GitHub OIDC/Sigstore.

The executor has no id-token privilege, verifies that issuer attestation
from the external GitHub service *before* spawning the official GitHub
MCP server, enforces the exact repo ID, branch, Git blob prestate, tool
arguments, version SHA and one-time nonce, then checks actual remote
GitHub API file bytes after an original source-native MCP call.

The owner-approved commit is a delegated action of the connected GitHub
admin account. A push-triggered attestation is NOT a distinct natural
person's interactive consent or a third-party service's resource grant.
"""
from __future__ import annotations
import argparse,asyncio,base64,hashlib,json,os,re,stat,subprocess,sys,urllib.request
from datetime import datetime,timezone
from pathlib import Path

ISSUER_REPO="risu-research/risu-verify"
ISSUER_REPO_ID=1350184511
ORG_ID=316025762
ISSUER_WORKFLOW="risu-research/risu-verify/.github/workflows/p6b23-owner-issued-github-mcp.yml"
ISSUER_BRANCH="qualification/p6b23-owner-grants-20261112"
ISSUER_REF="refs/heads/"+ISSUER_BRANCH
EXACT_PATH="benchmarks/p6b23/owner_sandbox.txt"
OWNER_ACCOUNT="moon10021017"
EXPECTED_RELEASE_TAR_SHA="a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b"
ORIGINAL_RELEASE="v2.1.0"
SCHEMA="risu-b23-real-github-owner-authorized-fixture-v1"
HEXDIGEST=re.compile(r"[a-f0-9]{64}\Z")


class Refused(Exception):pass


def require(ok,why):
    if not ok:raise Refused(why)


def digest(data):return hashlib.sha256(data).hexdigest()


def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode()


def strict(path):
    f=Path(path)
    require(f.is_file() and not f.is_symlink() and f.stat().st_size<=131072,
            "NO_SAFE_ORIGINAL_OWNER_GRANT_DOCUMENT")
    def pairs(it):
        result={}
        for key,val in it:
            if key in result:raise Refused("AMBIGUOUS_DUPLICATE_JSON_KEY")
            result[key]=val
        return result
    return json.loads(f.read_text("utf-8"),object_pairs_hook=pairs)


def github_api(uri,token):
    require(uri.startswith("https://api.github.com/repos/risu-research/risu-verify"),
            "GITHUB_API_RESOURCE_OUTSIDE_OWNER_ACCOUNT")
    r=urllib.request.Request(uri,headers={
       "Accept":"application/vnd.github+json",
       "Authorization":"Bearer "+token,
       "X-GitHub-Api-Version":"2022-11-28",
       "User-Agent":"RISU-Probe-B23-grant-bound-original-executor"})
    with urllib.request.urlopen(r,timeout=22) as res:
        require(res.status==200,"GITHUB_ACTUAL_OWNER_SOURCE_UNAVAILABLE")
        raw=res.read(1048576)
        require(len(raw)<1048576,"UNBOUNDED_GITHUB_RESPONSE")
        return json.loads(raw)


def gh_attested(grant_path,token):
    # Validate the actual GitHub OIDC/Sigstore signature using the official
    # GitHub CLI. A supplied JSON file or self-declared "verified" flag is
    # intentionally never accepted as proof.
    cmd=["gh","attestation","verify",str(Path(grant_path).resolve()),
         "--repo",ISSUER_REPO,"--signer-workflow",ISSUER_WORKFLOW,
         "--source-ref",ISSUER_REF,"--format","json"]
    env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),
         "GH_TOKEN":token}
    p=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=65)
    require(p.returncode==0,"EXTERNAL_GITHUB_SIGSTORE_ATTESTATION_INVALID")
    result=json.loads(p.stdout)
    require(type(result) is list and 0<len(result)<12,
            "UNVERIFIED_OR_AMBIGUOUS_GITHUB_ATTESTATION")
    claim_sha=digest(Path(grant_path).read_bytes())
    accepted=False
    verified_heads=[]
    for x in result:
        v=x.get("verificationResult",{})
        statement=v.get("statement",{})
        subjects=statement.get("subject",[])
        if any(y.get("digest",{}).get("sha256")==claim_sha and
               y.get("name") in ("OWNER_AUTHORIZATION.json",
                                 "benchmarks/p6b23/OWNER_AUTHORIZATION.json")
               for y in subjects):
            accepted=True
        verified_heads.append({
            "statement_subject_sha256":claim_sha,
            "predicate_type":statement.get("predicateType"),
            "verified_timestamp_count":len(v.get("verifiedTimestamps",[]))
        })
    require(accepted,"GITHUB_SIGSTORE_SUBJECT_DIGEST_MISMATCH")
    return {"gh_verified_signer":ISSUER_WORKFLOW,
            "gh_verified_source_ref":ISSUER_REF,
            "owner_grant_sha256":claim_sha,
            "verified_count":len(result),
            "verified_attestation_subjects":verified_heads}


def utc(text):
    require(type(text) is str and text.endswith("Z") and len(text)<=32,
            "INVALID_OWNER_ISSUANCE_TIME")
    try:return datetime.fromisoformat(text.replace("Z","+00:00"))
    except ValueError:raise Refused("INVALID_OWNER_ISSUANCE_TIME")


def preflight(grant_path,tar_path,run_id,actor,approval_mode,token,
              nonce_dir):
    grant=strict(grant_path)
    require(type(grant) is dict and set(grant)=={
      "schema","grant_origin","owner_repository","owner_repository_id",
      "organization_id","actor_account","approved_branch","resource_path",
      "tool","approved_action","pre_git_blob_sha1","pre_raw_sha256",
      "post_raw_sha256","original_github_mcp_release",
      "original_github_mcp_linux_x86_64_archive_sha256",
      "validity_utc_start","validity_utc_end","nonce",
      "requested_effect","approved_tool_arguments",
      "owner_approval_statement","limit"},
      "OWNER_SCOPE_FIELDS_UNEXPECTED")
    require(grant["schema"]==SCHEMA and
      grant["grant_origin"]=="AUTHENTICATED_GITHUB_ADMIN_ACCOUNT_DELEGATION" and
      grant["owner_repository"]==ISSUER_REPO and
      grant["owner_repository_id"]==ISSUER_REPO_ID and
      grant["organization_id"]==ORG_ID and
      grant["actor_account"]==OWNER_ACCOUNT and
      grant["approved_branch"]==ISSUER_BRANCH and
      grant["resource_path"]==EXACT_PATH and
      grant["tool"]=="create_or_update_file" and
      grant["approved_action"]=="REPLACE" and
      grant["original_github_mcp_release"]==ORIGINAL_RELEASE and
      grant["original_github_mcp_linux_x86_64_archive_sha256"]==EXPECTED_RELEASE_TAR_SHA,
      "GRANT_NOT_FROM_VERIFIED_ACTUAL_REPOSITORY_OWNER")
    require(type(grant["nonce"]) is str and bool(HEXDIGEST.fullmatch(grant["nonce"])),
            "UNBOUNDED_REPLAY_NONCE")
    require(utc(grant["validity_utc_start"])<=datetime.now(timezone.utc)<
            utc(grant["validity_utc_end"]),
            "OWNER_REPOSITORY_GRANT_EXPIRED")
    args=grant["approved_tool_arguments"]
    require(type(args) is dict and set(args)=={
        "owner","repo","branch","path","message","content","sha"},
        "TOOL_ARGUMENT_SCOPE_AMBIGUOUS")
    require(args["owner"]=="risu-research" and args["repo"]=="risu-verify" and
            args["branch"]==ISSUER_BRANCH and args["path"]==EXACT_PATH and
            args["sha"]==grant["pre_git_blob_sha1"] and
            type(args["content"]) is str and 0<len(args["content"])<800 and
            digest(args["content"].encode())==grant["post_raw_sha256"],
            "TOOL_ARGUMENTS_OUTSIDE_REPO_OWNER_GRANT")
    require(type(grant["pre_git_blob_sha1"]) is str and
            bool(re.fullmatch(r"[a-f0-9]{40}",grant["pre_git_blob_sha1"])) and
            bool(HEXDIGEST.fullmatch(grant["pre_raw_sha256"])) and
            bool(HEXDIGEST.fullmatch(grant["post_raw_sha256"])),
            "WRONG_OWNER_GIT_BLOB_PRECONDITION")
    require(Path(tar_path).is_file() and
            digest(Path(tar_path).read_bytes())==EXPECTED_RELEASE_TAR_SHA,
            "ORIGINAL_PUBLISHER_MCP_SERVER_DISTRIBUTION_UNVERIFIED")
    require(type(run_id) is str and run_id.isdecimal() and
            actor==OWNER_ACCOUNT and approval_mode in (
               "DIRECT_AUTHENTICATED_OWNER_ACCOUNT_DISPATCH",
               "DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT"),
            "ORIGINAL_OWNER_APPROVAL_ACCOUNT_UNVERIFIED")

    # No original MCP process has been started yet. Verify the external
    # GitHub-owned Sigstore attestation, real repository, actual grant-issuer
    # account permission and the authentic GitHub workflow run from API.
    cert=gh_attested(grant_path,token)
    repo=github_api("https://api.github.com/repos/"+ISSUER_REPO,token)
    require(repo["id"]==ISSUER_REPO_ID and
            repo["owner"]["id"]==ORG_ID and repo["private"] is False,
            "GITHUB_REAL_REPOSITORY_OWNERSHIP_NOT_CONFIRMED")
    approval=github_api(
        "https://api.github.com/repos/"+ISSUER_REPO+
        "/collaborators/"+OWNER_ACCOUNT+"/permission",token)
    require(approval["permission"]=="admin",
            "ISSUER_ACCOUNT_HAS_NO_REAL_REPOSITORY_ADMIN_AUTHORITY")
    run=github_api(
        "https://api.github.com/repos/"+ISSUER_REPO+
        "/actions/runs/"+run_id,token)
    require(run["actor"]["login"]==OWNER_ACCOUNT and
            run["head_branch"]==ISSUER_BRANCH and
            run["path"]==".github/workflows/p6b23-owner-issued-github-mcp.yml",
            "GITHUB_OIDC_SIGNED_WORKFLOW_NOT_ACTUAL_OWNER_RUN")
    require((run["event"]=="workflow_dispatch")==
              (approval_mode=="DIRECT_AUTHENTICATED_OWNER_ACCOUNT_DISPATCH"),
            "WRONG_OWNER_APPROVAL_EVENT_CLASSIFICATION")
    # For the first B23 baseline, require the real owner-authored commit
    # before taking actions that would destroy its original precondition.
    branch=github_api("https://api.github.com/repos/"+ISSUER_REPO+
        "/branches/"+ISSUER_BRANCH,token)
    require(type(branch["commit"]["sha"]) is str and len(branch["commit"]["sha"])==40,
            "OWNER_RESOURCE_BRANCH_IDENTITY_UNVERIFIED")
    original=github_api("https://api.github.com/repos/"+ISSUER_REPO+
         "/contents/"+EXACT_PATH+"?ref="+ISSUER_BRANCH,token)
    require(original["type"]=="file" and original["sha"]==grant["pre_git_blob_sha1"],
            "OWNER_PRECALL_RESOURCE_GIT_BLOB_CHANGED")
    actual_before=base64.b64decode(original["content"],validate=False)
    require(digest(actual_before)==grant["pre_raw_sha256"],
            "OWNER_ACTUAL_REMOTE_PRESTATE_MISMATCH")
    require(os.path.isdir(nonce_dir) and os.stat(nonce_dir).st_mode&0o077==0,
            "NONCE_LEDGER_NOT_PRIVATE")
    nonce_path=Path(nonce_dir)/grant["nonce"]
    # Complete all checks before consuming a nonce or starting a server.
    fd=os.open(nonce_path,os.O_WRONLY|os.O_EXCL|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,canonical({
           "nonce":grant["nonce"],
           "grant_digest":cert["owner_grant_sha256"],
           "github_verified_owner_account":OWNER_ACCOUNT,
           "original_server_spawned":False}))
        os.fsync(fd)
    finally:os.close(fd)
    return {"grant":grant,"cert":cert,
            "owner_github_run_id":run_id,
            "owner_github_run_event":run["event"],
            "verified_admin_permission":approval["permission"],
            "remote_old_file_sha256":digest(actual_before),
            "remote_old_blob_sha1":original["sha"],
            "remote_old_branch_head":branch["commit"]["sha"],
            "nonce_sha256":digest(grant["nonce"].encode())}


async def original_mcp(server_exe,token,arguments):
    proc=await asyncio.create_subprocess_exec(
       str(Path(server_exe).absolute()),"stdio","--tools","create_or_update_file",
       stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
       stderr=asyncio.subprocess.PIPE,limit=1048576,
       env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),
            "HOME":os.environ.get("HOME","/tmp"),
            "GITHUB_PERSONAL_ACCESS_TOKEN":token,
            "GITHUB_TOOLSETS":"repos",
            "GITHUB_TOOLS":"create_or_update_file",
            "CI":"true"})
    wire=[]
    async def exchange(request):
        raw=canonical(request)+b"\n"
        proc.stdin.write(raw)
        await asyncio.wait_for(proc.stdin.drain(),20)
        wire.append(raw)
        if "id" not in request:return None
        for _ in range(25):
            data=await asyncio.wait_for(proc.stdout.readline(),35)
            if not data or not data.endswith(b"\n") or len(data)>1048576:
                raise RuntimeError("Original GitHub MCP server did not return bounded JSON-RPC")
            wire.append(data)
            msg=json.loads(data)
            if msg.get("id")==request["id"]:return msg
            if "id" not in msg:continue
            raise RuntimeError("Unexpected native GitHub MCP server initiated call")
        raise RuntimeError("Unbounded original MCP notifications")
    try:
        hello=await exchange({"jsonrpc":"2.0","id":1,"method":"initialize",
           "params":{"protocolVersion":"2025-11-25","capabilities":{},
                     "clientInfo":{"name":"risu-b23-attested-owner-gate","version":"1"}}})
        if type(hello.get("result")) is not dict:
            raise RuntimeError("Official GitHub MCP initialization failed")
        await exchange({"jsonrpc":"2.0","method":"notifications/initialized"})
        catalog=await exchange({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        tools=catalog.get("result",{}).get("tools",[])
        names={t.get("name") for t in tools if type(t) is dict}
        if "create_or_update_file" not in names:
            raise RuntimeError("Official GitHub MCP server did not advertise frozen write tool")
        call={"jsonrpc":"2.0","id":20,"method":"tools/call",
              "params":{"name":"create_or_update_file","arguments":arguments}}
        response=await exchange(call)
        if (type(response.get("result")) is not dict or
            response["result"].get("isError") is True or "error" in response):
            raise RuntimeError("Original native Github MCP tool failed")
        return {
          "original_mcp_source_tool":"create_or_update_file",
          "original_mcp_tool_list_count":len(names),
          "original_native_jsonrpc_b64":base64.b64encode(b"".join(wire)).decode(),
          "original_native_jsonrpc_sha256":digest(b"".join(wire)),
          "original_mcp_server_pid":proc.pid,
          "original_mcp_tool_result":response["result"]
        }
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:await asyncio.wait_for(proc.wait(),5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()


def live_state(token,branch=ISSUER_BRANCH):
    item=github_api("https://api.github.com/repos/"+ISSUER_REPO+
        "/contents/"+EXACT_PATH+"?ref="+branch,token)
    raw=base64.b64decode(item["content"],validate=False)
    return {"file_sha256":digest(raw),"git_blob_sha":item["sha"],
            "bytes":len(raw),"file_contents_b64":base64.b64encode(raw).decode()}


async def execute(argv=None):
    p=argparse.ArgumentParser()
    for f in ("grant","original-server","original-archive",
              "authenticating-run","approval-mode","actor","out"):
        p.add_argument("--"+f,required=True)
    a=p.parse_args(argv)
    target=Path(a.out)
    if target.exists():raise RuntimeError("Never overwrite original GitHub owner result")
    target.mkdir()
    ledger=target/"ledger"
    ledger.mkdir(mode=0o700)
    token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    require(type(token) is str and len(token)>10,
            "NO_REAL_GITHUB_TOKEN_FOR_OWNER_RESOURCE")
    def record(name,obj):
        file=target/name
        with file.open("x") as fd:
            json.dump(obj,fd,sort_keys=True,indent=2)
            fd.write("\n")
    evidence={"schema":"risu-b23-external-github-owner-original-mcp-evidence-v1",
      "issuer_repo":ISSUER_REPO,
      "verified_human_direct_approval":False,
      "original_publisher_release":"github/github-mcp-server v2.1.0",
      "original_native_mcp_started":False,
      "original_tool_calls":0,
      "phase":"NO_ORIGINAL_PROCESS_STARTED"}
    # Negative controls must not spawn any server. They operate on local
    # policy variants and are run BEFORE the owner-approved live call.
    grant0=strict(a.grant)
    expected="benchmarks/p6b23/owner_sandbox.txt"
    negative=[
        ("no_owner_grant",None),
        ("forged_owner_grant",{**grant0,"nonce":"f"*64}),
        ("unapproved_path",{**grant0,"resource_path":"README.md"}),
        ("wrong_target_branch",{**grant0,"approved_branch":"main"}),
        ("unapproved_tool",{**grant0,"tool":"delete_file"})
    ]
    negatives=[]
    for name,bad in negative:
        mutant=target/(name+".json")
        if bad is not None:
            record(mutant.name,bad)
        try:
            preflight(mutant,a.original_archive,a.authenticating_run,a.actor,
                a.approval_mode,token,ledger)
        except (Refused,FileNotFoundError,ValueError,OSError):
            negatives.append({"name":name,"server_started":False,
                              "original_tool_calls":0,"decision":"DENIED_PRECALL"})
        else:raise RuntimeError("Preflight accepted unauthorized mutation: "+name)
    evidence["precall_adversarial_denials"]=negatives
    # The only operation which can spawn the official GitHub MCP server.
    try:
        proof=preflight(a.grant,a.original_archive,a.authenticating_run,
            a.actor,a.approval_mode,token,ledger)
        evidence.update({
           "phase":"GITHUB_SIGSTORE_AND_REPO_ADMIN_APPROVED_PRECALL",
           "grant_source":proof["cert"],
           "actual_owner_platform_permission":proof["verified_admin_permission"],
           "actual_owner_workflow_event":proof["owner_github_run_event"],
           "actual_owner_workflow_run_id":proof["owner_github_run_id"],
           "owner_old_remote_blob":proof["remote_old_blob_sha1"],
           "owner_old_remote_content_sha256":proof["remote_old_file_sha256"],
           "original_github_mcp_release_tar_sha256":EXPECTED_RELEASE_TAR_SHA,
           "nonce_sha256":proof["nonce_sha256"]})
        result=await original_mcp(a.original_server,token,
            proof["grant"]["approved_tool_arguments"])
        evidence["original_native_mcp_started"]=True
        evidence["original_tool_calls"]=1
        evidence["original_result"]=result
        state=live_state(token)
        evidence["remote_post_effect"]=state
        require(state["file_sha256"]==proof["grant"]["post_raw_sha256"],
                "ORIGINAL_GITHUB_MCP_RESULT_NOT_BACKED_BY_REMOTE_OWNER_RESOURCE")
        require(state["git_blob_sha"]!=proof["grant"]["pre_git_blob_sha1"],
                "ORIGINAL_GITHUB_REPO_FILE_EFFECT_NOT_OBSERVED")
        evidence["phase"]="OWNER_ATTESTED_PRECALL_ALLOWED_ORIGINAL_MCP_REMOTE_EFFECT_CONFIRMED"
        record("REAL_OWNER_REPOSITORY_ORIGINAL_MCP_RESULT.json",evidence)
        # A reused grant never launches the original MCP process even if
        # someone reverts owner resource bytes to the previous version.
        replay_failed=False
        try:
            preflight(a.grant,a.original_archive,a.authenticating_run,
                a.actor,a.approval_mode,token,ledger)
        except (Refused,FileExistsError,ValueError,OSError):
            replay_failed=True
        require(replay_failed,"ORIGINAL_SIGNED_GRANT_REPLAY_NOT_DENIED")
        record("REPLAY_PRECALL_DENIED.json",{
            "precall":"DENIED","original_mcp_server_spawned":False,
            "nonce_reused":True,
            "approved_owner_resource_persisted":state["file_sha256"]})
        print("B23_REAL_GITHUB_OWNER_APPROVED_ORIGINAL_MCP_REMOTE_EFFECT",
              json.dumps({"issuer_repo":ISSUER_REPO,
                 "issuer_admin":OWNER_ACCOUNT,
                 "approval_mode":a.approval_mode,
                 "remote_after_sha256":state["file_sha256"],
                 "original_tool_calls":1,
                 "precall_denials":len(negatives)+1},sort_keys=True))
        return 0
    except Exception as e:
        evidence["phase"]="UNVERIFIED_OR_FAIL_CLOSED"
        evidence["failure_kind"]=type(e).__name__
        evidence["failure_reason"]=str(e)[:190] if isinstance(e,Refused) else "FAILED_ORIGINAL_MCP_EXECUTION"
        record("REJECTED_OR_UNVERIFIED.json",evidence)
        print("B23_PRECALL_OR_REMOTE_GITHUB_OWNER_EFFECT_FAILED",
              type(e).__name__,file=sys.stderr)
        return 2


def main():
    return asyncio.run(execute())


if __name__=="__main__":
    raise SystemExit(main())
