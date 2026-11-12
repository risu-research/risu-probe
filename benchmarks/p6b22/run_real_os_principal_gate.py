"""P6-B22 two *actual OS UIDs* with separate keys, original upstream MCP and enforcement.

This runner is only for an EPHEMERAL GitHub-hosted Ubuntu VM with sudo.
It creates one owner Unix principal and one different executor principal,
uses the owner's private-only key to authorize exact requests, and uses
the executor-only atomic nonce ledger to PREVENT the original source
process from spawning when a permission is absent, stale, revoked or invalid.

The identities are distinct real OS accounts, not verified independent
human users. GitHub CI's privileged runner remains a superuser capable
of modifying everything, so these controls never claim a real customer
authorization chain.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,shutil,secrets,stat,subprocess,sys
from pathlib import Path


CASES={}
SHORT="RISU B22 synthetic owner-approved content\n"
LONG="RISU B22 old harmless synthetic contents plus longer text used only in synthetic fixtures\n"


def sha(b):return hashlib.sha256(b).hexdigest()
def execute(*args,timeout=90,expect=0):
    run=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=timeout,
        cwd="/tmp" if args and str(args[0])=="sudo" else None)
    if expect is not None and run.returncode!=expect:
        raise RuntimeError("External integration subprocess failed: "+
          " ".join(str(x) for x in args[:3])+" rc="+str(run.returncode)+
          " stderr="+run.stderr[-1600:]+" stdout="+run.stdout[-1500:])
    return run


def write(p,v):
    p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")


def owner_cmd(py,script,user,*args):
    return execute("sudo","-u",user,"-H",py,script,*args)


def state(p):
    if not p.exists():return {"exists":False,"sha256":None,"size":0}
    raw=p.read_bytes()
    return {"exists":True,"sha256":sha(raw),"size":len(raw)}


def run(args):
    assert os.name=="posix" and os.geteuid()!=0
    original_wheel=next(args.published_wheels.glob("filesystem_mcp-1.0.2-*.whl"))
    assert sha(original_wheel.read_bytes())=="94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235"
    if args.out.exists():raise RuntimeError("Never overwrite real two-UID source-run evidence")
    args.out.mkdir()
    rid=secrets.token_hex(5)
    base=Path("/tmp/risu-b22-two-real-uids-"+rid)
    base.mkdir(mode=0o755)
    base.chmod(0o755)
    usernames={"owner":"risu22owner","exec":"risu22exec","group":"risu22shared"}
    for name in (usernames["owner"],usernames["exec"]):
        execute("id",name,expect=1)
    execute("sudo","groupadd",usernames["group"])
    for x in ("owner","exec"):
        execute("sudo","useradd","-m","-s","/bin/bash",usernames[x])
        execute("sudo","chmod","700","/home/"+usernames[x])
        execute("sudo","usermod","-aG",usernames["group"],usernames[x])
    uid_owner=int(execute("id","-u",usernames["owner"]).stdout.strip())
    uid_exec=int(execute("id","-u",usernames["exec"]).stdout.strip())
    assert uid_owner!=uid_exec and uid_owner!=0 and uid_exec!=0
    permitted=base/"owned-resource"
    published=base/"public-owner-grants"
    ledger=base/"executor-private-ledger"
    results=base/"executor-records"
    requests=base/"requests"
    for p in (permitted,published,ledger,results,requests):p.mkdir(mode=0o755)
    execute("sudo","chown",usernames["owner"]+":"+usernames["group"],permitted)
    execute("sudo","chmod","2770",permitted)
    execute("sudo","chown",usernames["owner"]+":"+usernames["group"],published)
    execute("sudo","chmod","755",published)
    for p in (ledger,results):
        execute("sudo","chown",usernames["exec"]+":"+usernames["group"],p)
        execute("sudo","chmod","700" if p==ledger else "755",p)
    requests.chmod(0o755)
    private=Path("/home")/usernames["owner"]/"b22-private-owner-ed25519.pem"
    root=published/"owner-pretrusted-public.json"
    rev_empty=published/"revocations_epoch0.json"
    # GitHub runner home is deliberately private; never loosen its
    # permissions just to let another OS user traverse a checkout.
    source_issuer=Path(args.issuer_script).resolve()
    issuer_script=base/"PUBLIC_OWNER_ISSUER_CODE.py"
    shutil.copyfile(source_issuer,issuer_script)
    issuer_script.chmod(0o644)
    source_venv=Path(args.original_python).absolute().parent.parent
    server_venv=base/"PINNED_UPSTREAM_VENV"
    shutil.copytree(source_venv,server_venv,symlinks=True)
    original_py=server_venv/"bin/python"
    source_wheel=original_wheel
    external_wheel=base/source_wheel.name
    shutil.copyfile(source_wheel,external_wheel)
    external_wheel.chmod(0o644)
    assert sha(external_wheel.read_bytes())==sha(source_wheel.read_bytes())
    original_wheel=external_wheel
    gateway_py=Path(sys.executable).resolve()
    signer=[
        "sudo","-u",usernames["owner"],"-H",str(gateway_py),str(issuer_script)
    ]
    execute(*signer,"bootstrap","--private",private,"--root",root,
            "--directory",permitted,"--issuer","b22-real-linux-principal-resource-owner",
            "--resource-id","urn:risu-b22:fixture:real-posix-user-file",
            "--wheel-sha256",sha(original_wheel.read_bytes()),
            "--executor-uid",uid_exec)
    pinned_root=sha(root.read_bytes())
    root_object=json.loads(root.read_text())
    assert root_object["owner_uid"]==uid_owner and root_object["executor_uid"]==uid_exec
    # Different actual POSIX account cannot read the signing private key.
    no_secret=execute("sudo","-u",usernames["exec"],"test","-r",private,expect=1)
    assert private.stat().st_uid==uid_owner and private.stat().st_mode&0o077==0
    execute(*signer,"revocation","--private",private,"--root",root,
            "--out",rev_empty,"--sequence",0)
    current_rev=rev_empty
    rev_pin=sha(current_rev.read_bytes())
    assert (permitted.stat().st_uid==uid_owner and
            ledger.stat().st_uid==uid_exec)
    # Ensure the imported original module resolves from the pinned isolated venv.
    mod=execute("sudo","-u",usernames["exec"],"-H",original_py,"-I","-c",
         "import filesystem_mcp.server as s, pathlib, hashlib; "
         "print(hashlib.sha256(pathlib.Path(s.__file__).read_bytes()).hexdigest())")
    assert mod.stdout.strip()=="c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8"
    issuer_private_access_test={
      "owner_uid":uid_owner,"executor_uid":uid_exec,
      "owner_is_distinct_OS_user":True,
      "owner_resource_directory_uid":permitted.stat().st_uid,
      "executor_nonce_ledger_uid":ledger.stat().st_uid,
      "private_key_uid":private.stat().st_uid,
      "private_key_mode":oct(private.stat().st_mode&0o777),
      "executor_can_read_owner_private_key":False,
      "original_module_sha256":mod.stdout.strip(),
      "original_publisher_wheel_sha256":sha(original_wheel.read_bytes()),
      "pretrusted_owner_root_sha256":pinned_root,
      "ephemeral_privileged_CI_runner_can_sudo":True
    }
    write(args.out/"OS_INDEPENDENT_ACCOUNT_STATE.json",issuer_private_access_test)
    print("B22_TWO_REAL_POSIX_PRINCIPALS_VERIFIED",json.dumps(issuer_private_access_test))
    records={}
    def request(name,content=SHORT):
        target=permitted/(name+".txt")
        data={"jsonrpc":"2.0","id":20,"method":"tools/call",
              "params":{"name":"write_file",
                        "arguments":{"path":str(target),
                                     "content":content,"append":False}}}
        file=requests/(name+".json")
        write(file,data)
        return file,target

    def grant(label,request_file,operation):
        out=published/("grant_"+label+".json")
        execute(*signer,"grant","--private",private,"--root",root,
                "--request",request_file,"--out",out,
                "--allow-operation",operation)
        assert out.is_file() and out.stat().st_uid==uid_owner
        return out

    def gateway(label,request_file,grant_file,target,authorized,rev=None,
                rev_sha=None):
        output=results/(label+".json")
        syscall=results/(label+".execve.strace")
        tool=["sudo","-u",usernames["exec"],"-H","strace","-f",
              "-e","execve","-o",str(syscall),
              str(gateway_py),"-m","risu_p5d_cli",
              "enforce-mcp-preflight",
              "--request",str(request_file),
              "--grant",str(grant_file),
              "--trust-root",str(root),
              "--trusted-root-sha256",pinned_root,
              "--revocations",str(rev or current_rev),
              "--revocations-sha256",rev_sha or rev_pin,
              "--original-wheel",str(original_wheel.absolute()),
              "--ledger",str(ledger),
              "--server-python",str(original_py),
              "--out",str(output)]
        before=state(target)
        if target.is_file():
            (args.out/(label+"_BEFORE_ORIGINAL_TARGET.bin")).write_bytes(target.read_bytes())
        p=execute(*tool,expect=0 if authorized else 3,timeout=100)
        after=state(target)
        if target.is_file():
            (args.out/(label+"_AFTER_ORIGINAL_TARGET.bin")).write_bytes(target.read_bytes())
        obj=json.loads(output.read_text())
        trace=syscall.read_text(errors="replace")
        # Actual OS syscall tracing verifies the original upstream Python
        # '-m filesystem_mcp' process was (or was not) even started.
        native_spawn=('-m", "filesystem_mcp"' in trace or
                      "'-m', 'filesystem_mcp'" in trace)
        assert native_spawn==authorized,(label,trace[-1500:])
        assert obj["server_started"] is authorized
        assert obj["native_original_tool_calls"]==(1 if authorized else 0)
        if authorized:
            assert obj["decision"]=="AUTHORIZED_EXECUTED_AND_POSTCONDITION_MATCHED"
            raw=base64.b64decode(obj["original_raw_jsonrpc_b64"])
            assert obj["original_raw_jsonrpc_sha256"]==sha(raw)
            (args.out/(label+"_ORIGINAL_NATIVE_STDIO.jsonl")).write_bytes(raw)
            assert after["sha256"]==sha(SHORT.encode())
        else:
            assert obj["decision"]=="DENIED_BEFORE_SERVER_SPAWN"
            assert before==after,(label,before,after)
        rec={
          "case":label,"decision":obj["decision"],
          "expected_authorized":authorized,
          "gateway_exit_code":p.returncode,
          "gateway_reason":obj["reason"],
          "actual_original_server_execve_seen":native_spawn,
          "original_tool_call_count":obj["native_original_tool_calls"],
          "file_before":before,"file_after":after,
          "signed_grant_file_sha256":sha(grant_file.read_bytes()) if grant_file.is_file() else None,
          "request_file_sha256":sha(request_file.read_bytes()),
          "revocation_epoch_sha256":rev_sha or rev_pin,
          "original_server_pid":obj.get("original_mcp_process_pid"),
          "real_owner_uid":uid_owner,"real_executor_uid":uid_exec,
          "resource_directory_mode_at_invocation":oct(permitted.stat().st_mode&0o7777),
          "resource_directory_owner_uid_at_invocation":permitted.stat().st_uid,
          "source_report_file":label+".json",
          "strace_sha256":sha(syscall.read_bytes()),
          "strace_os_authorship":"CI tracer process run under unprivileged executor"
        }
        records[label]=rec
        print("B22_ACTUAL_INDEPENDENT_OS_OWNER_ENFORCEMENT",json.dumps({
           "case":label,"decision":rec["decision"],
           "true_mcp_spawn":native_spawn,"before":before,"after":after}),flush=True)
        return rec

    # 1: actual independent resource owner approves exact CREATE.
    f_create,t_create=request("new-owner-approved")
    g_create=grant("create",f_create,"CREATE")
    gateway("allowed_create",f_create,g_create,t_create,True)

    # 2: owner separately signs a NO_CHANGE for same existing content;
    # a real new tool call is allowed and preserves content.
    g_noop=grant("noop",f_create,"NO_CHANGE")
    gateway("allowed_noop",f_create,g_noop,t_create,True)
    # 3: a second use of exactly the same valid signed grant is blocked by
    # atomic executor-owned nonce ledger, not by changed target state.
    gateway("denied_replay",f_create,g_noop,t_create,False)
    assert records["denied_replay"]["gateway_reason"]=="REPLAY_OR_UNREADABLE_LOCAL_OS_RESOURCE"

    # 4: physically owner-created longer file can be replaced only with
    # independently signed REPLACE, not merely a server permission hint.
    f_replace,t_replace=request("owner-replace")
    old="RISU B22 original longer synthetic text for genuine replacement\n"
    execute("sudo","-u",usernames["owner"],"-H",gateway_py,"-c",
        "import pathlib;pathlib.Path("+repr(str(t_replace))+").write_text("+repr(old)+")")
    g_replace=grant("replace",f_replace,"REPLACE")
    gateway("allowed_replace",f_replace,g_replace,t_replace,True)

    # 5: no user-signed grant ever exists.
    f_missing,t_missing=request("never-approved")
    gateway("denied_no_grant",f_missing,published/"never-issued-grant.json",t_missing,False)

    # 6: real separate owner explicitly signs NO_CHANGE, but request
    # would CREATE a new file; gateway refuses before original server.
    f_forbidden,t_forbidden=request("owner-denies-creation")
    g_forbidden=grant("owner-restricts-to-nochange",f_forbidden,"NO_CHANGE")
    gateway("denied_signed_scope",f_forbidden,g_forbidden,t_forbidden,False)
    assert records["denied_signed_scope"]["gateway_reason"]=="REQUESTED_DIRECTION_NOT_APPROVED_BY_OWNER"

    # 7: owner signed initially, then *it* publishes new cryptographically
    # signed revocation epoch; exact epoch digest is re-pinned by runner.
    f_revoked,t_revoked=request("owner-revoked-this-grant")
    g_revoked=grant("revoked-creation",f_revoked,"CREATE")
    revoke_nonce=json.loads(g_revoked.read_text())["policy"]["nonce"]
    next_rev=published/"revocations_epoch1.json"
    execute(*signer,"revocation","--private",private,"--root",root,
            "--out",next_rev,"--sequence",1,"--nonces",revoke_nonce)
    current_rev=next_rev
    rev_pin=sha(current_rev.read_bytes())
    gateway("denied_revoked",f_revoked,g_revoked,t_revoked,False)
    assert records["denied_revoked"]["gateway_reason"]=="OWNER_REVOKED_THIS_GRANT"

    # 8: owner really withdraws POSIX access (0700), which a valid
    # signature may never override. Restore for later fixtures.
    f_acl,t_acl=request("owner-posix-dac-withdrawn")
    g_acl=grant("os-dac-denied",f_acl,"CREATE")
    execute("sudo","-u",usernames["owner"],"chmod","700",permitted)
    try:gateway("denied_os_dac",f_acl,g_acl,t_acl,False)
    finally:execute("sudo","-u",usernames["owner"],"chmod","2770",permitted)

    # 9: owner grants for a non-existing file but then physically writes
    # different bytes before the attempted execution. Stale approval
    # must not be reused on the modified resource.
    f_stale,t_stale=request("owner-changed-precondition")
    g_stale=grant("before-unrelated-owner-write",f_stale,"CREATE")
    execute("sudo","-u",usernames["owner"],"-H",gateway_py,"-c",
        "import pathlib;pathlib.Path("+repr(str(t_stale))+").write_text('owner-changed-state')")
    gateway("denied_stale_state",f_stale,g_stale,t_stale,False)
    assert records["denied_stale_state"]["gateway_reason"]=="STALE_PRECALL_TARGET_STATE"

    # 10: the request is mutated AFTER the owner signed it. An exact
    # byte-identity signature over the requested action prevents it.
    f_change,t_change=request("client-changes-request-after-signing")
    g_change=grant("before-client-changed-input",f_change,"CREATE")
    altered=json.loads(f_change.read_text())
    altered["params"]["arguments"]["content"]="NOT THE OWNER SIGNED PAYLOAD"
    write(f_change,altered)
    gateway("denied_tampered_request",f_change,g_change,t_change,False)
    assert records["denied_tampered_request"]["gateway_reason"]=="SCOPE_NOT_BOUND_TO_ACTUAL_RESOURCE_ACTOR_AND_REQUEST"

    shutil.copyfile(root,args.out/"PREISSUED_PUBLIC_OWNER_ROOT.json")
    shutil.copyfile(current_rev,args.out/"FINAL_SIGNED_OWNER_REVOCATION.json")
    for p in published.glob("revocations_epoch*.json"):
        shutil.copyfile(p,args.out/p.name)
    for p in published.glob("grant_*.json"):
        shutil.copyfile(p,args.out/p.name)
    for p in requests.glob("*.json"):
        shutil.copyfile(p,args.out/("request_"+p.name))
    for p in results.glob("*.json"):
        shutil.copyfile(p,args.out/p.name)
    for p in results.glob("*.strace"):
        shutil.copyfile(p,args.out/p.name)
    summary={
       "schema":"risu-b22-two-real-posix-users-original-mcp-execution-v1",
       "OS_resource_owner_uid":uid_owner,
       "OS_unprivileged_executor_uid":uid_exec,
       "distinct_real_posix_principals":True,
       "owner_private_key_in_export":False,
       "original_upstream_public_wheel_sha256":sha(original_wheel.read_bytes()),
       "original_source_module_sha256":mod.stdout.strip(),
       "owner_trust_root_pinned_before_first_call_sha256":pinned_root,
       "final_owner_signed_revocation_epoch_sha256":rev_pin,
       "authorized_native_original_MCP_calls":sum(
           z["original_tool_call_count"] for z in records.values()),
       "genuinely_denied_before_original_MCP_server_spawn":sum(
           not z["actual_original_server_execve_seen"] for z in records.values()),
       "total_preflight_decisions":len(records),
       "true_pre_execution_block_checked_by_OS_strace":True,
       "all_denied_target_files_unchanged":all(
           z["file_before"]==z["file_after"] for z in records.values()
           if not z["expected_authorized"]),
       "independent_human_user_authentication":"NOT_PERFORMED",
       "workflow_operator_has_sudo_privileges":True,
       "cases":records
    }
    assert summary["authorized_native_original_MCP_calls"]==3
    assert summary["genuinely_denied_before_original_MCP_server_spawn"]==7
    assert summary["total_preflight_decisions"]==10
    assert summary["all_denied_target_files_unchanged"]
    write(args.out/"FIRST_REAL_OS_PRINCIPAL_ENFORCEMENT_SUMMARY.json",summary)
    print("B22_REAL_SEPARATE_OS_OWNER_GATEWAY_FINAL",json.dumps({
      k:summary[k] for k in (
         "authorized_native_original_MCP_calls",
         "genuinely_denied_before_original_MCP_server_spawn",
         "total_preflight_decisions",
         "all_denied_target_files_unchanged")},sort_keys=True),flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original-python",required=True,type=Path)
    p.add_argument("--published-wheels",required=True,type=Path)
    p.add_argument("--issuer-script",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    run(a)


if __name__=="__main__":
    main()
