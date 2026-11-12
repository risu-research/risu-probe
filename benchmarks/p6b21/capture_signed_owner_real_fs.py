"""P6-B21 ORIGINAL third-party MCP write_file with pre-execution signed fixture grants.

No user data, networks in the MCP process, secrets or outside-path writes.
A fresh Ed25519 fixture owner is created in memory before any original MCP
call. It signs exact resource, package, argument and allowable directional
effects before the native request. Original tool is NOT patched or made to
enforce the grant; one intentionally denied case demonstrates retrospective
policy violation detection only, not an upstream security vulnerability.
"""
from __future__ import annotations
import argparse,asyncio,base64,hashlib,json,os,secrets,tempfile,zipfile
from datetime import datetime,timezone,timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from risu_mcp_effects import PLAN,EPISODE,sha,canonical
from risu_mcp_effect_authority import ROOTS,GRANT,EVENT,MANIFEST,DOMAIN
from risu_mcp_trace import _read_trace
from risu_mcp_authority import correlate

CELLS=("before_trigger","before_control","after_trigger","after_control")
SHORT="RISU B21 harmless local file\n"
LONG="RISU B21 harmless local file plus preexisting extra nonsecret text\n"
ISSUER="b21-local-synthetic-file-owner"
ACTOR="b21-harmless-mcp-client"


def ztime():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")


def write(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)+"\n")


def state(path):
    if not path.exists():return {"exists":False,"sha":None,"size":0}
    raw=path.read_bytes()
    return {"exists":True,"sha":sha(raw),"size":len(raw)}


def b64(data):return base64.b64encode(data).decode("ascii")


def prepare(run_root,plan,original_wheel):
    root_key=Ed25519PrivateKey.generate()
    pub=root_key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    principal={
       "issuer":ISSUER,
       "key_id":sha(pub),
       "ed25519_public_key_b64":b64(pub),
       "resource_ids":["fixture://risu-b21/"+cell+"/payload" for cell in CELLS]
    }
    root_json={
       "schema":ROOTS,
       "principals":[principal],
       "trust_scope":"CI_LOCAL_FIXTURE_ONLY"
    }
    trusted_path=run_root/"pretrusted_synthetic_owner_root.json"
    write(trusted_path,root_json)
    digest=sha(trusted_path.read_bytes())
    (run_root/"PREISSUED_OWNER_ROOT_SHA256.txt").write_text(digest+"\n")
    original_target=run_root/"original_unmodified_pypi_wheel.whl"
    original_target.write_bytes(original_wheel.read_bytes())
    meta={
       "schema":MANIFEST,
       "plan_sha256":sha(canonical(plan)),
       "declared_dataset_role":plan["classification"],
       "original_software_file":original_target.name,
       "original_software_sha256":sha(original_target.read_bytes()),
       "cases":{}
    }
    print("B21_FIXTURE_OWNER_PUBLIC_KEY_PINNED_PREEXEC",digest,flush=True)
    return root_key,principal,meta,digest


async def run_case(py,case,root,plan,private,owner,manifest):
    directory=root/case
    directory.mkdir(parents=True,exist_ok=False)
    record={
       "schema":"risu-b21-original-native-signed-owner-observation-v1",
       "case":case,"owner_issuer":ISSUER,"actor":ACTOR,
       "source_package_version":"filesystem-mcp==1.0.2",
       "original_mcp_server_unmodified":True,
       "status":"UNVERIFIED",
       "process_pid":None
    }
    proc=None
    wire=[]
    with tempfile.TemporaryDirectory(prefix="risu-b21-owned-fixture-") as d:
        workspace=Path(d).resolve()
        allowed=workspace/"allowed"
        allowed.mkdir()
        target=allowed/"payload.txt"
        if case=="before_control":
            target.write_text(SHORT)
        if case=="after_control":
            target.write_text(LONG)
        before=state(target)
        record["before"]=before
        # All fixture target paths are created by this CI job and owned
        # by the current runner OS user; this is not real client approval.
        env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),
            "HOME":str(workspace),"TMPDIR":str(workspace),
            "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1",
            "LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
            "CI":"true","NO_COLOR":"1"}
        async def rpc(payload):
            assert proc and proc.stdin and proc.stdout
            raw=(json.dumps(payload,separators=(",",":"),ensure_ascii=False)+"\n").encode()
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),15)
            wire.append(raw)
            if "id" not in payload:return None
            for _ in range(20):
                response=await asyncio.wait_for(proc.stdout.readline(),35)
                if not response or not response.endswith(bytes([10])) or len(response)>524288:
                    raise RuntimeError("Original external MCP server returned no bounded protocol line")
                wire.append(response)
                msg=json.loads(response)
                if type(msg) is not dict or msg.get("jsonrpc")!="2.0":
                    raise RuntimeError("Original external stdout non-MCP content")
                if msg.get("id")==payload["id"]:return msg
                if "id" not in msg:continue
                raise RuntimeError("Unexpected original MCP server-to-client request")
            raise RuntimeError("Too many unexpected source-native notifications")
        try:
            proc=await asyncio.create_subprocess_exec(
                str(py.absolute()),"-I","-m","filesystem_mcp",str(allowed),
                cwd=str(workspace),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                limit=524300)
            record["process_pid"]=proc.pid
            hello=await rpc({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},
                          "clientInfo":{"name":"risu-b21-owner-test","version":"1"}}})
            if type(hello.get("result")) is not dict:
                raise RuntimeError("Original MCP server rejected handshake")
            record["original_negotiated_protocol"]=hello["result"].get("protocolVersion")
            await rpc({"jsonrpc":"2.0","method":"notifications/initialized"})
            catalog=await rpc({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            tools=catalog.get("result",{}).get("tools",[])
            if not any(type(t) is dict and t.get("name")=="write_file" for t in tools):
                raise RuntimeError("Original source did not advertise write_file")
            record["advertised_tool_count"]=len(tools)
            if target.is_file():
                (directory/"actual_before_payload.bin").write_bytes(target.read_bytes())
            request={"jsonrpc":"2.0","id":20,"method":"tools/call","params":{
                "name":"write_file","arguments":{
                     "path":str(target),"content":SHORT,"append":False}}}
            arguments=request["params"]["arguments"]
            argsha=sha(canonical(arguments))
            wheel_sha=manifest["original_software_sha256"]
            case_resource="fixture://risu-b21/"+case+"/payload"
            issued=ztime()
            exp=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat(
                      timespec="seconds").replace("+00:00","Z")
            intended={
              "file-presence":["ACTIVATE"] if case=="before_trigger" else
                         ["NO_CHANGE"],
              "file-contents":["CREATE"] if case=="before_trigger" else
                         ["NO_CHANGE"] if case=="before_control" else
                         ["NO_CHANGE"] if case=="after_trigger" else ["REPLACE"],
              "file-size":["INCREASE"] if case=="before_trigger" else
                         ["NO_CHANGE"] if case in ("before_control","after_trigger")
                         else ["DECREASE"]
            }
            # Denied case is intentionally allowed NO_CHANGE for all three,
            # while the original server performs a normal file creation.
            policy={
                "audience":"risu-mcp-effect-authority-b21",
                "issuer":ISSUER,"key_id":owner["key_id"],
                "case":case,"actor":ACTOR,
                "resource_id":case_resource,
                "resource_argument_pointer":"/path",
                "resource_argument_sha256":sha(canonical(str(target))),
                "run_nonce":secrets.token_hex(32),
                "tool":"write_file",
                "args_sha256":argsha,
                "wheel_sha256":wheel_sha,
                "issued_at":issued,"expires_at":exp,
                "allowed_directions":intended
            }
            signature=private.sign(DOMAIN+canonical(policy))
            signed={"schema":GRANT,"policy":policy,
                    "signature_ed25519_b64":b64(signature)}
            grant_path=directory/"PREISSUED_SIGNED_OWNER_GRANT.json"
            write(grant_path,signed)
            pre_hash=sha(grant_path.read_bytes())
            record["signed_owner_policy_file_sha256_before_tool"]=pre_hash
            record["preissue_at"]=issued
            # The grant is signed and physically written BEFORE MCP calls.
            invoked=ztime()
            actual=await rpc(request)
            completed=ztime()
            after=state(target)
            if target.is_file():
                (directory/"actual_after_payload.bin").write_bytes(target.read_bytes())
            record["after"]=after
            record["tool_result_success"]=(
                type(actual.get("result")) is dict and
                actual["result"].get("isError") is not True and
                "error" not in actual)
            record["payload_correct"]=after["sha"]==sha(SHORT.encode())
            record["grant_sha256_after_tool"]=sha(grant_path.read_bytes())
            if record["grant_sha256_after_tool"]!=pre_hash or not record["tool_result_success"] or not record["payload_correct"]:
                raise RuntimeError("Preissued grant modified or original native tool unsuccessful")
            raw_output=b"".join(wire)
            (directory/"original_stdio.jsonl").write_bytes(raw_output)
            parsed,trace_sha=_read_trace(directory/"original_stdio.jsonl")
            calls,issues=correlate(parsed)
            if issues or len(calls)!=1:
                raise RuntimeError("Original native tool/catalog pairing not unique")
            call=calls[0]
            if call["args"]!=arguments or call["name"]!="write_file":
                raise RuntimeError("Captured upstream call not exact preissued grant target")
            observer={
                "schema":"risu-b21-independent-file-effect-observer-v1",
                "case":case,
                "observed_by":"parent_fixture_owner",
                "before_exists":before["exists"],"after_exists":after["exists"],
                "before_sha256":before["sha"],"after_sha256":after["sha"],
                "before_bytes":before["size"],"after_bytes":after["size"],
                "target_resource_path_sha256":sha(canonical(str(target))),
                "actual_after_content_sha256":sha((directory/"actual_after_payload.bin").read_bytes())
            }
            observer_file=directory/"ORIGINAL_PARENT_FILE_OBSERVER.json"
            write(observer_file,observer)
            sensor_params=[
                ("file-presence","boolean","before_exists","after_exists",
                 before["exists"],after["exists"]),
                ("file-contents","digest","before_sha256","after_sha256",
                 before["sha"],after["sha"]),
                ("file-size","counter","before_bytes","after_bytes",
                 before["size"],after["size"])
            ]
            episode={
                "schema":EPISODE,
                "case":case,
                "trace_sha256":trace_sha,
                "observer_trust_scope":"CI_OBSERVED_NOT_REMOTELY_ATTESTED",
                "call":{
                    "tool":"write_file",
                    "arguments_sha256":sha(canonical(arguments)),
                    "result_sha256":sha(canonical(call["response"])),
                    "request_line":call["request_line"],
                    "response_line":call["response_line"]
                },
                "sensors":[{
                    "id":id_,"kind":kind,"before":pre,"after":post,
                    "original_observer":{
                       "file":case+"/"+observer_file.name,
                       "sha256":sha(observer_file.read_bytes()),
                       "before_pointer":"/"+bp,
                       "after_pointer":"/"+ap
                    }
                } for id_,kind,bp,ap,pre,post in sensor_params]
            }
            write(directory/"episode.json",episode)
            event={
                "schema":EVENT,"case":case,"actor":ACTOR,
                "resource_id":case_resource,
                "run_nonce":policy["run_nonce"],
                "grant_sha256":pre_hash,
                "tool":"write_file",
                "args_sha256":argsha,
                "resource_argument_sha256":policy["resource_argument_sha256"],
                "wheel_sha256":wheel_sha,
                "invoked_at":invoked,
                "completed_at":completed,
                "trace_sha256":trace_sha,
                "original_observer_sha256":sha(observer_file.read_bytes())
            }
            event_file=directory/"PRECALL_BOUND_EXECUTION_EVENT.json"
            write(event_file,event)
            manifest["cases"][case]={
                "grant_file":case+"/"+grant_path.name,
                "grant_sha256":pre_hash,
                "event_file":case+"/"+event_file.name,
                "event_sha256":sha(event_file.read_bytes())
            }
            record["status"]="CAPTURED_ORIGINAL_NATIVE_WITH_PRECALL_OWNER_GRANT"
            record["result_response_sha256"]=sha(canonical(call["response"]))
            record["original_trace_sha256"]=trace_sha
        except Exception as ex:
            record["status"]="UNVERIFIED_ORIGINAL_NATIVE_EXECUTION"
            record["error_kind"]=type(ex).__name__
            record["error_detail"]=str(ex)[:280]
        finally:
            if proc is not None and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc is not None and proc.stderr:
                try:
                    stderr=await asyncio.wait_for(proc.stderr.read(4096),3)
                    record["source_original_stderr_tail"]=stderr.decode("utf-8","replace")[-400:]
                except (OSError,asyncio.TimeoutError):pass
        write(directory/"SOURCE_ORIGINAL_EXECUTION_RECORD.json",record)
        print("B21_ORIGINAL_MCP_SIGNED_OWNER_EFFECT",json.dumps({
           "case":case,"status":record["status"],
           "before":record.get("before"),"after":record.get("after"),
           "signed_policy_preissued":record.get("preissue_at"),
           "error":record.get("error_kind")
        },sort_keys=True),flush=True)


async def main_async(args):
    plan=json.loads(args.plan.read_text("utf-8"))
    assert plan["schema"]==PLAN
    assert plan["tool"]=="write_file"
    assert set(plan["cells"])==set(CELLS)
    assert plan["classification"]=="DEVELOPMENT_POSITIVE_CONTROL"
    assert not args.out.exists(),"Never overwrite original signed-run native evidence"
    args.out.mkdir(parents=True)
    wheel=next(args.wheel_dir.glob("filesystem_mcp-1.0.2-*.whl"))
    # Source pin freeze maintained independently in CI.
    assert sha(wheel.read_bytes())=="94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235"
    py=args.python.absolute()
    assert py.is_file()
    key,principal,manifest,root_sha=prepare(args.out,plan,wheel)
    (args.out/"ORIGINAL_FROZEN_PLAN.json").write_bytes(args.plan.read_bytes())
    for cell in CELLS:await run_case(py,cell,args.out,plan,key,principal,manifest)
    write(args.out/"SIGNED_OWNER_AUTHORITY_MANIFEST.json",manifest)
    print("B21_PRETRUSTED_FIXTURE_OWNER_ROOT_SHA256",root_sha,flush=True)
    print("B21_ORIGINAL_OWNER_SIGNED_CAPTURE_COMPLETE",len(manifest["cases"]),flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--python",type=Path,required=True)
    parser.add_argument("--wheel-dir",type=Path,required=True)
    parser.add_argument("--plan",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    asyncio.run(main_async(args))


if __name__=="__main__":
    main()
