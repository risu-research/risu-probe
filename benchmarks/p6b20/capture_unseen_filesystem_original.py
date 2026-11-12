"""B20 isolated original non-Git MCP source: filesystem-mcp 1.0.2.

Run the unmodified third-party original installed Python entrypoint.
Measure file existence, content SHA-256 and byte count outside the server
process before and after one genuine native MCP write_file per case.
'Before/after' are two independent replicates of the SAME publisher version,
not a software bug-fix comparison. All fixtures are safe synthetic files.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,subprocess,tempfile
from pathlib import Path

from risu_mcp_effects import PLAN,EPISODE,sha,canonical
from risu_mcp_trace import _read_trace
from risu_mcp_authority import correlate

TEXT="RISU B20 safe synthetic write\n"
CELLS=("before_trigger","before_control","after_trigger","after_control")


def snap(file):
    if not file.is_file():return {"exists":False,"digest":None,"size":0}
    raw=file.read_bytes()
    return {"exists":True,"digest":sha(raw),"size":len(raw)}


def writing(path,object):
    path.write_text(json.dumps(object,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))


async def case_run(py:Path,cell:str,out:Path):
    trigger=cell.endswith("_trigger")
    root=out/cell
    root.mkdir(parents=True,exist_ok=False)
    original=[]
    origin={"schema":"risu-b20-unseen-filesystem-firstpass-record-v1",
         "case":cell,"tool":"write_file",
         "target_distribution":"filesystem-mcp==1.0.2",
         "code_unmodified":True,
         "status":"UNVERIFIED",
         "process_pid":None}
    proc=None
    with tempfile.TemporaryDirectory(prefix="risu-b20-unseen-fs-") as d:
        workspace=Path(d).resolve()
        allowed=workspace/"allowed"
        allowed.mkdir()
        target=allowed/"payload.txt"
        if not trigger:
            target.write_text(TEXT,encoding="utf-8")
        env={
          "PATH":os.environ.get("PATH","/usr/bin:/bin"),
          "HOME":str(workspace),"TMPDIR":str(workspace),
          "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1",
          "LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
          "NO_COLOR":"1","CI":"true",
        }
        async def exchange(request):
            assert proc is not None and proc.stdin and proc.stdout
            data=(json.dumps(request,separators=(",",":"),ensure_ascii=False)+chr(10)).encode()
            proc.stdin.write(data)
            await asyncio.wait_for(proc.stdin.drain(),15)
            original.append(data)
            if "id" not in request:return None
            for _ in range(16):
                line=await asyncio.wait_for(proc.stdout.readline(),35)
                if not line or not line.endswith(bytes([10])) or len(line)>400000:
                    raise RuntimeError("Unmodified native filesystem-mcp returned no bounded JSON line")
                original.append(line)
                msg=json.loads(line)
                if type(msg) is not dict or msg.get("jsonrpc")!="2.0":
                    raise RuntimeError("Non protocol stdout in original source MCP")
                if msg.get("id")==request["id"]:return msg
                if "id" not in msg:continue
                raise RuntimeError("Unexpected source-native server request")
            raise RuntimeError("Too many unexpected upstream notifications")
        try:
            proc=await asyncio.create_subprocess_exec(
                str(py.absolute()),"-I","-m","filesystem_mcp",str(allowed),
                cwd=str(workspace),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                limit=410000)
            origin["process_pid"]=proc.pid
            init=await exchange({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},
                  "clientInfo":{"name":"risu-b20-independent-effect","version":"1"}}})
            if type(init.get("result")) is not dict:raise RuntimeError("Original external server initialization failed")
            origin["protocol_version"]=init["result"].get("protocolVersion")
            await exchange({"jsonrpc":"2.0","method":"notifications/initialized"})
            listing=await exchange({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            tools=listing.get("result",{}).get("tools")
            if type(tools) is not list or not any(type(t) is dict and
                t.get("name")=="write_file" for t in tools):
                raise RuntimeError("Source-original filesystem write_file not advertised")
            before=snap(target)
            if target.is_file():
                (root/"observed_before_payload.bin").write_bytes(target.read_bytes())
            # Only harmless text content in a path under the explicitly allowed
            # synthetic temp fixture, never any outside workspace.
            request={"jsonrpc":"2.0","id":20,"method":"tools/call",
              "params":{"name":"write_file",
                  "arguments":{"path":str(target),"content":TEXT,"append":False}}}
            response=await exchange(request)
            after=snap(target)
            if target.is_file():
                (root/"observed_after_payload.bin").write_bytes(target.read_bytes())
            origin["tool_success"]=type(response.get("result")) is dict and (
                response["result"].get("isError") is not True and
                "error" not in response)
            origin["before"]=before
            origin["after"]=after
            origin["expected_payload_sha256"]=sha(TEXT.encode())
            origin["expected_after_content_matches"]=(
                after["digest"]==sha(TEXT.encode()))
            if not origin["tool_success"] or not origin["expected_after_content_matches"]:
                raise RuntimeError("Original source write_file not successful")
            if before["exists"]==trigger:
                raise RuntimeError("Original fixture precondition contamination")
            origin["status"]="CAPTURED_ORIGINAL_NATIVE"
        except Exception as e:
            origin["status"]="UNVERIFIED_SOURCE_EXECUTION"
            origin["failure"]=type(e).__name__
            origin["failure_detail"]=str(e)[:260]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),6)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc and proc.stderr:
                try:
                    raw=await asyncio.wait_for(proc.stderr.read(4096),3)
                    origin["original_stderr_tail"]=raw.decode("utf-8","replace")[-850:]
                except (OSError,asyncio.TimeoutError):pass
        stdout=b"".join(original)
        (root/"original_stdio.jsonl").write_bytes(stdout)
        origin["trace_sha256"]=sha(stdout)
        writing(root/"original_file_observer.json",{
            "schema":"risu-b20-original-unmodified-filesystem-state-v1",
            "case":cell,"observed_by":"independent-parent-test-harness",
            "before_exists":origin.get("before",{}).get("exists"),
            "after_exists":origin.get("after",{}).get("exists"),
            "before_sha256":origin.get("before",{}).get("digest"),
            "after_sha256":origin.get("after",{}).get("digest"),
            "before_bytes":origin.get("before",{}).get("size"),
            "after_bytes":origin.get("after",{}).get("size"),
            "fixture_path_hash":sha(str(target).encode()),
            "actual_module_unmodified":True,
        })
        writing(root/"original_native_process.json",origin)
        if origin["status"]=="CAPTURED_ORIGINAL_NATIVE":
            wire,digest=_read_trace(root/"original_stdio.jsonl")
            calls,anomalies=correlate(wire)
            if anomalies or len(calls)!=1:raise RuntimeError("Unqualified original native trace")
            c=calls[0]
            observer=root/"original_file_observer.json"
            sensor_source={
                "file":cell+"/original_file_observer.json",
                "sha256":sha(observer.read_bytes())
            }
            kinds=[
              ("target-file-existence","boolean","before_exists","after_exists",
                 before["exists"],after["exists"]),
              ("target-file-content-digest","digest","before_sha256","after_sha256",
                 before["digest"],after["digest"]),
              ("target-file-byte-count","counter","before_bytes","after_bytes",
                 before["size"],after["size"])
            ]
            sensors=[{"id":key,"kind":kind,"before":b,"after":a,
                "original_observer":{**sensor_source,
                   "before_pointer":"/"+bp,"after_pointer":"/"+ap}}
                for key,kind,bp,ap,b,a in kinds]
            writing(root/"episode.json",{
                "schema":EPISODE,"case":cell,
                "trace_sha256":digest,
                "observer_trust_scope":"CI_OBSERVED_NOT_REMOTELY_ATTESTED",
                "call":{"tool":"write_file",
                  "arguments_sha256":sha(canonical(c["args"])),
                  "result_sha256":sha(canonical(c["response"])),
                  "request_line":c["request_line"],
                  "response_line":c["response_line"]},
                "sensors":sensors,
            })
        print("B20_REAL_NEW_PUBLISHER_ORIGINAL_EFFECT",json.dumps({
            "case":cell,"status":origin["status"],
            "before":origin.get("before"),"after":origin.get("after"),
            "original_success":origin.get("tool_success"),
            "original_trace_sha256":origin["trace_sha256"]},sort_keys=True))


async def all_cases(py,freeze,plan,out):
    metadata=json.loads(freeze.read_text("utf-8"))
    original_plan=json.loads(plan.read_text("utf-8"))
    assert metadata["schema"]=="risu-b20-general-effect-evaluation-freeze-v1"
    assert metadata["product"]["git_blob_sha1"]=="ab8191a3ca153ac079fcd07d128ddfcd7a06e99f"
    assert original_plan["schema"]==PLAN
    assert original_plan["classification"]=="HELDOUT_NORMAL_CONTROL"
    assert original_plan["tool"]=="write_file"
    assert original_plan["sensors"]==[
      {"id":key,"kind":kind,"pattern":"preserved-in-both-trigger-cases","expected":None}
      for key,kind in (
        ("target-file-existence","boolean"),
        ("target-file-content-digest","digest"),
        ("target-file-byte-count","counter"))]
    assert not out.exists()
    out.mkdir(parents=True)
    (out/"PREDECLARED_PLAN_SHA256.txt").write_text(sha(canonical(original_plan))+"\n")
    (out/"PLAN.json").write_bytes(plan.read_bytes())
    for cell in CELLS:await case_run(py,cell,out)
    print("B20_REAL_FILESYSTEM_FOUR_ORIGINAL_CASES_FINISHED",len(CELLS))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--python",required=True,type=Path)
    p.add_argument("--freeze",required=True,type=Path)
    p.add_argument("--plan",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    asyncio.run(all_cases(a.python.absolute(),a.freeze,a.plan,a.out))
if __name__=="__main__":main()
