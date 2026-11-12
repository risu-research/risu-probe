"""P6-B18: launch pristine external built MCP executable and measure /proc/PID/exe.

CI harness only, not the installed offline RISU verifier. No upstream source
patches or production requests. Only frozen synthetic native MCP operations.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,tempfile
from pathlib import Path


def sha_bytes(x):return hashlib.sha256(x).hexdigest()


def sha_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()


def proc_witness(proc,binary):
    pid=proc.pid
    proc_exe=Path(f"/proc/{pid}/exe")
    proc_cmd=Path(f"/proc/{pid}/cmdline")
    inode=proc_exe.stat()
    raw=proc_cmd.read_bytes()
    cmd=[x.decode("utf-8","surrogateescape") for x in raw.split(bytes([0])) if x]
    actual=os.readlink(proc_exe)
    claimed=str(binary.resolve())
    if actual!=claimed or len(cmd)!=1 or Path(cmd[0]).resolve()!=binary.resolve():
        raise RuntimeError("Running executable is not the intended original built binary")
    return {
        "pid":pid,"path":actual,"inode":[inode.st_dev,inode.st_ino],
        "proc_digest":sha_file(proc_exe),
        "disk_digest":sha_file(binary),
        "cmdline":cmd
    }


async def capture(binary,cohort,attestation,out):
    frozen=json.loads(cohort.read_text("utf-8"))
    assert frozen["schema"]=="risu-p6b18-executed-binary-predeclared-v1"
    raw_binary=sha_file(binary)
    if out.exists() or not binary.is_file():raise ValueError("No binary or refusing overwrite of original evidence")
    assert attestation["schema"]=="risu-b18-gh-attestation-cli-result-v1"
    assert attestation["verified"] is True and attestation["subject_sha256"]==raw_binary
    out.mkdir(parents=True)
    original_lines=[]
    original_calls=[]
    start={}
    stop={}
    origin={
        "schema":"risu-b18-runtime-procfs-evidence-v1",
        "status":"UNVERIFIED","source_revision":frozen["source"]["revision"],
        "binary_sha256":raw_binary,
        "attested_subject_sha256":attestation["subject_sha256"],
        "verification_run_id":attestation["verification_run_id"],
        "selected_calls":frozen["runtime"]["selected_count"],
        "captured_calls":0,
        "proc_pid":None,
    }
    proc=None
    with tempfile.TemporaryDirectory(prefix="risu-b18-native-") as d:
        root=Path(d).resolve()
        env={"PATH":os.environ.get("PATH",""),"HOME":str(root),
             "LANG":"C.UTF-8","LC_ALL":"C.UTF-8","NO_COLOR":"1",
             "GOMAXPROCS":"2","CI":"true"}
        async def transact(message):
            assert proc and proc.stdin and proc.stdout
            wire=(json.dumps(message,ensure_ascii=False,separators=(",",":"))+chr(10)).encode("utf-8")
            proc.stdin.write(wire)
            await asyncio.wait_for(proc.stdin.drain(),15)
            original_lines.append(wire)
            reqline=len(original_lines)
            if "id" not in message:return None,reqline,None
            for _ in range(18):
                line=await asyncio.wait_for(proc.stdout.readline(),30)
                if not line or not line.endswith(bytes([10])) or len(line)>524288:
                    raise RuntimeError("Missing complete native MCP stdout JSON-RPC response")
                original_lines.append(line)
                resp=json.loads(line)
                if type(resp) is not dict or resp.get("jsonrpc")!="2.0":
                    raise RuntimeError("Original binary emitted invalid stdout protocol line")
                if resp.get("id")==message["id"]:
                    return resp,reqline,len(original_lines)
                if "id" not in resp:continue
                raise RuntimeError("Unexpected upstream request to test client")
            raise RuntimeError("Too many unmatched notifications")
        try:
            proc=await asyncio.create_subprocess_exec(str(binary.resolve()),cwd=str(root),
                env=env,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,limit=524290)
            start=proc_witness(proc,binary)
            response,_,_=await transact({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"risu-b18-executable-provenance","version":"1"}}})
            if type(response.get("result")) is not dict:
                raise RuntimeError("Original Go MCP binary rejected initialization")
            origin["negotiated_protocol"]=response["result"].get("protocolVersion")
            await transact({"jsonrpc":"2.0","method":"notifications/initialized"})
            cursor=None; catalog_names=set()
            for page in range(8):
                page_result,_,_=await transact({"jsonrpc":"2.0","id":2+page,
                     "method":"tools/list","params":({"cursor":cursor} if cursor else {})})
                item=page_result.get("result")
                if type(item) is not dict or type(item.get("tools")) is not list:
                    raise RuntimeError("Original Go MCP tools/list response missing")
                catalog_names.update(x["name"] for x in item["tools"] if type(x) is dict and "name" in x)
                cursor=item.get("nextCursor")
                if not cursor:break
            else:raise RuntimeError("Original Go source catalog exceeded eight pages")
            origin["advertised_tools"]=sorted(catalog_names)
            for i,selected in enumerate(frozen["runtime"]["expected_original_calls"]):
                if selected["tool"] not in catalog_names:
                    raise RuntimeError("Pinned original tool missing from inband catalog")
                answer,request_line,response_line=await transact({
                    "jsonrpc":"2.0","id":20+i,"method":"tools/call",
                    "params":{"name":selected["tool"],"arguments":selected["arguments"]}})
                original_calls.append({
                    "selection":i,"name":selected["tool"],
                    "arguments":selected["arguments"],"request_line":request_line,
                    "response_line":response_line,"response":answer})
            stop=proc_witness(proc,binary)
            origin.update({
                "status":"CAPTURED_ORIGINAL_GO_BINARY",
                "captured_calls":len(original_calls),
                "proc_pid":proc.pid,
                "proc_exe_target":start["path"],
                "binary_command_verified":True,
                "proc_exe_sha256_before":start["proc_digest"],
                "proc_exe_sha256_after":stop["proc_digest"],
                "disk_sha256_before":start["disk_digest"],
                "disk_sha256_after":stop["disk_digest"],
                "proc_device_inode_before":start["inode"],
                "proc_device_inode_after":stop["inode"],
                "start_cmdline":start["cmdline"],
                "end_cmdline":stop["cmdline"]
            })
        except Exception as e:
            origin["status"]="UNVERIFIED_ORIGINAL_RUNTIME"
            origin["error_type"]=type(e).__name__
            origin["error_detail"]=str(e)[:250]
            if start:
                origin["initial_procfs_observation"]=start
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc and proc.stderr:
                try:
                    data=await asyncio.wait_for(proc.stderr.read(4096),3)
                    origin["stderr_setup_only"]=data.decode("utf-8","replace")[-800:]
                except (OSError,asyncio.TimeoutError):pass
    wire=b"".join(original_lines)
    origin["trace_sha256"]=sha_bytes(wire)
    origin["original_stdio_lines"]=len(original_lines)
    (out/"original_stdio.jsonl").write_bytes(wire)
    (out/"runtime_witness.json").write_text(json.dumps(origin,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    (out/"per_call_original.json").write_text(json.dumps(original_calls,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    print("B18_ACTUAL_EXECUTED_PROCESS",json.dumps({k:origin.get(k) for k in (
        "status","proc_pid","binary_sha256","proc_exe_sha256_before",
        "proc_exe_sha256_after","captured_calls","error_type")},sort_keys=True))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--frozen",required=True,type=Path)
    p.add_argument("--attestation",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    asyncio.run(capture(a.binary.resolve(),a.frozen,
        json.loads(a.attestation.read_text("utf-8")),a.out))
if __name__=="__main__":main()
