"""P6-B19 unmodified upstream PyPI wheel native MCP security-repair harness.

Original published 2026.11.4 / 2026.11.11 wheels run in two separate
isolated Python virtual environments. Synthetic local Git repos contain only
benign marker script (no data exfiltration, shell access, network or secrets).
No patched source or changed upstream MCP library code. Only original stdio
JSON-RPC + independent side-effect witness is measured.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,shlex,subprocess,tempfile
from pathlib import Path
import zipfile


def hash_bytes(b):return hashlib.sha256(b).hexdigest()
def hash_path(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for part in iter(lambda:f.read(1024*1024),b""):h.update(part)
    return h.hexdigest()

def command(*args,env=None,cwd=None):
    x=subprocess.run(list(map(str,args)),check=False,stdout=subprocess.PIPE,
       stderr=subprocess.PIPE,env=env,cwd=cwd,timeout=25)
    if x.returncode:
        raise RuntimeError("Synthetic Git setup failure: "+x.stderr[:200].decode("utf-8","replace"))
    return x.stdout

def init_repo(base:Path,configured:bool):
    repo=base/"synthetic-repository"
    repo.mkdir()
    command("git","-C",repo,"init","-q")
    (repo/"README.md").write_text("RISU B19 offline synthetic Git fixture\n")
    command("git","-C",repo,"add","README.md")
    command("git","-C",repo,"-c","user.name=RISU Benign",
         "-c","user.email=risu-synthetic@invalid.example","commit","-qm","synthetic")
    marker=base/"benign-marker-only.txt"
    script=repo/"safe-monitor.sh"
    marker_text="RISU_B19_BENIGN_EXECUTION\n"
    # Intentionally benign local marker-only script; no env exfiltration.
    script.write_text("#!/bin/sh\nprintf 'RISU_B19_BENIGN_EXECUTION\\n' >> "+
         shlex.quote(str(marker))+"\nexit 0\n",encoding="utf-8")
    script.chmod(0o700)
    if configured:
        # Must be LAST Git setup operation. No Git status calls after this
        # point, until the actual source-native MCP tool request.
        command("git","-C",repo,"config","core.fsmonitor",str(script))
    return repo,marker,marker_text.encode()

async def run_case(variant,case,exe,wheel,code_digest,root):
    configured=case=="CONFIGURED"
    with tempfile.TemporaryDirectory(prefix="risu-b19-signed-upstream-") as folder:
        tmp=Path(folder).resolve()
        repo,marker,marker_line=init_repo(tmp,configured)
        # Do not carry tokens, credentials, Python import injection, existing
        # Git overrides, proxies or caller-global config into original code.
        env={
          "PATH":os.environ.get("PATH","/usr/bin:/bin"),
          "HOME":str(tmp),"TMPDIR":str(tmp),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
          "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1",
          "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
          "GIT_TERMINAL_PROMPT":"0","CI":"true","NO_COLOR":"1"}
        log=[]
        proc=None
        origin={
            "schema":"risu-b19-real-native-effect-witness-v1",
            "variant":variant["id"],"case":case,
            "source_version":variant["version"],
            "release_wheel_sha256":hash_path(wheel),
            "installed_source_sha256":code_digest,
            "isolated_python_runtime":True,
            "injected_config":configured,
            "repository_path":str(repo),
            "marker_before":False,"marker_after":False,
            "status":"UNVERIFIED","process_pid":None
        }
        async def msg(payload):
            wire=(json.dumps(payload,separators=(",",":"),ensure_ascii=False)+chr(10)).encode()
            proc.stdin.write(wire)
            await asyncio.wait_for(proc.stdin.drain(),20)
            log.append(wire)
            if "id" not in payload:return None
            for _ in range(20):
                got=await asyncio.wait_for(proc.stdout.readline(),45)
                if not got or not got.endswith(bytes([10])) or len(got)>524288:
                    raise RuntimeError("Original MCP process did not send valid bounded JSON line")
                log.append(got)
                response=json.loads(got)
                if type(response) is not dict or response.get("jsonrpc")!="2.0":
                    raise RuntimeError("Unexpected native stdout")
                if response.get("id")==payload["id"]:return response
                if "id" not in response:continue
                raise RuntimeError("Original server issued unhandled client request")
            raise RuntimeError("Unbounded original MCP notifications")
        try:
            proc=await asyncio.create_subprocess_exec(
                str(exe.absolute()),"-I","-m","mcp_server_git",
                "--repository",str(repo),
                cwd=str(tmp),env=env,
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,limit=524300)
            origin["process_pid"]=proc.pid
            origin["process_python_exe_target"]=os.readlink(f"/proc/{proc.pid}/exe")
            origin["process_python_exe_sha256"]=hash_path(f"/proc/{proc.pid}/exe")
            handshake=await msg({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"risu-b19-upstream-release","version":"1"}}})
            if type(handshake.get("result")) is not dict:
                raise RuntimeError("Original server rejected MCP initialization")
            origin["negotiated_protocol"]=handshake["result"].get("protocolVersion")
            origin["serverInfo"]=handshake["result"].get("serverInfo",{})
            await msg({"jsonrpc":"2.0","method":"notifications/initialized"})
            catalog=await msg({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            original_tools=catalog.get("result",{}).get("tools",[])
            if not isinstance(original_tools,list) or not any(
              isinstance(x,dict) and x.get("name")=="git_status" for x in original_tools):
                raise RuntimeError("Selected upstream git_status absent from original in-band catalog")
            if marker.exists():
                raise RuntimeError("Marker was created before tool call")
            origin["marker_before"]=False
            native=await msg({"jsonrpc":"2.0","id":20,"method":"tools/call",
                "params":{"name":"git_status","arguments":{"repo_path":str(repo)}}})
            result=native.get("result")
            origin["tool_result_iserror"]=(type(result) is not dict or
                result.get("isError") is True or "error" in native)
            contents=result.get("content",[]) if type(result) is dict else []
            texts=[z.get("text","") for z in contents if type(z) is dict and z.get("type")=="text"]
            origin["tool_status_text_present"]=bool(texts and
               any("branch" in t.lower() or "Repository status" in t for t in texts))
            origin["marker_after"]=marker.exists()
            raw=marker.read_bytes() if marker.exists() else b""
            origin["marker_after_sha256"]=hash_bytes(raw)
            origin["marker_after_bytes"]=len(raw)
            origin["marker_content_valid"]= (
                 raw==b"" if not origin["marker_after"] else (
                 len(raw)>0 and len(raw)%len(marker_line)==0 and
                 raw==marker_line*(len(raw)//len(marker_line))))
            origin["marker_trigger_count"]=len(raw)//len(marker_line) if origin["marker_content_valid"] else None
            origin["status"]="CAPTURED_ORIGINAL_NATIVE"
        except Exception as e:
            origin["status"]="UNVERIFIED_NATIVE_SOURCE_OR_RUNTIME"
            origin["error_kind"]=type(e).__name__
            origin["error_message"]=str(e)[:280]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc and proc.stderr:
                try:
                    error=(await asyncio.wait_for(proc.stderr.read(4096),3)).decode("utf-8","replace")
                    origin["stderr_setup_tail"]=error[-600:]
                except (OSError,asyncio.TimeoutError):pass
        wire=b"".join(log)
        origin["trace_sha256"]=hash_bytes(wire)
        origin["raw_stdio_lines"]=len(log)
        destination=root/variant["id"]/case
        destination.mkdir(parents=True,exist_ok=False)
        (destination/"original_stdio.jsonl").write_bytes(wire)
        (destination/"original_effect_witness.json").write_text(
            json.dumps(origin,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
        print("B19_ORIGINAL_NATIVE",json.dumps({key:origin.get(key) for key in (
          "variant","case","status","source_version","marker_before",
          "marker_after","marker_trigger_count","tool_result_iserror",
          "tool_status_text_present","error_kind")},sort_keys=True))

async def main_async(args):
    frozen=json.loads(args.freeze.read_text("utf-8"))
    assert frozen["schema"]=="risu-p6b19-signed-official-before-after-freeze-v1"
    variants={a["id"]:a for a in frozen["versions"]}
    assert set(variants)=={"VULNERABLE","FIXED"}
    root=args.out
    if root.exists():raise RuntimeError("Refuse to overwrite original native source evidence")
    root.mkdir(parents=True)
    for name in ("VULNERABLE","FIXED"):
        variant=variants[name]
        wheel=args.wheel_root/name/variant["wheel"]
        code_witness=json.loads((args.wheel_root/name/"source_code_equivalence.json").read_text())
        installed_code_digest=code_witness["installed_code_sha256"]
        exe=args.venvs/name/"bin/python"
        if not exe.exists() or not wheel.exists():
            raise RuntimeError("Signed original wheel or installed venv missing")
        for case in ("CONFIGURED","NORMAL"):
            await run_case(variant,case,exe,wheel,installed_code_digest,root)
        # Repeatedly verify signed wheel after native execution, no mutation.
        if hash_path(wheel)!=variant["wheel_sha256"]:
            raise RuntimeError("Wheel changed after native original execution")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--freeze",required=True,type=Path)
    p.add_argument("--wheel-root",required=True,type=Path)
    p.add_argument("--venvs",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    asyncio.run(main_async(args))
if __name__=="__main__":main()
